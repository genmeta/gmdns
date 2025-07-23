use std::{
    io::{self},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::BytesMut;
use dashmap::DashMap;
use futures::{Sink, SinkExt};
use socket2::{Domain, Socket, Type};
use tokio::{net::UdpSocket, sync::mpsc, time::timeout};
use tracing::info;

use crate::parser::{
    packet::{Packet, WritePacket, be_packet},
    record::{
        RData::{E, E6, EE, EE6},
        endpoint::EndpointAddr,
    },
};

const MULTICAST_PORT: u16 = 5353;
const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MAX_DEQUE_SIZE: usize = 64;

#[derive(Clone)]
pub struct MdnsProtocol {
    io: Arc<UdpSocket>,
    req_deque: mpsc::Sender<(SocketAddr, Packet)>,
    resp_deque: ArcAsyncDeque<(SocketAddr, Packet)>,
    response_router: Arc<DashMap<u16, mpsc::Sender<(SocketAddr, Packet)>>>,
}

impl MdnsProtocol {
    pub fn new(
        device: &str,
        ip: Ipv4Addr,
        request_handler: impl Sink<(SocketAddr, Packet), Error = io::Error> + Unpin,
    ) -> io::Result<Self> {
        info!("[MDNS] add mdns dvice {device} {ip}");
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        #[cfg(not(target_os = "windows"))]
        socket.set_reuse_port(true)?;

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MULTICAST_PORT);
        socket.bind(&bind.into())?;
        if ip.is_loopback() {
            socket.set_multicast_loop_v4(true)?;
        } else {
            socket.set_multicast_loop_v4(false)?;
        }
        socket.join_multicast_v4(&MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED)?;
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        socket.bind_device(Some(device.as_bytes()));

        let io = Arc::new(tokio::net::UdpSocket::from_std(socket.into())?);

        let (request_tx, request_rx) = mpsc::channel(MAX_DEQUE_SIZE);

        let resp_deque = ArcAsyncDeque::new();
        let response_router = Arc::new(DashMap::<u16, mpsc::Sender<(SocketAddr, Packet)>>::new());

        let _rcvd_task = {
            let response_router = response_router.clone();
            let req_deque = req_deque.clone();
            let resp_deque = resp_deque.clone();
            let io = io.clone();
            tokio::spawn(async move {
                loop {
                    let mut recv_buffer = [0u8; 1024];
                    let (count, src) = io.recv_from(&mut recv_buffer).await.unwrap();
                    let packet = match be_packet(&recv_buffer[..count]) {
                        Ok((_, p)) => p,
                        Err(_) => continue,
                    };
                    match (packet.header.flags.query(), packet.header.id) {
                        (true, 0) => Self::push_to_deque(&resp_deque, src, packet),
                        (true, _) => {
                            if let Some(entry) = response_router.get(&packet.header.id) {
                                let pending = entry.value().clone();
                                if pending.try_send((src, packet)).is_err() {
                                    tracing::warn!(
                                        "[MDNS]: Failed to send response for query id {}",
                                        packet.header.id
                                    );
                                };
                            }
                        }
                        (false, _) => Self::push_to_deque(&req_deque, src, packet),
                    }
                }
            })
        }
        .abort_handle();
        Ok(Self {
            io,
            req_deque,
            resp_deque,
            response_router,
        })
    }

    pub async fn query(&self, local_name: String) -> io::Result<(SocketAddr, Vec<EndpointAddr>)> {
        let packet = Packet::query_with_id(local_name.clone());
        let query_id = packet.header.id;
        if query_id == 0 {
            return Err(io::Error::other("query id should not be 0"));
        }
        self.spwan_broadcast_packet(&packet)?;
        let pending_response = ArcAsyncDeque::new();
        self.response_router
            .insert(query_id, pending_response.clone());

        for _ in 0..3 {
            match timeout(Duration::from_millis(300), pending_response.pop()).await {
                Ok(Some((src, packet))) => {
                    let endpoint = packet
                        .answers
                        .iter()
                        .filter_map(|answer| {
                            tracing::debug!("[MDNS]: recv response: {answer:?}");
                            if answer.name != local_name {
                                tracing::debug!(
                                    "[MDNS]: Ignored answer for different service name: {} != {}",
                                    answer.name,
                                    local_name
                                );
                                return None;
                            }
                            match answer.data {
                                E(e) | EE(e) | E6(e) | EE6(e) => Some(e),
                                _ => {
                                    tracing::debug!("Ignored record: {answer:?}");
                                    None
                                }
                            }
                        })
                        .collect::<Vec<_>>();
                    if endpoint.is_empty() {
                        self.spwan_broadcast_packet(&packet)?;
                        continue;
                    } else {
                        self.response_router.remove(&query_id);
                        return Ok((src, endpoint));
                    }
                }
                _ => {
                    self.spwan_broadcast_packet(&packet)?;
                }
            }
        }
        self.response_router.remove(&query_id);
        Err(io::Error::new(io::ErrorKind::TimedOut, "Query timed out"))
    }

    pub fn spwan_broadcast_packet(&self, packet: &Packet) -> io::Result<()> {
        let packet = packet.clone();
        tokio::spawn({
            let io = self.io.clone();
            async move {
                let mut buf = BytesMut::with_capacity(1024);
                buf.put_packet(&packet);
                io.send_to(buf.as_ref(), (MULTICAST_ADDR, MULTICAST_PORT))
                    .await
            }
        });
        Ok(())
    }
}
