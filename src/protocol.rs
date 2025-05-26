use std::{
    future::poll_fn,
    io::{self},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    task::{Poll, Waker},
    time::Duration,
};

use bytes::BytesMut;
use dashmap::DashMap;
use qbase::util::ArcAsyncDeque;
use socket2::{Domain, Socket, Type};
use tokio::{net::UdpSocket, task::AbortHandle, time::timeout};
use tracing::{debug, warn};

use crate::parser::packet::{Packet, WritePacket, be_packet};

const MULTICAST_PORT: u16 = 5353;
const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

enum Reponse {
    Demand(Waker),
    Answer((SocketAddr, Packet)),
}

#[derive(Clone)]
pub struct MdnsProtocol {
    io: Arc<UdpSocket>,
    _recv_task: AbortHandle,
    request_queue: ArcAsyncDeque<(SocketAddr, Packet)>,
    response_queue: ArcAsyncDeque<(SocketAddr, Packet)>,
    response_router: Arc<DashMap<u16, Reponse>>,
}

impl MdnsProtocol {
    pub fn new() -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        socket.set_reuse_port(true)?;

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MULTICAST_PORT);
        socket.bind(&bind.into())?;
        socket.set_multicast_loop_v4(false)?;
        socket.join_multicast_v4(&MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED)?;
        let io = Arc::new(tokio::net::UdpSocket::from_std(socket.into())?);

        let request_queue = ArcAsyncDeque::new();
        let response_queue = ArcAsyncDeque::new();
        let response_router = Arc::new(DashMap::<u16, Reponse>::new());
        let rcvd_task = {
            let request_queue = request_queue.clone();
            let response_router = response_router.clone();
            let response_queue = response_queue.clone();
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
                        (true, 0) => response_queue.push_back((src, packet)),
                        (true, _) => {
                            let waker = match response_router.entry(packet.header.id) {
                                dashmap::Entry::Occupied(mut entry) => {
                                    match entry.insert(Reponse::Answer((src, packet))) {
                                        Reponse::Demand(waker) => Some(waker),
                                        _ => None,
                                    }
                                }
                                dashmap::Entry::Vacant(_) => {
                                    debug!("Response not found for ID: {}", packet.header.id);
                                    None
                                }
                            };
                            if let Some(w) = waker {
                                w.wake()
                            }
                        }
                        (false, _) if request_queue.len() < 64 => {
                            request_queue.push_back((src, packet))
                        }
                        (false, _) => warn!("Request queue is full, dropping packet from {}", src),
                    }
                }
            })
        }
        .abort_handle();
        Ok(Self {
            io,
            _recv_task: rcvd_task,
            request_queue,
            response_queue,
            response_router,
        })
    }

    pub async fn query(&self, packet: Packet) -> io::Result<(SocketAddr, Packet)> {
        let query_id = packet.header.id;
        if query_id == 0 {
            return Err(io::Error::other("query id should not be 0"));
        }
        self.spwan_broadcast_packet(packet)?;
        let query = poll_fn(|cx| match self.response_router.entry(query_id) {
            dashmap::Entry::Occupied(mut entry) => {
                if let Reponse::Demand(waker) = entry.get() {
                    if !waker.will_wake(cx.waker()) {
                        Poll::Ready(Err(io::Error::other("query id duplicated")))
                    } else {
                        entry.insert(Reponse::Demand(cx.waker().clone()));
                        Poll::Pending
                    }
                } else {
                    let Reponse::Answer(answer) = entry.remove() else {
                        unreachable!()
                    };
                    Poll::Ready(Ok(answer))
                }
            }
            dashmap::Entry::Vacant(entry) => {
                entry.insert(Reponse::Demand(cx.waker().clone()));
                Poll::Pending
            }
        });

        timeout(Duration::from_millis(500), query)
            .await
            .unwrap_or_else(|_| {
                self.response_router.remove(&query_id);
                Err(io::Error::new(io::ErrorKind::TimedOut, "Query timed out"))
            })
    }

    pub fn spwan_broadcast_packet(&self, packet: Packet) -> io::Result<()> {
        tokio::spawn({
            let io = self.io.clone();
            async move {
                let mut buf = BytesMut::with_capacity(512);
                buf.put_packet(&packet);
                io.send_to(buf.as_ref(), (MULTICAST_ADDR, MULTICAST_PORT))
                    .await
            }
        });
        Ok(())
    }

    pub fn request_queue(&self) -> ArcAsyncDeque<(SocketAddr, Packet)> {
        self.request_queue.clone()
    }

    pub fn response_queue(&self) -> ArcAsyncDeque<(SocketAddr, Packet)> {
        self.response_queue.clone()
    }
}
