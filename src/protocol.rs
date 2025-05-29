use std::{
    future::poll_fn,
    io::{self},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    task::{Poll, Waker},
    time::Duration,
};

use bytes::BytesMut;
use dashmap::DashMap;
use socket2::{Domain, Socket, Type};
use tokio::{net::UdpSocket, sync::mpsc::Receiver, time::timeout};
use tracing::debug;

use crate::parser::packet::{Packet, WritePacket, be_packet};

const MULTICAST_PORT: u16 = 5353;
const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

enum Reponse {
    Demand(Waker),
    Answer((SocketAddr, Packet)),
}

type ArcReceiver<T> = Arc<Mutex<Option<Receiver<T>>>>;

#[derive(Clone)]
pub struct MdnsProtocol {
    io: Arc<UdpSocket>,
    req_rx: ArcReceiver<(SocketAddr, Packet)>,
    resp_rx: ArcReceiver<(SocketAddr, Packet)>,
    response_router: Arc<DashMap<u16, Reponse>>,
}

impl MdnsProtocol {
    pub fn new() -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        #[cfg(not(target_os = "windows"))]
        socket.set_reuse_port(true)?;

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MULTICAST_PORT);
        socket.bind(&bind.into())?;
        socket.set_multicast_loop_v4(false)?;
        socket.join_multicast_v4(&MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED)?;
        let io = Arc::new(tokio::net::UdpSocket::from_std(socket.into())?);

        let (req_tx, req_rx) = tokio::sync::mpsc::channel(64);
        let (resp_tx, resp_rx) = tokio::sync::mpsc::channel(64);
        let response_router = Arc::new(DashMap::<u16, Reponse>::new());
        let _rcvd_task = {
            let response_router = response_router.clone();
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
                        (true, 0) => resp_tx.send((src, packet)).await.unwrap(),
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
                        (false, _) => req_tx.send((src, packet)).await.unwrap(),
                    }
                }
            })
        }
        .abort_handle();
        Ok(Self {
            io,
            req_rx: Arc::new(Mutex::new(Some(req_rx))),
            resp_rx: Arc::new(Mutex::new(Some(resp_rx))),
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

        timeout(Duration::from_secs(1), query)
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

    pub fn take_req_rx(&self) -> Option<Receiver<(SocketAddr, Packet)>> {
        self.req_rx.lock().unwrap().take()
    }

    pub fn take_resp_rx(&self) -> Option<Receiver<(SocketAddr, Packet)>> {
        self.resp_rx.lock().unwrap().take()
    }
}
