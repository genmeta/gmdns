use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZero,
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
    time::Duration,
};

use dashmap::DashMap;
use futures::{Stream, StreamExt};
use socket2::{Domain, Socket, Type};
use thiserror::Error;
use tokio::{io, net::UdpSocket, task::JoinSet, time};

use crate::parser::{
    packet::{Packet, WritePacket, be_packet},
    record::endpoint::EndpointAddr,
};

pub struct MdnsSocket(UdpSocket);

const MULTICAST_PORT: u16 = 5353;
const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MAX_DEQUE_SIZE: usize = 64;

impl MdnsSocket {
    pub fn new(device: &str, ip: Ipv4Addr) -> io::Result<Self> {
        tracing::info!(target: "mdns", "add mdns dvice {device} {ip}");
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
        socket.bind_device(Some(device.as_bytes()))?;

        UdpSocket::from_std(socket.into()).map(Self)
    }

    pub async fn receive(&self) -> io::Result<(SocketAddr, Packet)> {
        loop {
            let mut recv_buffer = [0u8; 2048];

            let (size, source) = self.0.recv_from(&mut recv_buffer).await?;

            let Ok((_remain, packet)) = be_packet(&recv_buffer[..size]) else {
                continue;
            };

            return Ok((source, packet));
        }
    }

    pub async fn broadcast_packet(&self, packet: Packet) -> io::Result<()> {
        let mut buf = Vec::with_capacity(2048);
        buf.put_packet(&packet);
        self.0
            .send_to(&buf, (MULTICAST_ADDR, MULTICAST_PORT))
            .await?;

        Ok(())
    }
}

#[allow(clippy::type_complexity)]
pub struct PacketRouter {
    requests: (
        flume::Sender<(SocketAddr, Packet)>,
        flume::Receiver<(SocketAddr, Packet)>,
    ),
    responses: (
        flume::Sender<(SocketAddr, Packet)>,
        flume::Receiver<(SocketAddr, Packet)>,
    ),
    queries: DashMap<NonZero<u16>, flume::Sender<(SocketAddr, Packet)>>,
}

impl PacketRouter {
    pub fn new() -> Self {
        Self {
            requests: flume::bounded(MAX_DEQUE_SIZE),
            responses: flume::bounded(MAX_DEQUE_SIZE),
            queries: DashMap::new(),
        }
    }

    pub fn receive_query(
        &self,
    ) -> impl Future<Output = Result<(SocketAddr, Packet), flume::RecvError>> + Send + use<> {
        self.requests.1.clone().into_recv_async()
    }

    pub fn receive_boardcast(
        &self,
    ) -> impl Future<Output = Result<(SocketAddr, Packet), flume::RecvError>> + Send + use<> {
        self.responses.1.clone().into_recv_async()
    }

    pub async fn register_query(
        self: &Arc<Self>,
        query_id: NonZero<u16>,
    ) -> impl Stream<Item = (SocketAddr, Packet)> {
        struct Responses {
            query_id: NonZero<u16>,
            router: Weak<PacketRouter>,
            recver: flume::r#async::RecvStream<'static, (SocketAddr, Packet)>,
        }

        impl Stream for Responses {
            type Item = (SocketAddr, Packet);

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                Pin::new(&mut self.recver).poll_next(cx)
            }
        }

        impl Drop for Responses {
            fn drop(&mut self) {
                if let Some(router) = self.router.upgrade() {
                    router.queries.remove(&self.query_id);
                }
            }
        }

        let (tx, rx) = flume::bounded(MAX_DEQUE_SIZE);
        self.queries.insert(query_id, tx);

        Responses {
            query_id,
            router: Arc::downgrade(self),
            recver: rx.into_stream(),
        }
    }

    pub fn deliver(&self, source: SocketAddr, packet: Packet) {
        match (packet.header.flags.query(), packet.header.id) {
            (true, 0) => {
                if let Err(e) = self.responses.0.try_send((source, packet)) {
                    tracing::warn!(target: "mdns", "Failed to deliver boardcast: {e}");
                }
            }
            (true, query_id) => match self.queries.get(&NonZero::new(query_id).unwrap()) {
                Some(tx) => {
                    if let Err(e) = tx.try_send((source, packet)) {
                        tracing::warn!(
                            target: "mdns",
                            "Failed to route response for query id {query_id}: {e}"
                        );
                    }
                }
                None => tracing::warn!(
                    target: "mdns",
                    "Received response for query id {query_id}, but no such kquery registered"
                ),
            },
            (false, _) => {
                if let Err(e) = self.requests.0.try_send((source, packet)) {
                    tracing::warn!(target: "mdns", "Failed to deliver incoming request: {e}");
                }
            }
        }
    }
}

pub struct MdnsProtocol {
    socket: MdnsSocket,
    router: Weak<PacketRouter>,
}

#[derive(Debug, Error)]
#[error("MDns socket is not listening")]
pub struct Disconnected;

impl From<Disconnected> for io::Error {
    fn from(error: Disconnected) -> Self {
        io::Error::new(io::ErrorKind::NotConnected, error)
    }
}

impl MdnsProtocol {
    pub fn new(device: &str, ip: Ipv4Addr) -> io::Result<Arc<Self>> {
        let socket = MdnsSocket::new(device, ip)?;
        let router = Arc::new(PacketRouter::new());
        let proto = Arc::new(Self {
            socket,
            router: Arc::downgrade(&router),
        });

        tokio::spawn({
            let proto = proto.clone();
            async move {
                while let Ok((source, packet)) = proto.socket.receive().await {
                    router.deliver(source, packet);
                }
            }
        });

        Ok(proto)
    }

    pub async fn broadcast_packet(&self, packet: Packet) -> io::Result<()> {
        self.socket.broadcast_packet(packet).await
    }

    pub async fn query(
        self: &Arc<Self>,
        local_name: String,
    ) -> io::Result<(SocketAddr, Vec<EndpointAddr>)> {
        let router = self.router.upgrade().ok_or(Disconnected)?;

        let packet = Packet::query_with_id(local_name.clone());
        let query_id = NonZero::new(packet.header.id).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Query id should not be 0")
        })?;

        let mut packets = router.register_query(query_id).await;
        let mut broadcast_tasks = JoinSet::new();

        for _ in 0..3 {
            _ = broadcast_tasks.spawn({
                let this = self.clone();
                let packet = packet.clone();
                async move { this.broadcast_packet(packet).await }
            });

            if let Ok(Some((source, packet))) =
                time::timeout(Duration::from_millis(300), packets.next()).await
            {
                use crate::parser::record::RData::*;
                let endpoints = packet
                    .answers
                    .iter()
                    .inspect(|answer| {
                        tracing::debug!(target: "mdns", "Recv response: {answer:?}");
                    })
                    .filter(|answer| {
                        if answer.name != local_name {
                            tracing::debug!(
                                target: "mdns",
                                "Ignored answer for different service name: {} != {}",
                                answer.name,
                                local_name
                            );
                        }
                        answer.name == local_name
                    })
                    .filter_map(|answer| match answer.data {
                        E(e) | EE(e) | E6(e) | EE6(e) => Some(e),
                        _ => {
                            tracing::debug!("Ignored record: {answer:?}");
                            None
                        }
                    })
                    .collect::<Vec<_>>();

                if !endpoints.is_empty() {
                    return Ok((source, endpoints));
                }
            }
        }

        broadcast_tasks.abort_all();
        Err(io::ErrorKind::TimedOut.into())
    }

    pub async fn receive_query(&self) -> Result<(SocketAddr, Packet), Disconnected> {
        let router = self.router.upgrade().ok_or(Disconnected)?;

        router.receive_query().await.map_err(|_| Disconnected)
    }
    pub async fn receive_boardcast(&self) -> Result<(SocketAddr, Packet), Disconnected> {
        let router = self.router.upgrade().ok_or(Disconnected)?;

        router.receive_boardcast().await.map_err(|_| Disconnected)
    }
}
