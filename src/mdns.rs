use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    io::{self},
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use futures::{Stream, stream};
use tokio::time::{self};
use tokio_util::task::AbortOnDropHandle;

use crate::{
    parser::{packet::Packet, record::endpoint::EndpointAddr},
    protocol::MdnsProtocol,
};

#[derive(Debug)]
pub struct Mdns {
    service_name: String,
    local_device: String,
    proto: Arc<MdnsProtocol>,
    hosts: Arc<Mutex<HashMap<String, Vec<EndpointAddr>>>>,
    _broadcast: AbortOnDropHandle<()>,
    _responder: AbortOnDropHandle<()>,
}

impl Display for Mdns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mDNS({})", self.local_device)
    }
}

impl Mdns {
    pub fn new(service_name: &str, ip: Ipv4Addr, device: &str) -> io::Result<Self> {
        let service_name = service_name.to_string();
        let proto = MdnsProtocol::new(device, ip)?;
        let hosts = Arc::new(Mutex::new(HashMap::<String, Vec<EndpointAddr>>::new()));

        let broadcast = AbortOnDropHandle::new(tokio::spawn({
            let proto = proto.clone();
            let service_name = service_name.clone();
            async move {
                let mut interval = time::interval(Duration::from_secs(10));
                interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    let packet = Packet::query(service_name.clone());
                    if let Err(e) = proto.broadcast_packet(packet).await {
                        tracing::debug!(target: "mdns", "Broadcast packet error: {}", e);
                    }
                }
            }
        }));

        let responder = AbortOnDropHandle::new(tokio::spawn({
            let proto = proto.clone();
            let hosts = hosts.clone();
            let service_name = service_name.clone();

            async move {
                while let Ok((_src, query)) = proto.receive_query().await {
                    let packet = {
                        let guard = hosts.lock().unwrap();
                        let host_name = guard
                            .keys()
                            .cloned()
                            .map(|h| Self::local_name(service_name.clone(), h))
                            .collect::<HashSet<_>>();

                        query
                            .questions
                            .iter()
                            .any(|q| host_name.iter().any(|h| h.contains(q.name.as_str())))
                            .then(|| Packet::answer(query.header.id, &guard))
                    };
                    if let Some(packet) = packet
                        && let Err(e) = proto.broadcast_packet(packet).await
                    {
                        tracing::debug!(target: "mdns", "Send response error: {}", e);
                    }
                }
            }
        }));

        Ok(Self {
            service_name,
            local_device: device.to_string(),
            proto,
            hosts,
            _broadcast: broadcast,
            _responder: responder,
        })
    }

    #[inline]
    pub fn local_device(&self) -> &str {
        &self.local_device
    }

    #[inline]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    #[inline]
    pub fn insert_host(&self, host_name: String, host_addr: Vec<SocketAddr>) {
        let local_name = Self::local_name(self.service_name.clone(), host_name.clone());
        let mut guard = self.hosts.lock().unwrap();
        tracing::debug!(
            target: "mdns",
            %local_name, ?host_addr,
            "Adding host with addresses",
        );
        let eps = host_addr
            .into_iter()
            .map(|addr| match addr {
                SocketAddr::V4(addr) => EndpointAddr::direct_v4(addr),
                SocketAddr::V6(addr) => EndpointAddr::direct_v6(addr),
            })
            .collect::<Vec<_>>();
        guard.insert(local_name, eps);
    }

    #[inline]
    pub async fn query(&self, domain: String) -> io::Result<Vec<EndpointAddr>> {
        let proto = self.proto.clone();
        let local_name = Self::local_name(self.service_name.clone(), domain.clone());
        let (src, mut endpoints) = proto.query(local_name).await?;
        if let Some(pos) = endpoints.iter().position(|ep| ep.addr().ip() == src.ip()) {
            endpoints.swap(0, pos);
        }
        if endpoints.is_empty() {
            return Err(io::Error::other("empty dns result"));
        }
        Ok(endpoints)
    }

    #[inline]
    pub fn discover(&self) -> impl Stream<Item = (SocketAddr, Packet)> {
        Box::pin(stream::unfold(self.proto.clone(), async move |proto| {
            Some((proto.receive_boardcast().await.ok()?, proto))
        }))
    }

    #[inline]
    fn local_name(service_name: String, name: String) -> String {
        name.split_once("genmeta.net")
            .map(|(prefix, _)| format!("{prefix}{service_name}"))
            .unwrap_or(name)
    }
}
