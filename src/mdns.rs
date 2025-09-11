use std::{
    collections::{HashMap, HashSet},
    io::{self},
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::time::{self};
use tokio_stream::{Stream, wrappers::ReceiverStream};

use crate::{
    parser::{packet::Packet, record::endpoint::EndpointAddr},
    protocol::MdnsProtocol,
};

#[derive(Clone)]
pub struct Mdns {
    service_name: String,
    proto: Arc<MdnsProtocol>,
    hosts: Arc<Mutex<HashMap<String, Vec<EndpointAddr>>>>,
}

impl Mdns {
    pub fn new(service_name: &str, ip: Ipv4Addr, device: &str) -> io::Result<Self> {
        let service_name = service_name.to_string();
        let proto = MdnsProtocol::new(device, ip)?;
        let hosts = Arc::new(Mutex::new(HashMap::<String, Vec<EndpointAddr>>::new()));

        tokio::spawn({
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
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
        });

        tokio::spawn({
            let proto = proto.clone();
            let hosts = hosts.clone();
            let service_name = service_name.clone();
            async move {
                while let Ok((_src, query)) = proto.receive_query().await {
                    let guard = hosts.lock().unwrap();
                    let host_name = guard
                        .keys()
                        .cloned()
                        .map(|h| Self::local_name(service_name.clone(), h))
                        .collect::<HashSet<_>>();
                    if query
                        .questions
                        .iter()
                        .any(|q| host_name.iter().any(|h| h.contains(q.name.as_str())))
                    {
                        let packet = Packet::answer(query.header.id, &guard);
                        let proto = proto.clone();
                        tokio::spawn(async move {
                            if let Err(error) = proto.broadcast_packet(packet).await {
                                tracing::debug!(target: "mdns", ?error,"Broadcast answer packet error");
                            }
                        });
                    }
                }
            }
        });

        Ok(Self {
            service_name,
            proto,
            hosts,
        })
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    pub fn add_host(&self, host_name: String, host_addr: Vec<SocketAddr>) {
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
                SocketAddr::V4(addr) => EndpointAddr::E(addr),
                SocketAddr::V6(addr) => EndpointAddr::E6(addr),
            })
            .collect::<Vec<_>>();
        guard.insert(local_name, eps);
    }

    pub async fn query(&self, domain: String) -> io::Result<Vec<EndpointAddr>> {
        let proto = self.proto.clone();
        let local_name = Self::local_name(self.service_name.clone(), domain.clone());
        let (src, mut endpoints) = proto.query(local_name).await?;
        if let Some(pos) = endpoints.iter().position(|ep| ep.addr().ip() == src.ip()) {
            endpoints.swap(0, pos);
        }
        if endpoints.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("No endpoint found for: {domain}"),
            ));
        }
        Ok(endpoints)
    }

    pub fn discover(&mut self) -> impl Stream<Item = (SocketAddr, Packet)> {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let proto = self.proto.clone();
        tokio::spawn({
            async move {
                while let Ok((src, packet)) = proto.receive_boardcast().await {
                    if let Err(error) = tx.send((src, packet)).await {
                        tracing::debug!(target: "mdns", %error, "Failed to send response packet");
                    }
                }
            }
        });
        ReceiverStream::new(rx)
    }

    fn local_name(service_name: String, name: String) -> String {
        name.split_once("genmeta.net")
            .map(|(prefix, _)| format!("{prefix}{service_name}"))
            .unwrap_or(name)
    }
}
