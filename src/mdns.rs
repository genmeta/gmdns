use std::{
    collections::{HashMap, HashSet},
    io::{self},
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio_stream::{Stream, wrappers::ReceiverStream};
use tracing::{debug, warn};

use crate::{
    parser::{packet::Packet, record::endpoint::EndpointAddr},
    protocol::MdnsProtocol,
};

#[derive(Clone)]
pub struct Mdns {
    service_name: String,
    proto: MdnsProtocol,
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
                loop {
                    let packet = Packet::query(service_name.clone());
                    if let Err(e) = proto.spwan_broadcast_packet(&packet) {
                        warn!("[MDNS]: broadcast packet error: {}", e);
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
                let req_rx = proto.req_deque();
                while let Some((_src, query)) = req_rx.pop().await {
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
                        let _ = proto.spwan_broadcast_packet(&packet);
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
        debug!(
            "[MDNS]: Adding host: {} with addresses: {:?}",
            local_name, host_addr
        );
        let eps = host_addr
            .into_iter()
            .map(|addr| {
                if addr.is_ipv6() {
                    EndpointAddr::E6(addr)
                } else {
                    EndpointAddr::E(addr)
                }
            })
            .collect::<Vec<_>>();
        guard.insert(local_name, eps);
    }

    pub async fn query(&self, domain: String) -> io::Result<Vec<EndpointAddr>> {
        let proto = self.proto.clone();
        let local_name = Self::local_name(self.service_name.clone(), domain.clone());
        tracing::info!("[MDNS]: Querying for: {local_name}");
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
        tracing::info!("[MDNS]: Found endpoints: {endpoints:?} for {domain}");
        Ok(endpoints)
    }

    pub fn discover(&mut self) -> impl Stream<Item = (SocketAddr, Packet)> {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let proto = self.proto.clone();
        tokio::spawn({
            async move {
                let resp_deque = proto.resp_queue();
                while let Some((src, packet)) = resp_deque.pop().await {
                    tx.send((src, packet)).await.unwrap_or_else(|e| {
                        warn!("[MDNS]: Failed to send response packet: {e}");
                    });
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
