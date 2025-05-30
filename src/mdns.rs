use std::{
    collections::HashMap,
    io::{self},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio_stream::{Stream, wrappers::ReceiverStream};
use tracing::{debug, warn};

use crate::{
    parser::{
        packet::Packet,
        record::{
            RData::{E, E6, EE, EE6},
            endpoint::EndpointAddr,
        },
    },
    protocol::MdnsProtocol,
};

#[derive(Clone)]
pub struct Mdns {
    service_name: String,
    proto: MdnsProtocol,
    hosts: Arc<Mutex<HashMap<String, Vec<EndpointAddr>>>>,
}

impl Mdns {
    pub fn new(service_name: &str) -> io::Result<Self> {
        let service_name = service_name.to_string();
        let proto = MdnsProtocol::new()?;
        let hosts = Arc::new(Mutex::new(HashMap::<String, Vec<EndpointAddr>>::new()));
        tokio::spawn({
            let proto = proto.clone();
            let service_name = service_name.clone();
            async move {
                loop {
                    let packet = Packet::query(service_name.clone());
                    if let Err(e) = proto.spwan_broadcast_packet(packet) {
                        warn!("[MDNS]: broadcast packet error: {}", e);
                    }
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            }
        });

        tokio::spawn({
            let proto = proto.clone();
            let hosts = hosts.clone();
            let service_name = service_name.clone();
            async move {
                let mut req_rx = proto.take_req_rx().unwrap();
                while let Some((_src, query)) = req_rx.recv().await {
                    if !query
                        .questions
                        .iter()
                        .any(|q| q.name.contains(&service_name))
                    {
                        tracing::trace!(
                            "[MDNS]: Received query {query:?} without service name: {service_name:?}",
                        );
                        continue;
                    }
                    let packet = Packet::answer(query.header.id, &hosts.lock().unwrap());
                    let _ = proto.spwan_broadcast_packet(packet);
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
        let local_name = Self::local_name(self.service_name.clone(), domain.clone());
        let packet = Packet::query_with_id(local_name.clone());
        let proto = self.proto.clone();
        debug!("[MDNS]: Querying for: {local_name}");
        let (src, response) = proto.query(packet).await?;
        let mut endpoints = response
            .answers
            .into_iter()
            .filter_map(|answer| {
                debug!("[MDNS]: recv response: {answer:?}");
                if answer.name != local_name {
                    debug!(
                        "[MDNS]: Ignored answer for different service name: {} != {}",
                        answer.name, local_name
                    );
                    return None;
                }
                match answer.data {
                    E(e) | EE(e) | E6(e) | EE6(e) => Some(e),
                    _ => {
                        debug!("Ignored record: {answer:?}");
                        None
                    }
                }
            })
            .collect::<Vec<_>>();

        if let Some(pos) = endpoints.iter().position(|ep| ep.addr().ip() == src.ip()) {
            endpoints.swap(0, pos);
        }
        if endpoints.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("No endpoint found for: {local_name}"),
            ));
        }

        Ok(endpoints)
    }

    pub fn discover(&mut self) -> impl Stream<Item = (SocketAddr, Packet)> {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn({
            let proto = self.proto.clone();
            async move {
                let mut resp_rx = proto.take_resp_rx().unwrap();
                while let Some((src, packet)) = resp_rx.recv().await {
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
