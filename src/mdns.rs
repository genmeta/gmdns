use std::{
    collections::HashMap,
    io::{self},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use qbase::net::EndpointAddr;
use tokio::sync::mpsc::Receiver;
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tracing::{debug, warn};

use crate::{
    parser::{
        packet::Packet,
        record::{
            self, Class,
            RData::{self, E, E6, EE, EE6},
            Type,
        },
    },
    protocol::MdnsProtocol,
};

pub struct Mdns {
    service_name: String,
    proto: MdnsProtocol,
    hosts: Arc<Mutex<HashMap<String, Vec<SocketAddr>>>>,
    rx: Option<Receiver<(SocketAddr, Packet)>>,
}

impl Mdns {
    pub fn new(service_name: String) -> io::Result<Self> {
        let proto = MdnsProtocol::new()?;
        let hosts = Arc::new(Mutex::new(HashMap::<String, Vec<SocketAddr>>::new()));
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
                while let Some((_src, query)) = proto.request_queue().pop().await {
                    if !query
                        .questions
                        .iter()
                        .any(|q| q.name.contains(&service_name))
                    {
                        debug!(
                            "[MDNS]: Received query {:?} without service name: {:?}",
                            query, service_name
                        );
                        continue;
                    }
                    let mut packet = Packet::reponse_with_id(query.header.id);
                    let guard = hosts.lock().unwrap();
                    guard.iter().for_each(|(name, addrs)| {
                        addrs.iter().for_each(|addr| {
                            let ep = record::e::E(EndpointAddr::direct(*addr));
                            let (rtype, rdata) = match addr {
                                SocketAddr::V4(_) => (Type::E, RData::E(ep)),
                                SocketAddr::V6(_) => (Type::E6, RData::E6(ep)),
                            };
                            packet.add_response(name, rtype, Class::IN, 300, rdata);
                        });
                    });
                    let _ = proto.spwan_broadcast_packet(packet);
                }
            }
        });

        let (tx, rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn({
            let proto = proto.clone();
            async move {
                while let Some((src, packet)) = proto.response_queue().pop().await {
                    tx.send((src, packet)).await.unwrap_or_else(|e| {
                        warn!("[MDNS]: Failed to send response packet: {}", e);
                    });
                }
            }
        });

        Ok(Self {
            service_name,
            proto,
            hosts,
            rx: Some(rx),
        })
    }

    pub fn add_host(&mut self, host_name: String, host_addr: Vec<SocketAddr>) {
        let local_name = Self::local_name(self.service_name.clone(), host_name.clone());
        let mut guard = self.hosts.lock().unwrap();
        debug!(
            "[MDNS]: Adding host: {} with addresses: {:?}",
            local_name, host_addr
        );
        guard.insert(local_name, host_addr);
    }

    pub async fn query(&mut self, domain: String) -> io::Result<Vec<EndpointAddr>> {
        let local_name = Self::local_name(self.service_name.clone(), domain.clone());
        let packet = Packet::query_with_id(local_name.clone());
        let proto = self.proto.clone();
        let (src, response) = proto.query(packet).await?;
        let mut endpoints = response
            .answers
            .into_iter()
            .filter_map(|answer| {
                if answer.name != local_name {
                    debug!(
                        "[MDNS]: Ignored answer for different service name: {} != {}",
                        answer.name, local_name
                    );
                    return None;
                }
                match answer.data {
                    E(e) | EE(e) | E6(e) | EE6(e) => Some(e.endpoint()),
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

        Ok(endpoints)
    }

    pub fn discover(&mut self) -> impl Stream<Item = (SocketAddr, Packet)> {
        ReceiverStream::new(
            self.rx
                .take()
                .expect("[MDNS]: Receiver already taken, cannot discover again!"),
        )
    }

    fn local_name(service_name: String, name: String) -> String {
        name.split_once("genmeta.net")
            .map(|(prefix, _)| format!("{}{}", prefix, service_name))
            .unwrap_or(name)
    }
}
