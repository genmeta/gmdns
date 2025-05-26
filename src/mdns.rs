use std::{
    collections::HashMap,
    io::{self},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::BytesMut;
use socket2::{Domain, Socket, Type};
use tokio::sync::mpsc::{self};
use tokio_stream::{Stream, wrappers::UnboundedReceiverStream};

use crate::parser::{
    self,
    packet::{Packet, WritePacket, be_packet},
    question::{QueryClass, QueryType},
    record::{RData, srv::Srv},
};

const MULTICAST_PORT: u16 = 5353;
const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

struct Mdns {
    domain: String,
    service_name: String,
    io: Arc<tokio::net::UdpSocket>,
    address: Vec<SocketAddr>,
}

impl Mdns {
    fn new(domain: String, service_name: String, address: Vec<SocketAddr>) -> io::Result<Self> {
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
        // 定时发布 query
        tokio::spawn({
            let service_name = service_name.clone();
            let io = io.clone();
            async move {
                loop {
                    let _ = Self::send_query(io.clone(), service_name.clone()).await;
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
        });

        Ok(Self {
            domain,
            service_name,
            io,
            address,
        })
    }

    pub async fn send_query(
        io: Arc<tokio::net::UdpSocket>,
        service_name: String,
    ) -> io::Result<()> {
        let mut buf = BytesMut::with_capacity(512);
        let mut question = Packet::default();
        question.add_question(&service_name, QueryType::Ptr, QueryClass::IN, false);
        buf.put_packet(&question);
        let addr = SocketAddr::new(IpAddr::V4(MULTICAST_ADDR), MULTICAST_PORT);
        io.send_to(&buf[..], &addr).await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct ArcMdns(Arc<Mutex<Mdns>>);

impl ArcMdns {
    pub fn new(domain: String, service_name: String, address: Vec<SocketAddr>) -> Self {
        let mdns = Mdns::new(domain, service_name, address).unwrap();

        ArcMdns(Arc::new(Mutex::new(mdns)))
    }

    pub fn discover(&mut self) -> impl Stream<Item = (String, Vec<SocketAddr>)> {
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        let guard = self.0.lock().unwrap();
        let io = guard.io.clone();
        let service_name = guard.service_name.clone();
        tokio::spawn({
            let mdns = self.clone();
            async move {
                loop {
                    let mut recv_buffer = [0u8; 1024];
                    let (count, src) = io.recv_from(&mut recv_buffer).await.unwrap();
                    match be_packet(&recv_buffer[..count]) {
                        Ok((_remain, packet)) => match packet.header.flags.query() {
                            true => {
                                let (domian, addr) = mdns.parse_response(&packet, &src).unwrap();
                                let _ = response_tx.send((domian, addr));
                            }
                            false => {
                                if packet
                                    .questions
                                    .iter()
                                    .any(|question| question.name == service_name)
                                {
                                    let _ = mdns.send_response().await;
                                }
                            }
                        },
                        Err(_) => {
                            continue;
                        }
                    };
                }
            }
        });

        UnboundedReceiverStream::new(response_rx)
    }

    pub fn publish(&self, address: Vec<SocketAddr>) {
        let mut guard = self.0.lock().unwrap();
        guard.address = address;
    }

    fn response_packet(&self) -> Packet {
        let mut response = Packet::default();
        let guard = self.0.lock().unwrap();
        let domain = &guard.domain;

        response.add_question(&guard.service_name, QueryType::Ptr, QueryClass::IN, false);

        const TTL: u32 = 300;

        let mut srv_map: HashMap<String, Srv> = HashMap::new();
        guard.address.iter().for_each(|addr| {
            let (rtype, ip) = match addr.ip() {
                IpAddr::V4(ipv4) => (parser::record::Type::A, RData::A(ipv4)),
                IpAddr::V6(ipv6) => (parser::record::Type::Aaaa, RData::Aaaa(ipv6)),
            };

            let name = format!("{}:{}", domain, addr.port());
            response.add_response(&name, rtype, parser::record::Class::IN, TTL, ip);
            srv_map
                .entry(name.clone())
                .or_insert_with(|| Srv::new(0, 0, addr.port(), name.clone()));
        });

        for srv in srv_map.into_values() {
            response.add_response(
                domain,
                parser::record::Type::Srv,
                parser::record::Class::IN,
                TTL,
                parser::record::RData::Srv(srv),
            );
        }
        response
    }

    pub async fn send_response(&self) -> io::Result<()> {
        let mut buf = BytesMut::with_capacity(512);
        let response = self.response_packet();
        let io = self.0.lock().unwrap().io.clone();
        let addr = SocketAddr::new(IpAddr::V4(MULTICAST_ADDR), MULTICAST_PORT);
        buf.put_packet(&response);
        io.send_to(&buf[..], addr).await?;
        Ok(())
    }

    fn parse_response(
        &self,
        packet: &Packet,
        src: &SocketAddr,
    ) -> io::Result<(String, Vec<SocketAddr>)> {
        let mut map_ports = HashMap::new();
        let mut domain = String::new();
        packet
            .answers
            .iter()
            .filter(|a| a.typ == parser::record::Type::Srv)
            .for_each(|a| {
                if let parser::record::RData::Srv(srv) = &a.data {
                    map_ports.insert(srv.target().clone(), srv.port());
                    if domain.is_empty() {
                        domain = a.name.clone();
                    }
                }
            });

        let mut addrs: Vec<SocketAddr> = packet
            .answers
            .iter()
            .filter_map(|a| {
                let port = map_ports.get(&a.name).copied().unwrap_or(0);
                match &a.data {
                    parser::record::RData::A(ip) => Some((*ip, port).into()),
                    parser::record::RData::Aaaa(ip) => Some((*ip, port).into()),
                    _ => None,
                }
            })
            .collect();
        // 找到和 SRC IP 相同的地址，放在最前面，提高连接成功率
        if let Some(index) = addrs.iter().position(|addr| addr.ip() == src.ip()) {
            addrs.swap(0, index);
        }
        Ok((domain, addrs))
    }
}
