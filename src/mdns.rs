use std::{
    io::{self},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::BytesMut;
use socket2::{Domain, Socket, Type};
use tokio::sync::mpsc;
use tokio_stream::{Stream, wrappers::UnboundedReceiverStream};

use crate::parser::{
    self,
    packet::{Packet, WritePacket, be_packet},
    question::{QueryClass, QueryType},
    record::srv::Srv,
};

const MULTICAST_PORT: u16 = 5353;
const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

struct Mdns {
    domain: String,
    service_name: String,
    io: Arc<tokio::net::UdpSocket>,
    address: Vec<IpAddr>,
    port: u16,
}

impl Mdns {
    fn new(
        domain: String,
        service_name: String,
        address: Vec<IpAddr>,
        port: u16,
    ) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        socket.set_reuse_port(true)?;

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MULTICAST_PORT);
        socket.bind(&bind.into())?;
        socket.set_multicast_loop_v4(false)?;
        socket.join_multicast_v4(&MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED)?;
        let io = Arc::new(tokio::net::UdpSocket::from_std(socket.into())?);

        Ok(Self {
            domain,
            service_name,
            io,
            address,
            port,
        })
    }
}

#[derive(Clone)]
pub struct ArcMdns(Arc<Mutex<Mdns>>);

impl ArcMdns {
    pub fn new(domain: String, service_name: String, address: Vec<IpAddr>, port: u16) -> Self {
        let mdns = Mdns::new(domain, service_name, address, port).unwrap();
        ArcMdns(Arc::new(Mutex::new(mdns)))
    }

    pub fn discover(&mut self) -> impl Stream<Item = (String, Vec<SocketAddr>)> {
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        let guard = self.0.lock().unwrap();
        let io = guard.io.clone();
        tokio::spawn({
            let mdns = self.clone();
            async move {
                loop {
                    let mut recv_buffer = [0u8; 1024];
                    let (count, _src) = io.recv_from(&mut recv_buffer).await.unwrap();
                    match be_packet(&recv_buffer[..count]) {
                        Ok((_remain, packet)) => match packet.header.flags.query() {
                            true => {
                                let (domian, addr) = mdns.parse_response(&packet).unwrap();
                                let _ = response_tx.send((domian, addr));
                            }
                            false => {
                                let _ = mdns.send_response().await;
                            }
                        },
                        Err(_) => {
                            tracing::error!("Invalid packet");
                            continue;
                        }
                    };
                }
            }
        });

        let io = guard.io.clone();
        let service_name = guard.service_name.clone();
        // 定时发布 query
        tokio::spawn(async move {
            loop {
                let _ = Self::send_query(io.clone(), service_name.clone()).await;
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
        });

        UnboundedReceiverStream::new(response_rx)
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

    fn reponse_packet(&self) -> Packet {
        let mut response = Packet::default();
        let garud = self.0.lock().unwrap();
        response.add_question(&garud.service_name, QueryType::Ptr, QueryClass::IN, false);
        for ip in garud.address.iter() {
            let (rtype, rdata) = match ip {
                IpAddr::V4(ipv4_addr) => (
                    parser::record::Type::A,
                    parser::record::RData::A(*ipv4_addr),
                ),
                IpAddr::V6(ipv6_addr) => (
                    parser::record::Type::Aaaa,
                    parser::record::RData::Aaaa(*ipv6_addr),
                ),
            };
            response.add_response(
                &garud.service_name,
                rtype,
                parser::record::Class::IN,
                300,
                rdata,
            );
        }

        let srv = Srv::new(0, 0, garud.port, garud.domain.clone());
        response.add_response(
            &garud.service_name,
            parser::record::Type::Srv,
            parser::record::Class::IN,
            300,
            parser::record::RData::Srv(srv),
        );
        response
    }

    fn parse_response(&self, packet: &Packet) -> io::Result<(String, Vec<SocketAddr>)> {
        let mut addr = vec![];
        let (port, domain) = packet
            .answers
            .iter()
            .find(|answer| answer.typ == parser::record::Type::Srv)
            .map(|answer| {
                if let parser::record::RData::Srv(srv) = &answer.data {
                    (srv.port(), srv.target().to_string())
                } else {
                    (0, "".to_string())
                }
            })
            .unwrap_or((0, "".to_string()));
        for answer in packet.answers.iter() {
            if let parser::record::RData::A(ip) = answer.data {
                addr.push(SocketAddr::new(ip.into(), port));
            }
            if let parser::record::RData::Aaaa(ip) = answer.data {
                addr.push(SocketAddr::new(ip.into(), port));
            }
        }
        Ok((domain, addr))
    }

    pub async fn send_response(&self) -> io::Result<()> {
        let mut buf = BytesMut::with_capacity(512);
        let response = self.reponse_packet();
        let io = self.0.lock().unwrap().io.clone();
        let addr = SocketAddr::new(IpAddr::V4(MULTICAST_ADDR), MULTICAST_PORT);
        buf.put_packet(&response);
        io.send_to(&buf[..], addr).await?;
        Ok(())
    }
}
