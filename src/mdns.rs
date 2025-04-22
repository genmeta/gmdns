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
struct MDNS {
    service_name: String,
    io: Arc<tokio::net::UdpSocket>,
    address: Vec<IpAddr>,
    port: u16,
}

impl MDNS {
    fn new(service_name: String, address: Vec<IpAddr>, port: u16) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        socket.set_reuse_port(true)?;

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MULTICAST_PORT);
        socket.bind(&bind.into())?;
        let io = Arc::new(tokio::net::UdpSocket::from_std(socket.into())?);

        Ok(Self {
            service_name,
            io,
            address,
            port,
        })
    }
}

#[derive(Clone)]
pub struct ArcMDNS(Arc<Mutex<MDNS>>);

impl ArcMDNS {
    pub fn new(service_name: String, address: Vec<IpAddr>, port: u16) -> Self {
        let mdns = MDNS::new(service_name, address, port).unwrap();
        ArcMDNS(Arc::new(Mutex::new(mdns)))
    }

    pub fn discover(&mut self) -> impl Stream<Item = Packet> {
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        let guard = self.0.lock().unwrap();
        let io = guard.io.clone();
        tokio::spawn({
            let mdns = self.clone();
            async move {
                loop {
                    let mut recv_buffer = [0u8; 1024];
                    let (count, src) = io.recv_from(&mut recv_buffer).await.unwrap();
                    match be_packet(&recv_buffer[..count]) {
                        Ok((_remain, packet)) => match packet.header.flags.query() {
                            true => {
                                let _ = response_tx.send(packet);
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
                tokio::time::sleep(Duration::from_secs(15)).await;
                let _ = Self::send_query(io.clone(), service_name.clone()).await;
            }
        });

        UnboundedReceiverStream::new(response_rx)
    }

    pub async fn send_query(
        io: Arc<tokio::net::UdpSocket>,
        service_name: String,
    ) -> io::Result<()> {
        let mut buf = BytesMut::with_capacity(512);
        let mut question = Packet::new();
        question.add_question(&service_name, QueryType::Ptr, QueryClass::IN, false);
        buf.put_packet(&question);

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MULTICAST_PORT);
        io.send_to(&buf[..], &addr).await?;
        Ok(())
    }

    fn reponse_packet(&self) -> Packet {
        let mut response = Packet::new();
        let garud = self.0.lock().unwrap();
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

        let srv = Srv::new(0, 0, garud.port, garud.service_name.clone());
        response.add_response(
            &garud.service_name,
            parser::record::Type::Srv,
            parser::record::Class::IN,
            300,
            parser::record::RData::Srv(srv),
        );
        response
    }

    pub async fn send_response(&self) -> io::Result<()> {
        let mut buf = BytesMut::with_capacity(512);
        let response = self.reponse_packet();
        let io = self.0.lock().unwrap().io.clone();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MULTICAST_PORT);
        buf.put_packet(&response);
        io.send_to(&buf[..], addr).await?;
        Ok(())
    }
}
