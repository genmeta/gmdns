use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use bytes::BufMut;
use nom::{
    IResult, Parser,
    combinator::{flat_map, map},
    number::streaming::{be_u16, be_u32, be_u128},
};
/// EndpointAddress record
/// E: IPv4 Direct address
/// EE: IPv4 Relay address
/// E6: IPv6  Direct address
/// EE6: IPv6  Relay address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointAddr {
    E(SocketAddr),
    EE(SocketAddr, SocketAddr),
    E6(SocketAddr),
    EE6(SocketAddr, SocketAddr),
}

impl EndpointAddr {
    pub fn encpding_size(&self) -> usize {
        match self {
            EndpointAddr::E(..) => 2 + 4,
            EndpointAddr::EE(..) => 2 + 4 + 2 + 4,
            EndpointAddr::E6(..) => 2 + 16,
            EndpointAddr::EE6(..) => 2 + 16 + 2 + 16,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        match self {
            EndpointAddr::E(addr) => *addr,
            EndpointAddr::EE(outer, _) => *outer,
            EndpointAddr::E6(addr) => *addr,
            EndpointAddr::EE6(outer, _) => *outer,
        }
    }
}

pub(crate) trait WriteEndpointAddr {
    fn put_endpoint_addr(&mut self, endpoint: &EndpointAddr);
}

impl<B: BufMut> WriteEndpointAddr for B {
    fn put_endpoint_addr(&mut self, endpoint: &EndpointAddr) {
        match endpoint {
            EndpointAddr::E(addr) => self.put_socket_addr(addr),
            EndpointAddr::EE(outer, agent) => {
                self.put_socket_addr(outer);
                self.put_socket_addr(agent);
            }
            EndpointAddr::E6(addr) => self.put_socket_addr(addr),
            EndpointAddr::EE6(outer, agent) => {
                self.put_socket_addr(outer);
                self.put_socket_addr(agent);
            }
        }
    }
}

pub fn be_endpoint_addr(
    input: &[u8],
    is_relay: bool,
    is_ipv6: bool,
) -> nom::IResult<&[u8], EndpointAddr> {
    if is_relay {
        let (remain, outer) = be_socket_addr(input, is_ipv6)?;
        let (remain, agent) = be_socket_addr(remain, is_ipv6)?;
        if is_ipv6 {
            Ok((remain, EndpointAddr::EE6(outer, agent)))
        } else {
            Ok((remain, EndpointAddr::EE(outer, agent)))
        }
    } else {
        let (remain, addr) = be_socket_addr(input, is_ipv6)?;
        if is_ipv6 {
            Ok((remain, EndpointAddr::E6(addr)))
        } else {
            Ok((remain, EndpointAddr::E(addr)))
        }
    }
}

pub trait WriteSocketAddr {
    fn put_socket_addr(&mut self, addr: &SocketAddr);
}

impl<T: BufMut> WriteSocketAddr for T {
    fn put_socket_addr(&mut self, addr: &SocketAddr) {
        self.put_u16(addr.port());
        match addr.ip() {
            IpAddr::V4(ipv4) => self.put_u32(ipv4.into()),
            IpAddr::V6(ipv6) => self.put_u128(ipv6.into()),
        }
    }
}

pub fn be_socket_addr(input: &[u8], is_ipv6: bool) -> IResult<&[u8], SocketAddr> {
    flat_map(be_u16, |port| {
        map(be_ip_addr(is_ipv6), move |ip| SocketAddr::new(ip, port))
    })
    .parse(input)
}

pub fn be_ip_addr(is_v6: bool) -> impl Fn(&[u8]) -> IResult<&[u8], IpAddr> {
    move |input| match is_v6 {
        true => map(be_u128, |ip| IpAddr::V6(Ipv6Addr::from(ip))).parse(input),
        false => map(be_u32, |ip| IpAddr::V4(Ipv4Addr::from(ip))).parse(input),
    }
}

impl Display for EndpointAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EndpointAddr::E(addr) => write!(f, "{addr}"),
            EndpointAddr::EE(outer, agent) => write!(f, "{outer}-{agent}"),
            EndpointAddr::E6(addr) => write!(f, "{addr}"),
            EndpointAddr::EE6(outer, agent) => write!(f, "{outer}-{agent}"),
        }
    }
}
