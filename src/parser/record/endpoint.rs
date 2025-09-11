use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use bytes::BufMut;
use nom::{
    IResult, Parser,
    combinator::{flat_map, map},
    number::streaming::{be_u16, be_u32, be_u128},
};
/// EndpointAddress record
///
/// - E: IPv4 Direct address
/// - EE: IPv4 Relay address
/// - E6: IPv6 Direct address
/// - EE6: IPv6 Relay address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointAddr {
    E(SocketAddrV4),
    EE(SocketAddrV4, SocketAddrV4),
    E6(SocketAddrV6),
    EE6(SocketAddrV6, SocketAddrV6),
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
            EndpointAddr::E(addr) => (*addr).into(),
            EndpointAddr::EE(outer, _) => (*outer).into(),
            EndpointAddr::E6(addr) => (*addr).into(),
            EndpointAddr::EE6(outer, _) => (*outer).into(),
        }
    }
}

pub(crate) trait WriteEndpointAddr {
    fn put_endpoint_addr(&mut self, endpoint: &EndpointAddr);
}

impl<B: BufMut> WriteEndpointAddr for B {
    fn put_endpoint_addr(&mut self, endpoint: &EndpointAddr) {
        match endpoint {
            EndpointAddr::E(addr) => self.put_socket_addr_v4(addr),
            EndpointAddr::EE(outer, agent) => {
                self.put_socket_addr_v4(outer);
                self.put_socket_addr_v4(agent);
            }
            EndpointAddr::E6(addr) => self.put_socket_addr_v6(addr),
            EndpointAddr::EE6(outer, agent) => {
                self.put_socket_addr_v6(outer);
                self.put_socket_addr_v6(agent);
            }
        }
    }
}

pub fn be_endpoint_addr(
    input: &[u8],
    is_relay: bool,
    is_ipv6: bool,
) -> nom::IResult<&[u8], EndpointAddr> {
    match (is_relay, is_ipv6) {
        (true, true) => {
            let (remain, outer) = be_socket_addr_v6(input)?;
            let (remain, agent) = be_socket_addr_v6(remain)?;
            Ok((remain, EndpointAddr::EE6(outer, agent)))
        }
        (true, false) => {
            let (remain, outer) = be_socket_addr_v4(input)?;
            let (remain, agent) = be_socket_addr_v4(remain)?;
            Ok((remain, EndpointAddr::EE(outer, agent)))
        }
        (false, true) => {
            let (remain, addr) = be_socket_addr_v6(input)?;
            Ok((remain, EndpointAddr::E6(addr)))
        }
        (false, false) => {
            let (remain, addr) = be_socket_addr_v4(input)?;
            Ok((remain, EndpointAddr::E(addr)))
        }
    }
}

pub trait WriteSocketAddr {
    fn put_socket_addr_v4(&mut self, addr: &SocketAddrV4);

    fn put_socket_addr_v6(&mut self, addr: &SocketAddrV6);

    fn put_socket_addr(&mut self, addr: &SocketAddr) {
        match addr {
            SocketAddr::V4(v4) => self.put_socket_addr_v4(v4),
            SocketAddr::V6(v6) => self.put_socket_addr_v6(v6),
        }
    }
}

impl<T: BufMut> WriteSocketAddr for T {
    fn put_socket_addr_v4(&mut self, addr: &SocketAddrV4) {
        self.put_u16(addr.port());
        self.put_u32(u32::from(*addr.ip()));
    }

    fn put_socket_addr_v6(&mut self, addr: &SocketAddrV6) {
        self.put_u16(addr.port());
        self.put_u128(u128::from(*addr.ip()));
    }
}

pub fn be_socket_addr_v4(input: &[u8]) -> IResult<&[u8], SocketAddrV4> {
    flat_map(be_u16, |port| {
        map(be_ipv4_addr, move |ip| SocketAddrV4::new(ip, port))
    })
    .parse(input)
}

pub fn be_socket_addr_v6(input: &[u8]) -> IResult<&[u8], SocketAddrV6> {
    flat_map(be_u16, |port| {
        map(be_ipv6_addr, move |ip| SocketAddrV6::new(ip, port, 0, 0))
    })
    .parse(input)
}

pub fn be_ipv4_addr(input: &[u8]) -> IResult<&[u8], Ipv4Addr> {
    map(be_u32, Ipv4Addr::from).parse(input)
}

pub fn be_ipv6_addr(input: &[u8]) -> IResult<&[u8], Ipv6Addr> {
    map(be_u128, Ipv6Addr::from).parse(input)
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
