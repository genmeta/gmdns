use std::{
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
};

use bytes::{Buf, BufMut};
use endpoint::{EndpointAddr, WriteEndpointAddr, be_endpoint_addr};
use nom::{
    Parser,
    bytes::streaming::take,
    combinator::map,
    number::streaming::{be_u16, be_u32, be_u128},
};
use ptr::{Ptr, be_ptr};
use srv::{Srv, WriteSrv, be_srv};
use tokio::io;
use txt::Txt;

use super::name::{Name, be_name};
use crate::parser::{name::WriteName, record::ptr::WritePtr};

pub mod endpoint;
pub mod ptr;
pub mod srv;
pub mod txt;
/// '''text
/// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /                                               /
/// /                      NAME                     /
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     CLASS                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TTL                      |
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                   RDLENGTH                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/// /                     RDATA                     /
/// /                                               /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// '''
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct ResourceRecord {
    pub(crate) name: Name,
    pub(crate) typ: Type,
    /// Whether or not the set of resource records is fully contained in the
    /// packet, or whether there will be more resource records in future
    /// packets. Only used for multicast DNS.
    pub(crate) multicast_unique: bool,
    pub(crate) cls: Class,
    pub(crate) ttl: u32,
    pub(crate) data: RData,
}

impl ResourceRecord {
    pub fn data(&self) -> &RData {
        &self.data
    }

    pub fn name(&self) -> Name {
        self.name.clone()
    }
}

/// The CLASS value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Class {
    /// the Internet
    IN = 1,
    /// the CSNET class (Obsolete - used only for examples in some obsolete
    /// RFCs)
    CS = 2,
    /// the CHAOS class
    CH = 3,
    /// Hesiod [Dyer 87]
    HS = 4,
}

impl TryFrom<u16> for Class {
    type Error = io::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        let value = value & 0x7FFF; // Mask to 15 bits
        let class = match value {
            1 => Self::IN,
            2 => Self::CS,
            3 => Self::CH,
            4 => Self::HS,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unknown record class: {value}"),
                ));
            }
        };
        Ok(class)
    }
}

impl From<Class> for u16 {
    fn from(value: Class) -> Self {
        match value {
            Class::IN => 1,
            Class::CS => 2,
            Class::CH => 3,
            Class::HS => 4,
        }
    }
}

/// The TYPE value according to RFC 1035
///
/// All "EXPERIMENTAL" markers here are from the RFC
/// See https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Type {
    /// 1 a host addresss
    A,
    /// 2 an authoritative name server
    Ns,
    /// 28 IPv6 host address (RFC 2782)
    #[allow(clippy::upper_case_acronyms)]
    AAAA,
    /// 5 the canonical name for an alias
    Cname,
    /// 16 text strings
    Txt,
    /// 33 service record (RFC 2782)
    Srv,
    /// 12 a domain name pointer
    Ptr,
    /// Unassigned 265-32767
    /// 266 a ipv4 address,
    E,
    /// 267 a ipv6 address,
    E6,
    /// 268 a ipv4 relay endpoint,
    EE,
    /// 269 a ipv6 relay endpoint,
    EE6,
}

impl TryFrom<u16> for Type {
    type Error = io::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        let typ = match value {
            1 => Self::A,
            2 => Self::Ns,
            28 => Self::AAAA,
            5 => Self::Cname,
            16 => Self::Txt,
            33 => Self::Srv,
            12 => Self::Ptr,
            265 => Self::E,
            266 => Self::E,
            267 => Self::E6,
            268 => Self::EE,
            269 => Self::EE6,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unknown record type: {value}"),
                ));
            }
        };
        Ok(typ)
    }
}

impl From<Type> for u16 {
    fn from(value: Type) -> Self {
        match value {
            Type::A => 1,
            Type::Ns => 2,
            Type::AAAA => 28,
            Type::Cname => 5,
            Type::Txt => 16,
            Type::Srv => 33,
            Type::Ptr => 12,
            Type::E => 265,
            Type::E6 => 267,
            Type::EE => 268,
            Type::EE6 => 269,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CName(Name),
    Txt(Txt),
    Srv(Srv),
    Ptr(Ptr),
    E(EndpointAddr),
    E6(EndpointAddr),
    EE(EndpointAddr),
    EE6(EndpointAddr),
}

impl Display for RData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RData::A(ip) => write!(f, "{ip}"),
            RData::AAAA(ip) => write!(f, "{ip}"),
            RData::CName(name) => write!(f, "CName({name})"),
            RData::Txt(txt) => write!(f, "{txt:?})"),
            RData::Srv(srv) => write!(f, "{srv:?}"),
            RData::Ptr(ptr) => write!(f, "{ptr:?}"),
            RData::E(e) | RData::E6(e) | RData::EE(e) | RData::EE6(e) => write!(f, "{e}"),
        }
    }
}

impl RData {
    pub fn encpding_size(&self) -> usize {
        match self {
            RData::A(_ip) => 4,
            RData::AAAA(_ip) => 16,
            RData::CName(name) => name.len(),
            RData::Txt(txt) => txt.len(),
            RData::Srv(srv) => srv.encpding_size(),
            RData::Ptr(ptr) => ptr.encpding_size(),
            RData::E(e) => e.encpding_size(),
            RData::E6(e) => e.encpding_size(),
            RData::EE(e) => e.encpding_size(),
            RData::EE6(e) => e.encpding_size(),
        }
    }
}

pub fn be_record<'a>(input: &'a [u8], origin: &'a [u8]) -> nom::IResult<&'a [u8], ResourceRecord> {
    let (remain, name) = be_name(input, origin)?;
    let (remain, typ) = be_u16(remain)?;
    let (remain, cls) = be_u16(remain)?;
    let (remain, ttl) = be_u32(remain)?;
    let (mut remain, rdlen) = be_u16(remain)?;

    let Ok(typ) = Type::try_from(typ) else {
        if remain.len() < rdlen as usize {
            return Err(nom::Err::Incomplete(nom::Needed::new(
                rdlen as usize - remain.len(),
            )));
        }
        remain.advance(rdlen as usize);
        return Err(nom::Err::Error(nom::error::make_error(
            remain,
            nom::error::ErrorKind::Alt,
        )));
    };
    let (mut remain, rdata) = be_rdata(remain, origin, typ, rdlen)?;

    let multicast_unique = cls & 0x8000 == 0x8000;
    let cls = cls & 0x7FFF;
    let Ok(cls) = Class::try_from(cls) else {
        if remain.len() < rdlen as usize {
            return Err(nom::Err::Incomplete(nom::Needed::new(
                rdlen as usize - remain.len(),
            )));
        }
        remain.advance(rdlen as usize);
        return Err(nom::Err::Error(nom::error::make_error(
            remain,
            nom::error::ErrorKind::Alt,
        )));
    };

    Ok((
        remain,
        ResourceRecord {
            name,
            typ,
            multicast_unique,
            cls,
            ttl,
            data: rdata,
        },
    ))
}

fn be_rdata<'a>(
    input: &'a [u8],
    origin: &'a [u8],
    typ: Type,
    rdlen: u16,
) -> nom::IResult<&'a [u8], RData> {
    match typ {
        Type::A => map(be_u32, |ip| RData::A(Ipv4Addr::from(ip))).parse(input),
        Type::AAAA => map(be_u128, |ip| RData::AAAA(Ipv6Addr::from(ip))).parse(input),
        Type::Cname => be_name(input, origin).map(|(remain, name)| (remain, RData::CName(name))),
        Type::Txt => map(take(rdlen), |txt: &[u8]| RData::Txt(Txt::new(txt.to_vec()))).parse(input),
        Type::Srv => {
            let (remain, srv) = be_srv(input, origin)?;
            Ok((remain, RData::Srv(srv)))
        }
        Type::Ptr => be_ptr(input, origin).map(|(remain, ptr)| (remain, RData::Ptr(ptr))),
        Type::Ns => be_name(input, origin).map(|(remain, name)| (remain, RData::CName(name))),
        Type::E => be_endpoint_addr(input, false, false).map(|(remain, e)| (remain, RData::E(e))),
        Type::E6 => be_endpoint_addr(input, false, true).map(|(remain, e)| (remain, RData::E6(e))),
        Type::EE => be_endpoint_addr(input, true, false).map(|(remain, e)| (remain, RData::EE(e))),
        Type::EE6 => be_endpoint_addr(input, true, true).map(|(remain, e)| (remain, RData::EE6(e))),
    }
}

pub trait WriteRecord {
    fn put_record(&mut self, record: &ResourceRecord);
}

impl<T: BufMut> WriteRecord for T {
    fn put_record(&mut self, record: &ResourceRecord) {
        self.put_name(&record.name);
        self.put_u16(record.typ.into());
        let mut cls = record.cls.into();
        if record.multicast_unique {
            cls |= 0x8000;
        }
        self.put_u16(cls);
        self.put_u32(record.ttl);
        self.put_u16(record.data.encpding_size() as u16);
        self.put_rdata(&record.data);
    }
}

pub trait WriteRData {
    fn put_rdata(&mut self, rdata: &RData);
}

impl<T: BufMut> WriteRData for T {
    fn put_rdata(&mut self, rdata: &RData) {
        match rdata {
            RData::A(ip) => self.put_slice(&ip.octets()),
            RData::AAAA(ip) => self.put_slice(&ip.octets()),
            RData::CName(name) => self.put_name(name),
            RData::Txt(txt) => self.put_slice(txt),
            RData::Srv(srv) => self.put_srv(srv),
            RData::Ptr(ptr) => self.put_ptr(ptr),
            RData::E(e) => self.put_endpoint_addr(e),
            RData::E6(e) => self.put_endpoint_addr(e),
            RData::EE(e) => self.put_endpoint_addr(e),
            RData::EE6(e) => self.put_endpoint_addr(e),
        }
    }
}
