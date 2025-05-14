use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::BufMut;
use nom::{
    Parser,
    bytes::streaming::take,
    combinator::map,
    number::streaming::{be_u16, be_u32, be_u128},
};
use ptr::{Ptr, be_ptr};
use srv::{Srv, WriteSrv, be_srv};
use tracing::warn;
use txt::Txt;

use super::name::{Name, be_name};
use crate::parser::{name::WriteName, record::ptr::WritePtr};

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
#[derive(Debug)]
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

/// The CLASS value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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

impl Class {
    pub fn from_u16(value: u16) -> Self {
        let value = value & 0x7FFF; // Mask to 15 bits
        match value {
            1 => Self::IN,
            2 => Self::CS,
            3 => Self::CH,
            4 => Self::HS,
            _ => {
                warn!("Unknown class value: {}", value);
                Self::IN
            }
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            Self::IN => 1,
            Self::CS => 2,
            Self::CH => 3,
            Self::HS => 4,
        }
    }
}

/// The TYPE value according to RFC 1035
///
/// All "EXPERIMENTAL" markers here are from the RFC
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Type {
    /// a host addresss
    A,
    /// an authoritative name server
    Ns,
    /// IPv6 host address (RFC 2782)
    Aaaa,
    /// the canonical name for an alias
    Cname,
    /// text strings
    Txt,
    /// service record (RFC 2782)
    Srv,
    /// a domain name pointer
    Ptr,
    /// Unimplemented record type
    Unimplemented(u16),
}

impl Type {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::A,
            2 => Self::Ns,
            28 => Self::Aaaa,
            5 => Self::Cname,
            16 => Self::Txt,
            33 => Self::Srv,
            12 => Self::Ptr,
            _ => Self::Unimplemented(value),
        }
    }
    pub fn to_u16(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Aaaa => 28,
            Self::Cname => 5,
            Self::Txt => 16,
            Self::Srv => 33,
            Self::Ptr => 12,
            Self::Unimplemented(value) => value,
        }
    }
}

#[derive(Debug)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    CName(Name),
    Txt(Txt),
    Srv(Srv),
    Ptr(Ptr),
    Unknown(),
}

impl RData {
    pub fn len(&self) -> usize {
        match self {
            RData::A(_ip) => 4,
            RData::Aaaa(_ip) => 16,
            RData::CName(name) => name.len(),
            RData::Txt(txt) => txt.len(),
            RData::Srv(srv) => srv.len(),
            RData::Ptr(ptr) => ptr.len(),
            RData::Unknown() => 0,
        }
    }
}

pub fn be_record<'a>(input: &'a [u8], origin: &'a [u8]) -> nom::IResult<&'a [u8], ResourceRecord> {
    let (remain, name) = be_name(input, origin)?;
    let (remain, typ) = be_u16(remain)?;
    let (remain, cls) = be_u16(remain)?;
    let (remain, ttl) = be_u32(remain)?;
    let (remain, rdlen) = be_u16(remain)?;
    let (remain, rdata) = be_rdata(remain, origin, Type::from_u16(typ), rdlen)?;

    Ok((
        remain,
        ResourceRecord {
            name,
            typ: Type::from_u16(typ),
            multicast_unique: cls & 0x8000 != 0,
            cls: Class::from_u16(cls),
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
        Type::Aaaa => map(be_u128, |ip| RData::Aaaa(Ipv6Addr::from(ip))).parse(input),
        Type::Cname => be_name(input, origin).map(|(remain, name)| (remain, RData::CName(name))),
        Type::Txt => map(take(rdlen), |txt: &[u8]| RData::Txt(Txt::new(txt.to_vec()))).parse(input),
        Type::Srv => {
            let (remain, srv) = be_srv(input, origin)?;
            Ok((remain, RData::Srv(srv)))
        }
        Type::Ptr => be_ptr(input, origin).map(|(remain, ptr)| (remain, RData::Ptr(ptr))),
        Type::Ns => be_name(input, origin).map(|(remain, name)| (remain, RData::CName(name))),
        Type::Unimplemented(_) => Ok((&input[rdlen as usize..], RData::Unknown())),
    }
}

pub trait WriteRecord {
    fn put_record(&mut self, record: &ResourceRecord);
}

impl<T: BufMut> WriteRecord for T {
    fn put_record(&mut self, record: &ResourceRecord) {
        self.put_name(&record.name);
        self.put_u16(record.typ.to_u16());
        let mut cls = record.cls.to_u16();
        if record.multicast_unique {
            cls |= 0x8000;
        }
        self.put_u16(cls);
        self.put_u32(record.ttl);
        self.put_u16(record.data.len() as u16);
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
            RData::Aaaa(ip) => self.put_slice(&ip.octets()),
            RData::CName(name) => self.put_name(name),
            RData::Txt(txt) => self.put_slice(txt),
            RData::Srv(srv) => self.put_srv(srv),
            RData::Ptr(ptr) => self.put_ptr(ptr),
            RData::Unknown() => (),
        }
    }
}
