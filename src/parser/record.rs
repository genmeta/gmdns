use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::BufMut;
use nom::{
    Parser,
    bytes::streaming::take,
    combinator::map,
    number::streaming::{be_u16, be_u32, be_u128},
};
use srv::{Srv, WriteSrv, be_srv};
use txt::Txt;

use super::name::{Name, be_name};
use crate::parser::name::WriteName;

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
pub struct ResourceRecord<'a> {
    pub(crate) name: Name,
    pub(crate) typ: Type,
    /// Whether or not the set of resource records is fully contained in the
    /// packet, or whether there will be more resource records in future
    /// packets. Only used for multicast DNS.
    pub(crate) multicast_unique: bool,
    pub(crate) cls: Class,
    pub(crate) ttl: u32,
    pub(crate) data: RData<'a>,
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
            _ => panic!("Unknown class {}", value),
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
    /// IPv6 host address (RFC 2782)
    AAAA,
    /// the canonical name for an alias
    CNAME,
    /// text strings
    TXT,
    /// service record (RFC 2782)
    SRV,
    /// Unimplemented record type
    Unimplemented(u16),
}

impl Type {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::A,
            28 => Self::AAAA,
            5 => Self::CNAME,
            16 => Self::TXT,
            33 => Self::SRV,
            _ => Self::Unimplemented(value),
        }
    }
    pub fn to_u16(self) -> u16 {
        match self {
            Self::A => 1,
            Self::AAAA => 28,
            Self::CNAME => 5,
            Self::TXT => 16,
            Self::SRV => 33,
            Self::Unimplemented(value) => value,
        }
    }
}

#[derive(Debug)]
pub enum RData<'a> {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(Name),
    Txt(Txt<'a>),
    Srv(Srv),
    Unknown(&'a [u8]),
}

pub fn be_record<'a>(
    input: &'a [u8],
    origin: &'a [u8],
) -> nom::IResult<&'a [u8], ResourceRecord<'a>> {
    let (remain, name) = be_name(input, origin)?;
    let (remian, typ) = be_u16(remain)?;
    let (remain, cls) = be_u16(remian)?;
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
) -> nom::IResult<&'a [u8], RData<'a>> {
    match typ {
        Type::A => map(be_u32, |ip| RData::A(Ipv4Addr::from(ip))).parse(input),
        Type::AAAA => map(be_u128, |ip| RData::Aaaa(Ipv6Addr::from(ip))).parse(input),
        Type::CNAME => be_name(input, origin).map(|(remian, name)| (remian, RData::Cname(name))),
        Type::TXT => map(take(rdlen), |txt| RData::Txt(Txt::new(txt))).parse(input),
        Type::SRV => {
            let (remain, srv) = be_srv(input, origin)?;
            Ok((remain, RData::Srv(srv)))
        }
        Type::Unimplemented(_) => map(take(rdlen), RData::Unknown).parse(input),
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

        match &record.data {
            RData::A(ip) => self.put_slice(&ip.octets()),
            RData::Aaaa(ip) => self.put_slice(&ip.octets()),
            RData::Cname(name) => self.put_name(name),
            RData::Txt(txt) => self.put_slice(txt),
            RData::Srv(srv) => self.put_srv(srv),
            RData::Unknown(unknown) => self.put_slice(unknown),
        }
    }
}
