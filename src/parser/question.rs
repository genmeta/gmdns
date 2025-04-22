use bytes::BufMut;
use nom::number::streaming::be_u16;

use super::name::{Name, be_name};
use crate::parser::name::WriteName;

///
/// ```text
/// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /                     QNAME                     /
/// /                                               /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     QTYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     QCLASS                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ``
#[derive(Debug)]
pub struct Question {
    pub(crate) name: Name,
    pub(crate) prefer_unicast: bool,
    pub(crate) qtype: QueryType,
    pub(crate) qclass: QueryClass,
}

#[derive(Debug, PartialEq, Eq)]
pub enum QueryType {
    /// a host addresss
    A,
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

impl QueryType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::A,
            28 => Self::Aaaa,
            5 => Self::Cname,
            16 => Self::Txt,
            33 => Self::Srv,
            12 => Self::Ptr,
            _ => Self::Unimplemented(value),
        }
    }
    pub fn to_u16(&self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
            Self::Cname => 5,
            Self::Txt => 16,
            Self::Srv => 33,
            Self::Ptr => 12,
            Self::Unimplemented(value) => *value,
        }
    }
}

/// The QCLASS value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum QueryClass {
    /// the Internet
    IN = 1,
    /// the CSNET class (Obsolete - used only for examples in some obsolete
    /// RFCs)
    CS = 2,
    /// the CHAOS class
    CH = 3,
    /// Hesiod [Dyer 87]
    HS = 4,
    /// Any class
    Any = 255,
}

impl QueryClass {
    pub fn from_u16(value: u16) -> Self {
        let value = value & 0x7FFF; // Mask to 15 bits
        match value {
            1 => Self::IN,
            2 => Self::CS,
            3 => Self::CH,
            4 => Self::HS,
            255 => Self::Any,
            _ => panic!("Unknown class {}", value),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            Self::IN => 1,
            Self::CS => 2,
            Self::CH => 3,
            Self::HS => 4,
            Self::Any => 255,
        }
    }
}

pub fn be_question<'a>(input: &'a [u8], origin: &'a [u8]) -> nom::IResult<&'a [u8], Question> {
    let (remain, name) = be_name(input, origin)?;
    let (remain, qtype) = be_u16(remain)?;
    let (remain, qclass) = be_u16(remain)?;

    Ok((
        remain,
        Question {
            name,
            prefer_unicast: qclass & 0x8000 == 0x8000,
            qtype: QueryType::from_u16(qtype),
            qclass: QueryClass::from_u16(qclass),
        },
    ))
}

pub trait WriteQuestion {
    fn put_question(&mut self, question: &Question);
}

impl<T: BufMut> WriteQuestion for T {
    fn put_question(&mut self, question: &Question) {
        self.put_name(&question.name);
        self.put_u16(question.qtype.to_u16());
        let mut qclass = question.qclass.to_u16();
        if question.prefer_unicast {
            qclass |= 0x8000;
        }
        self.put_u16(qclass);
    }
}
