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
    name: Name,
    prefer_unicast: bool,
    qtype: QueryType,
    qclass: QueryClass,
}

#[derive(Debug)]
pub enum QueryType {
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

impl QueryType {
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
    pub fn to_u16(&self) -> u16 {
        match self {
            Self::A => 1,
            Self::AAAA => 28,
            Self::CNAME => 5,
            Self::TXT => 16,
            Self::SRV => 33,
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

    pub fn to_u16(&self) -> u16 {
        match self {
            Self::IN => 1,
            Self::CS => 2,
            Self::CH => 3,
            Self::HS => 4,
            Self::Any => 255,
        }
    }
}

pub fn be_question(input: &[u8]) -> nom::IResult<&[u8], Question> {
    let (remain, name) = be_name(input)?;
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
        self.put_u16(question.qclass.to_u16());
    }
}
