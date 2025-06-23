use std::collections::HashMap;

use bytes::BufMut;

use super::{
    header::{Header, be_header},
    question::{QueryClass, QueryType, Question, be_question},
    record::{Class, RData, ResourceRecord, endpoint::EndpointAddr},
};
use crate::parser::{
    header::WriteHeader,
    question::WriteQuestion,
    record::{Type, WriteRecord, be_record},
};

/// Parsed DNS packet
#[derive(Debug, Default)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub nameservers: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
}

impl Packet {
    pub fn query_with_id(service_name: String) -> Self {
        let mut packet = Packet::default();
        let id: u16 = rand::random();
        packet.header.id = id;
        packet.header.flags.set_query(false);
        packet.add_question(&service_name, QueryType::A, QueryClass::IN, false);
        packet
    }

    pub fn query(service_name: String) -> Self {
        let mut packet = Self::default();
        packet.add_question(&service_name, QueryType::A, QueryClass::IN, true);
        packet
    }

    pub fn answer(id: u16, hosts: &HashMap<String, Vec<EndpointAddr>>) -> Self {
        let mut packet = Self::default();
        packet.header.id = id;
        packet.header.flags.set_query(true);
        hosts.iter().for_each(|(name, eps)| {
            eps.iter().for_each(|ep| {
                let (rtype, rdata) = match ep {
                    EndpointAddr::E(..) => (Type::E, RData::E(*ep)),
                    EndpointAddr::E6(..) => (Type::E6, RData::E6(*ep)),
                    EndpointAddr::EE(..) => (Type::EE, RData::EE(*ep)),
                    EndpointAddr::EE6(..) => (Type::EE6, RData::EE6(*ep)),
                };
                packet.add_answer(name, rtype, Class::IN, 300, rdata);
            });
        });
        packet
    }

    fn add_question(
        &mut self,
        qname: &str,
        qtype: QueryType,
        qclass: QueryClass,
        prefer_unicast: bool,
    ) {
        let question = Question {
            name: qname.to_string(),
            prefer_unicast,
            qtype,
            qclass,
        };
        self.header.questions_count += 1;
        self.questions.push(question);
    }

    fn add_answer(&mut self, name: &str, rtype: Type, rclass: Class, ttl: u32, data: RData) {
        let response = ResourceRecord {
            name: name.to_string(),
            typ: rtype,
            multicast_unique: false,
            cls: rclass,
            ttl,
            data,
        };
        // true 代表是 response
        self.header.flags.set_query(true);
        self.header.answers_count += 1;
        self.answers.push(response);
    }
}

pub fn be_packet(input: &[u8]) -> nom::IResult<&[u8], Packet> {
    let (remain, header) = be_header(input)?;

    let (remain, questions) =
        parse::<Question>(remain, input, header.questions_count, be_question)?;
    let (remain, answers) =
        parse::<ResourceRecord>(remain, input, header.answers_count, be_record)?;
    let (remain, nameservers) =
        parse::<ResourceRecord>(remain, input, header.nameservers_count, be_record)?;
    let (remain, additional) =
        parse::<ResourceRecord>(remain, input, header.additional_count, be_record)?;

    Ok((
        remain,
        Packet {
            header,
            questions,
            answers,
            nameservers,
            additional,
        },
    ))
}

fn parse<'a, T>(
    mut input: &'a [u8],
    original: &'a [u8],
    count: u16,
    parser: impl Fn(&'a [u8], &'a [u8]) -> nom::IResult<&'a [u8], T>,
) -> nom::IResult<&'a [u8], Vec<T>> {
    let mut records = Vec::with_capacity(count as usize);
    for _ in 0..count {
        match parser(input, original) {
            Ok((new_input, record)) => {
                records.push(record);
                input = new_input;
            }
            Err(nom::Err::Error(nom::error::Error {
                input: remaining, ..
            })) => {
                input = remaining;
            }
            _ => break,
        }
    }
    Ok((input, records))
}

pub trait WritePacket {
    fn put_packet(&mut self, packet: &Packet);
}

impl<T: BufMut> WritePacket for T {
    fn put_packet(&mut self, packet: &Packet) {
        self.put_header(&packet.header);
        for question in &packet.questions {
            self.put_question(question);
        }
        for answer in &packet.answers {
            self.put_record(answer);
        }
        for nameserver in &packet.nameservers {
            self.put_record(nameserver);
        }
        for additional in &packet.additional {
            self.put_record(additional);
        }
    }
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use bytes::BytesMut;

    use super::*;
    use crate::parser::{
        self,
        question::{QueryClass, QueryType},
        record::{Class, RData, Type, srv::Srv},
    };

    #[test]
    fn parse_example_query() {
        let query = b"\x06%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                      \x07example\x03com\x00\x00\x01\x00\x01";
        let (_, packet) = be_packet(query).unwrap();
        assert_eq!(packet.header.id, 1573);
        assert_eq!(packet.header.questions_count, 1);
        assert_eq!(packet.questions[0].qtype, QueryType::A);
        assert_eq!(packet.questions[0].qclass, QueryClass::IN);
        assert_eq!(packet.questions[0].name.to_string(), "example.com");
        assert_eq!(packet.header.answers_count, 0);
    }

    #[test]
    fn parse_example_response() {
        let response = b"\x06%\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                         \x07example\x03com\x00\x00\x01\x00\x01\
                         \xc0\x0c\x00\x01\x00\x01\x00\x00\x04\xf8\
                         \x00\x04]\xb8\xd8\"";
        let (_, packet) = be_packet(response).unwrap();
        assert_eq!(packet.header.id, 1573);
        assert_eq!(packet.header.questions_count, 1);
        assert_eq!(packet.questions[0].qtype, QueryType::A);
        assert_eq!(packet.questions[0].qclass, QueryClass::IN);
        assert_eq!(packet.questions[0].name.to_string(), "example.com");
        assert_eq!(packet.header.answers_count, 1);
        assert_eq!(packet.answers[0].name.to_string(), "example.com");
        assert_eq!(packet.answers[0].typ, Type::A);
        assert_eq!(packet.answers[0].cls, Class::IN);
        assert_eq!(packet.answers[0].ttl, 1272);
        match &packet.answers[0].data {
            RData::A(addr) => assert_eq!(*addr, Ipv4Addr::new(93, 184, 216, 34)),
            _ => panic!("unexpected rdata"),
        }
    }

    #[test]
    fn parse_response_with_multicast_unique() {
        let response = b"\x06%\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                         \x07example\x03com\x00\x00\x01\x00\x01\
                         \xc0\x0c\x00\x01\x80\x01\x00\x00\x04\xf8\
                         \x00\x04]\xb8\xd8\"";
        let (_, packet) = be_packet(response).unwrap();

        assert_eq!(packet.answers.len(), 1);
        assert!(packet.answers[0].multicast_unique);
        assert_eq!(packet.answers[0].cls, Class::IN);
    }

    #[test]
    fn parse_additional_record_response() {
        tracing_subscriber::fmt().with_ansi(false).init();
        let response = b"\x4a\xf0\x81\x80\x00\x01\x00\x01\x00\x01\x00\x01\
                         \x03www\x05skype\x03com\x00\x00\x01\x00\x01\
                         \xc0\x0c\x00\x05\x00\x01\x00\x00\x0e\x10\
                         \x00\x1c\x07\x6c\x69\x76\x65\x63\x6d\x73\x0e\x74\
                         \x72\x61\x66\x66\x69\x63\x6d\x61\x6e\x61\x67\x65\
                         \x72\x03\x6e\x65\x74\x00\
                         \xc0\x42\x00\x02\x00\x01\x00\x01\xd5\xd3\x00\x11\
                         \x01\x67\x0c\x67\x74\x6c\x64\x2d\x73\x65\x72\x76\x65\x72\x73\
                         \xc0\x42\
                         \x01\x61\xc0\x55\x00\x01\x00\x01\x00\x00\xa3\x1c\
                         \x00\x04\xc0\x05\x06\x1e";
        let (_, packet) = be_packet(response).unwrap();

        assert_eq!(packet.header.id, 19184);
        assert_eq!(packet.header.questions_count, 1);
        assert_eq!(packet.questions[0].qtype, QueryType::A);
        assert_eq!(packet.questions[0].qclass, QueryClass::IN);
        assert_eq!(&packet.questions[0].name.to_string()[..], "www.skype.com");
        assert_eq!(packet.answers.len(), 1);
        assert_eq!(&packet.answers[0].name.to_string()[..], "www.skype.com");
        assert_eq!(packet.answers[0].cls, Class::IN);
        assert_eq!(packet.answers[0].ttl, 3600);

        match &packet.answers[0].data {
            RData::CName(cname) => {
                assert_eq!(cname, "livecms.trafficmanager.net");
            }
            ref x => panic!("Wrong rdata {x:?}"),
        }
        assert_eq!(packet.additional.len(), 1);
        assert_eq!(
            &packet.additional[0].name.to_string()[..],
            "a.gtld-servers.net"
        );
        assert_eq!(packet.additional[0].cls, Class::IN);
        assert_eq!(packet.additional[0].ttl, 41756);
        match packet.additional[0].data {
            RData::A(addr) => {
                assert_eq!(addr, Ipv4Addr::new(192, 5, 6, 30));
            }
            ref x => panic!("Wrong rdata {x:?}"),
        }
    }

    #[test]
    fn parse_pack_packet() {
        let mut response = Packet::default();
        let address = [
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
            )),
        ];
        for ip in address.iter() {
            let (rtype, rdata) = match ip {
                IpAddr::V4(ipv4_addr) => (
                    parser::record::Type::A,
                    parser::record::RData::A(*ipv4_addr),
                ),
                IpAddr::V6(ipv6_addr) => (
                    parser::record::Type::AAAA,
                    parser::record::RData::AAAA(*ipv6_addr),
                ),
            };
            response.add_answer("example.com", rtype, parser::record::Class::IN, 300, rdata);
        }

        let srv = Srv::new(0, 0, 6000, "example.com".to_string());
        response.add_answer(
            "example.com",
            parser::record::Type::Srv,
            parser::record::Class::IN,
            300,
            parser::record::RData::Srv(srv),
        );
        let mut buf = BytesMut::with_capacity(512);
        buf.put_packet(&response);
        let packet = buf.freeze();
        let (_, parsed_packet) = be_packet(&packet).unwrap();
        assert_eq!(parsed_packet.header.id, response.header.id);
        assert_eq!(
            parsed_packet.header.questions_count,
            response.header.questions_count
        );
        assert_eq!(parsed_packet.answers.len(), response.answers.len());
        assert_eq!(parsed_packet.nameservers.len(), response.nameservers.len());
        assert_eq!(parsed_packet.additional.len(), response.additional.len());
        assert_eq!(parsed_packet.answers[0].name, response.answers[0].name);
    }
}
