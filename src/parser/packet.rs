use bytes::BufMut;
use nom::Parser;

use super::{
    header::{Header, be_header},
    question::{QueryClass, QueryType, Question, be_question},
    record::{Class, RData, ResourceRecord},
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
    pub fn add_question(
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

    pub fn add_response(&mut self, name: &str, rtype: Type, rclass: Class, ttl: u32, data: RData) {
        let response = ResourceRecord {
            name: name.to_string(),
            typ: rtype,
            multicast_unique: false,
            cls: rclass,
            ttl,
            data,
        };
        self.header.answers_count += 1;
        self.answers.push(response);
    }
}

pub fn be_packet(input: &[u8]) -> nom::IResult<&[u8], Packet> {
    let (remain, header) = be_header(input)?;

    let (remain, questions) = nom::multi::count(
        |remain| be_question(remain, input),
        header.questions_count as usize,
    )
    .parse(remain)?;

    let (remain, answers) = nom::multi::count(
        |remain| be_record(remain, input),
        header.answers_count as usize,
    )
    .parse(remain)?;

    let (remain, nameservers) = nom::multi::count(
        |remain| be_record(remain, input),
        header.nameservers_count as usize,
    )
    .parse(remain)?;

    let (remain, additional) = nom::multi::count(
        |remain| be_record(remain, input),
        header.additional_count as usize,
    )
    .parse(remain)?;
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
    use std::net::Ipv4Addr;

    use super::*;
    use crate::parser::{
        question::{QueryClass, QueryType},
        record::{Class, RData, Type},
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
            ref x => panic!("Wrong rdata {:?}", x),
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
            ref x => panic!("Wrong rdata {:?}", x),
        }
    }
}
