use bytes::BufMut;
use nom::Parser;

use super::{
    header::{Header, be_header},
    question::{Question, be_question},
    record::ResourceRecord,
};
use crate::parser::{
    header::WriteHeader,
    question::WriteQuestion,
    record::{WriteRecord, be_record},
};

/// Parsed DNS packet
#[derive(Debug)]
#[allow(missing_docs)] // should be covered by spec
pub struct Packet<'a> {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord<'a>>,
    pub nameservers: Vec<ResourceRecord<'a>>,
    pub additional: Vec<ResourceRecord<'a>>,
}

pub fn parse_packet(input: &[u8]) -> nom::IResult<&[u8], Packet> {
    let (remain, header) = be_header(input)?;
    let (remain, questions) =
        nom::multi::count(be_question, header.questions_count() as usize).parse(remain)?;
    let (remain, answers) =
        nom::multi::count(be_record, header.answers_count() as usize).parse(remain)?;
    let (remain, nameservers) =
        nom::multi::count(be_record, header.nameservers_count() as usize).parse(remain)?;
    let (remain, additional) =
        nom::multi::count(be_record, header.additional_count() as usize).parse(remain)?;
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
