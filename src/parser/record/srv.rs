use bytes::BufMut;
use nom::number::streaming::be_u16;

use crate::parser::name::{Name, WriteName, be_name};

#[derive(Debug)]
pub struct Srv {
    priority: u16,
    weight: u16,
    port: u16,
    target: Name,
}

pub fn be_srv<'a>(input: &'a [u8], origin: &'a [u8]) -> nom::IResult<&'a [u8], Srv> {
    let (remain, priority) = be_u16(input)?;
    let (remain, weight) = be_u16(remain)?;
    let (remain, port) = be_u16(remain)?;
    let (remain, target) = be_name(remain, origin)?;
    Ok((
        remain,
        Srv {
            priority,
            weight,
            port,
            target,
        },
    ))
}

pub trait WriteSrv {
    fn put_srv(&mut self, srv: &Srv);
}

impl<T: BufMut> WriteSrv for T {
    fn put_srv(&mut self, srv: &Srv) {
        self.put_u16(srv.priority);
        self.put_u16(srv.weight);
        self.put_u16(srv.port);
        self.put_name(&srv.target);
    }
}
