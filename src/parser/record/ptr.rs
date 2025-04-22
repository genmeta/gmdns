use bytes::BufMut;

use crate::parser::name::{Name, WriteName, be_name};

#[derive(Debug)]
pub struct Ptr(Name);

pub fn be_ptr<'a>(input: &'a [u8], origin: &'a [u8]) -> nom::IResult<&'a [u8], Ptr> {
    let (remain, name) = be_name(input, origin)?;
    Ok((remain, Ptr(name)))
}

pub trait WritePtr {
    fn put_ptr(&mut self, ptr: &Ptr);
}

impl<T: BufMut> WritePtr for T {
    fn put_ptr(&mut self, ptr: &Ptr) {
        self.put_name(&ptr.0);
    }
}
