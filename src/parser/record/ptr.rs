use bytes::BufMut;

use crate::parser::name::{Name, WriteName, be_name, name_encoding_size};

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Ptr(Name);

impl Ptr {
    pub fn encpding_size(&self) -> usize {
        name_encoding_size(&self.0)
    }
}

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

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;

    #[test]
    fn ptr_encoding_size_matches_bytes() {
        let ptr = Ptr("example.com".to_string());
        let mut buf = BytesMut::new();
        buf.put_ptr(&ptr);
        assert_eq!(buf.len(), ptr.encpding_size());
        assert_eq!(buf.as_ref(), b"\x07example\x03com\x00");
    }
}
