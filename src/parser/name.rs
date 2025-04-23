use bytes::BufMut;
use nom::{IResult, bytes::streaming::take, number::streaming::be_u8};

pub type Name = String;

pub fn be_name<'a>(input: &'a [u8], origin: &'a [u8]) -> IResult<&'a [u8], Name> {
    be_name_inner(input, origin, &mut vec![])
}

fn be_name_inner<'a>(
    input: &'a [u8],
    origin: &'a [u8],
    visited: &mut Vec<usize>,
) -> IResult<&'a [u8], Name> {
    let mut name = String::new();
    let mut remain = input;
    loop {
        let (left, (label, end)) = be_label(remain, origin, visited)?;
        if end {
            if !label.is_empty() {
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(&label);
            }
            if name.is_empty() {
                name.push('.');
            }
            return Ok((left, name));
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&label);
        remain = left;
    }
}

fn be_label<'a>(
    input: &'a [u8],
    origin: &'a [u8],
    visited: &mut Vec<usize>,
) -> IResult<&'a [u8], (String, bool)> {
    let (remain, len) = be_u8(input)?;
    if len == 0 {
        return Ok((remain, (String::new(), true)));
    }
    if (len & 0xC0) == 0xC0 {
        let (remain, offset_byte) = be_u8(remain)?;
        let offset = (((len & 0x3F) as u16) << 8) | offset_byte as u16;
        let offset = offset as usize;
        if offset >= origin.len() {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )));
        }
        if visited.contains(&offset) {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )));
        }
        visited.push(offset);
        let (_, name) = be_name_inner(&origin[offset..], origin, visited)?;
        visited.pop();
        return Ok((remain, (name, true)));
    }
    if len > 63 {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }
    let (remain, label_bytes) = take(len)(remain)?;
    let label = String::from_utf8_lossy(label_bytes).into_owned();
    Ok((remain, (label, false)))
}

pub trait WriteName {
    fn put_name(&mut self, name: &Name);
}

impl<T: BufMut> WriteName for T {
    fn put_name(&mut self, name: &Name) {
        // 处理根域名（直接写入0）
        if name == "." {
            self.put_u8(0);
            return;
        }

        let parts: Vec<&str> = name.split('.').collect();
        for (i, part) in parts.iter().enumerate() {
            // 检查标签长度
            if part.is_empty() {
                // 仅允许最后一个标签为空（根域名）
                if i != parts.len() - 1 {
                    panic!("Invalid empty label in middle");
                }
                continue;
            }

            let len = part.len();
            if len > 63 {
                panic!("Label exceeds 63 bytes");
            }

            self.put_u8(len as u8);
            self.put_slice(part.as_bytes());
        }
        // 写入根标签终止符
        self.put_u8(0);
    }
}

#[cfg(test)]
mod test {
    use bytes::BytesMut;

    use super::*;

    #[test]
    fn parse_example_name() {
        let name = b"\x07example\x03com\x00";
        let (remain, parsed_name) = be_name(name, name).unwrap();
        assert_eq!(remain.len(), 0);
        assert_eq!(parsed_name, "example.com");
    }

    #[test]
    fn parse_badpointer_same_offset() {
        // A buffer where an offset points to itself,
        // which is a bad compression pointer.
        let same_offset = [192, 2, 192, 2];
        let ret = be_name(&same_offset, &same_offset);
        assert!(ret.is_err())
    }

    #[test]
    fn write_example_name() {
        let mut buf = BytesMut::with_capacity(64);
        let name = "example.com".to_string();
        buf.put_name(&name);
        assert_eq!(buf.as_ref(), b"\x07example\x03com\x00");
    }

    #[test]
    fn write_name_root() {
        let mut buf = BytesMut::new();
        buf.put_name(&".".into());
        assert_eq!(buf.as_ref(), b"\x00");
    }

    #[test]
    fn nested_names() {
        let buf = b"\x02xx\x00\x02yy\xc0\x00\x02zz\xc0\x04";

        let (remaining, parsed) = be_name(buf, buf).unwrap();
        assert_eq!(remaining.len(), 10);
        assert_eq!(parsed, "xx");

        let (_remaining, parsed) = be_name(&buf[4..], buf).unwrap();
        assert_eq!(parsed, "yy.xx");

        // offset only
        let (_remaining, parsed) = be_name(&buf[7..], buf).unwrap();
        assert_eq!(parsed, "xx");

        let (_remaining, parsed) = be_name(&buf[9..], buf).unwrap();
        assert_eq!(parsed, "zz.yy.xx");
    }

    #[test]
    fn write_name_trailing_dot() {
        let mut buf = BytesMut::new();
        buf.put_name(&"example.com.".into());
        // 应等价于 "example.com"
        assert_eq!(buf.as_ref(), b"\x07example\x03com\x00");
    }

    #[test]
    #[should_panic(expected = "exceeds 63 bytes")]
    fn write_invalid_label_length() {
        let long_label = "a".repeat(64);
        let mut buf = BytesMut::new();
        buf.put_name(&long_label.to_string());
    }

    #[test]
    #[should_panic(expected = "empty label in middle")]
    fn write_empty_middle_label() {
        let mut buf = BytesMut::new();
        buf.put_name(&"a..b".into());
    }

    #[test]
    fn mdns_name_with_special_chars() {
        let raw_name = "HP Color LaserJet Pro M478f-9f [EC3C83]._http._tcp.local";

        let mut buf = BytesMut::new();
        buf.put_name(&raw_name.to_string());

        let (remaining, parsed) = be_name(&buf, &buf).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(parsed, raw_name);
    }
}
