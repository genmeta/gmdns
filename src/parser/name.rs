use bytes::BufMut;
use nom::{
    Err, IResult,
    bytes::streaming::take,
    error::{Error, ErrorKind},
    number::streaming::be_u8,
};

pub type Name = String;

/// https://datatracker.ietf.org/doc/html/rfc1035#section-3.1
/// TODO: 支持压缩域名
pub fn be_name(input: &[u8]) -> IResult<&[u8], Name> {
    let mut remain = input;
    let mut ret = String::new();
    loop {
        let (left, len) = be_u8(remain)?;
        if len == 0 {
            let name = if ret.is_empty() { ".".into() } else { ret };
            return Ok((left, name));
        }
        // 检查是否为压缩指针（高两位为11）
        if len & 0xC0 == 0xC0 {
            return Err(Err::Error(Error::new(input, ErrorKind::Verify)));
        }
        // 检查标签长度是否合法（1-63字节）
        if len > 63 {
            return Err(Err::Error(Error::new(input, ErrorKind::Verify)));
        }
        let (left, name_bytes) = take(len)(left)?;

        // 验证标签内容并转换为小写
        let mut label = String::with_capacity(len as usize);
        for &c in name_bytes {
            if !(32..=126).contains(&c) {
                // 允许 ASCII 32（空格）到 126（~）
                return Err(Err::Error(Error::new(input, ErrorKind::Verify)));
            }
            label.push(c as char);
        }
        // 检查首尾不能为连字符
        if label.starts_with('-') || label.ends_with('-') {
            return Err(Err::Error(Error::new(input, ErrorKind::Verify)));
        }
        // 拼接域名部分
        if !ret.is_empty() {
            ret.push('.');
        }
        ret.push_str(&label);
        remain = left;
    }
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
        let (remain, parsed_name) = be_name(name).unwrap();
        assert_eq!(remain.len(), 0);
        assert_eq!(parsed_name, "example.com");
    }

    #[test]
    fn write_example_name() {
        let mut buf = BytesMut::with_capacity(64);
        let name = "example.com".to_string();
        buf.put_name(&name);
        assert_eq!(buf.as_ref(), b"\x07example\x03com\x00");
    }

    #[test]
    fn test_write_name_root() {
        let mut buf = BytesMut::new();
        buf.put_name(&".".into());
        assert_eq!(buf.as_ref(), b"\x00");
    }

    #[test]
    fn test_write_name_trailing_dot() {
        let mut buf = BytesMut::new();
        buf.put_name(&"example.com.".into());
        // 应等价于 "example.com"
        assert_eq!(buf.as_ref(), b"\x07example\x03com\x00");
    }

    #[test]
    #[should_panic(expected = "exceeds 63 bytes")]
    fn test_write_invalid_label_length() {
        let long_label = "a".repeat(64);
        let mut buf = BytesMut::new();
        buf.put_name(&long_label.to_string());
    }

    #[test]
    #[should_panic(expected = "empty label in middle")]
    fn test_write_empty_middle_label() {
        let mut buf = BytesMut::new();
        buf.put_name(&"a..b".into());
    }

    #[test]
    fn test_mdns_name_with_special_chars() {
        let raw_name = "HP Color LaserJet Pro M478f-9f [EC3C83]._http._tcp.local";

        let mut buf = BytesMut::new();
        buf.put_name(&raw_name.to_string());

        let (remaining, parsed) = be_name(&buf).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(parsed, raw_name);
    }
}
