use std::ops::Deref;

#[derive(Debug)]
pub struct Txt<'a> {
    bytes: &'a [u8],
}

impl Deref for Txt<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes
    }
}

impl<'a> Txt<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl<'a> Iterator for Txt<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.len() > 1 {
            let len = self.bytes[0] as usize;
            assert!(len < self.bytes.len());
            let (item, remian) = self.bytes[1..].split_at(len);
            self.bytes = remian;
            return Some(item);
        }
        None
    }
}
