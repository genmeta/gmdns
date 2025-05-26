use bytes::BufMut;
use nom::IResult;
use qbase::net::{WriteEndpointAddr, be_endpoint_addr, route::EndpointAddr};

/// EndpointAddress record
/// E: IPv4 Direct address
/// EE: IPv4 Relay address
/// E6: IPv6  Direct address
/// EE6: IPv6  Relay address
#[derive(Debug)]
pub struct E(pub EndpointAddr);

impl E {
    pub fn new(addr: EndpointAddr) -> Self {
        E(addr)
    }

    pub fn len(&self) -> usize {
        self.0.encoding_size()
    }

    pub fn endpoint(&self) -> EndpointAddr {
        self.0
    }
}

pub trait WriteE {
    fn put_e(&mut self, e: &E);
}

impl<B: BufMut> WriteE for B {
    fn put_e(&mut self, e: &E) {
        self.put_endpoint_addr(e.0)
    }
}

pub fn be_e(input: &[u8]) -> IResult<&[u8], E> {
    let (input, addr) = be_endpoint_addr(input, false, false)?;
    Ok((input, E(addr)))
}
