use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use bytes::BufMut;
use nom::{
    IResult, Parser,
    bytes::streaming::take,
    combinator::{flat_map, map},
    error::{ErrorKind, make_error},
    number::streaming::{be_u8, be_u16, be_u32, be_u128},
};
use rustls::{SignatureScheme, pki_types::SubjectPublicKeyInfoDer, sign::SigningKey};

use crate::parser::{
    sigin,
    varint::{VarInt, WriteVarInt, be_varint},
};

/// EndpointAddress record
///
/// - E: IPv4 Direct address
/// - EE: IPv4 Relay address
/// - E6: IPv6 Direct address
/// - EE6: IPv6 Relay address
///
/// ## RDATA 线协议格式
///
/// 直连（E / E6）：
///
/// - IPv4：`port(u16, BE)` + `ipv4(u32, BE)`，总长 6 字节
/// - IPv6：`port(u16, BE)` + `ipv6(u128, BE)`，总长 18 字节
///
/// 中继（EE / EE6）：
///
/// - 先 outer，再 agent，各自都是一个 socket_addr
/// - IPv4：`outer(6)` + `agent(6)`，总长 12 字节
/// - IPv6：`outer(18)` + `agent(18)`，总长 36 字节
///
/// ### 包格式
///
/// ```text
/// +--------+-----------------+--------------------+----------------------------+
/// | flags  | sequence(varint)| addr(s)            | signature (optional)       |
/// +--------+-----------------+--------------------+----------------------------+
/// | u8     | QUIC varint     | v4: 2+4 / v6: 2+16 | scheme(u16)+len(varint)+N  |
/// +--------+-----------------+--------------------+----------------------------+
/// ```
///
/// - `flags`：bit7 为 `MAIN`，bit6 为 `SIGNED`（见 `EndpointAddr::FLAG_*`）
/// - `sequence`：DNS 记录编号，同一编号的记录视为一个机器，可以使用多路径连接（ `VarInt`）
/// - `addr(s)`：直连为 1 个地址；中继为 2 个地址（outer + agent）
/// - `signature`：当 `SIGNED` 置位时，允许附加签名字段；
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointMeta {
    flags: u8,
    sequence: VarInt,
    signature: Option<EndpointSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointSignature {
    scheme: u16,
    signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EndpointAddr {
    /// IPv4 直连地址：`addr`
    E {
        meta: EndpointMeta,
        addr: SocketAddrV4,
    },
    /// IPv4 中继地址：`outer` 为外部地址，`agent` 为中继代理地址
    EE {
        meta: EndpointMeta,
        outer: SocketAddrV4,
        agent: SocketAddrV4,
    },
    /// IPv6 直连地址：`addr`
    E6 {
        meta: EndpointMeta,
        addr: SocketAddrV6,
    },
    /// IPv6 中继地址：`outer` 为外部地址，`agent` 为中继代理地址
    EE6 {
        meta: EndpointMeta,
        outer: SocketAddrV6,
        agent: SocketAddrV6,
    },
}

impl EndpointAddr {
    const FLAG_MAIN: u8 = 0b1000_0000;
    const FLAG_SIGNED: u8 = 0b0100_0000;

    pub fn direct_v4(addr: SocketAddrV4) -> Self {
        Self::E {
            meta: EndpointMeta {
                flags: 0,
                sequence: VarInt::from_u32(0),
                signature: None,
            },
            addr,
        }
    }

    pub fn direct_v6(addr: SocketAddrV6) -> Self {
        Self::E6 {
            meta: EndpointMeta {
                flags: 0,
                sequence: VarInt::from_u32(0),
                signature: None,
            },
            addr,
        }
    }

    pub fn relay_v4(outer: SocketAddrV4, agent: SocketAddrV4) -> Self {
        Self::EE {
            meta: EndpointMeta {
                flags: 0,
                sequence: VarInt::from_u32(0),
                signature: None,
            },
            outer,
            agent,
        }
    }

    pub fn relay_v6(outer: SocketAddrV6, agent: SocketAddrV6) -> Self {
        Self::EE6 {
            meta: EndpointMeta {
                flags: 0,
                sequence: VarInt::from_u32(0),
                signature: None,
            },
            outer,
            agent,
        }
    }

    pub fn sign_with(
        &mut self,
        key: &(impl SigningKey + ?Sized),
        scheme: SignatureScheme,
    ) -> Result<(), sigin::SignError> {
        self.set_signed(true);
        let data = self.signed_data();
        let signature = sigin::sign(key, scheme, &data)?;
        *self.signature_mut() = Some(EndpointSignature {
            scheme: u16::from(scheme),
            signature,
        });
        Ok(())
    }

    pub fn verify_signature(
        &self,
        spki: SubjectPublicKeyInfoDer<'_>,
    ) -> Result<bool, sigin::VerifyError> {
        let Some(sig) = self.signature() else {
            return Ok(false);
        };
        let data = self.signed_data();
        sigin::verify(
            spki,
            SignatureScheme::from(sig.scheme),
            &data,
            &sig.signature,
        )
    }

    pub fn is_main(&self) -> bool {
        self.flags() & Self::FLAG_MAIN == Self::FLAG_MAIN
    }

    pub fn set_main(&mut self, is_main: bool) {
        let flags = self.flags_mut();
        if is_main {
            *flags |= Self::FLAG_MAIN;
        } else {
            *flags &= !Self::FLAG_MAIN;
        }
    }

    pub fn is_signed(&self) -> bool {
        self.flags() & Self::FLAG_SIGNED == Self::FLAG_SIGNED
    }

    pub fn set_signed(&mut self, is_signed: bool) {
        let flags = self.flags_mut();
        if is_signed {
            *flags |= Self::FLAG_SIGNED;
        } else {
            *flags &= !Self::FLAG_SIGNED;
        }
    }

    pub fn encpding_size(&self) -> usize {
        let mut meta_len = 1 + self.sequence().encoding_size();
        if self.is_signed()
            && let Some(sig) = self.signature()
        {
            let sig_len =
                VarInt::try_from(sig.signature.len() as u64).unwrap_or(VarInt::from_u32(0));
            meta_len += 2 + sig_len.encoding_size() + sig.signature.len();
        }

        match self {
            EndpointAddr::E { .. } => meta_len + 2 + 4,
            EndpointAddr::EE { .. } => meta_len + 2 + 4 + 2 + 4,
            EndpointAddr::E6 { .. } => meta_len + 2 + 16,
            EndpointAddr::EE6 { .. } => meta_len + 2 + 16 + 2 + 16,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        match self {
            EndpointAddr::E { addr, .. } => (*addr).into(),
            EndpointAddr::EE { outer, .. } => (*outer).into(),
            EndpointAddr::E6 { addr, .. } => (*addr).into(),
            EndpointAddr::EE6 { outer, .. } => (*outer).into(),
        }
    }

    pub fn set_sequence(&mut self, sequence: u64) {
        self.meta_mut().sequence = VarInt::from_u64(sequence).expect("Sequence too large");
    }

    fn meta(&self) -> &EndpointMeta {
        match self {
            EndpointAddr::E { meta, .. } => meta,
            EndpointAddr::EE { meta, .. } => meta,
            EndpointAddr::E6 { meta, .. } => meta,
            EndpointAddr::EE6 { meta, .. } => meta,
        }
    }

    fn meta_mut(&mut self) -> &mut EndpointMeta {
        match self {
            EndpointAddr::E { meta, .. } => meta,
            EndpointAddr::EE { meta, .. } => meta,
            EndpointAddr::E6 { meta, .. } => meta,
            EndpointAddr::EE6 { meta, .. } => meta,
        }
    }

    fn flags(&self) -> u8 {
        self.meta().flags
    }

    fn flags_mut(&mut self) -> &mut u8 {
        &mut self.meta_mut().flags
    }

    fn sequence(&self) -> VarInt {
        self.meta().sequence
    }

    fn signature(&self) -> Option<&EndpointSignature> {
        self.meta().signature.as_ref()
    }

    fn signature_mut(&mut self) -> &mut Option<EndpointSignature> {
        &mut self.meta_mut().signature
    }

    fn write_base<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.flags());
        buf.put_varint(self.sequence());
        match self {
            EndpointAddr::E { addr, .. } => buf.put_socket_addr_v4(addr),
            EndpointAddr::EE { outer, agent, .. } => {
                buf.put_socket_addr_v4(outer);
                buf.put_socket_addr_v4(agent);
            }
            EndpointAddr::E6 { addr, .. } => buf.put_socket_addr_v6(addr),
            EndpointAddr::EE6 { outer, agent, .. } => {
                buf.put_socket_addr_v6(outer);
                buf.put_socket_addr_v6(agent);
            }
        }
    }

    fn signed_data(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.set_signed(true);
        *unsigned.signature_mut() = None;
        let mut buf = bytes::BytesMut::with_capacity(unsigned.encpding_size());
        unsigned.write_base(&mut buf);
        buf.to_vec()
    }
}

pub(crate) trait WriteEndpointAddr {
    fn put_endpoint_addr(&mut self, endpoint: &EndpointAddr);
}

impl<B: BufMut> WriteEndpointAddr for B {
    fn put_endpoint_addr(&mut self, endpoint: &EndpointAddr) {
        endpoint.write_base(self);
        if endpoint.is_signed()
            && let Some(sig) = endpoint.signature()
        {
            self.put_u16(sig.scheme);
            let len = VarInt::try_from(sig.signature.len() as u64).unwrap_or(VarInt::from_u32(0));
            self.put_varint(len);
            self.put_slice(&sig.signature);
        }
    }
}

pub fn be_endpoint_addr(
    input: &[u8],
    is_relay: bool,
    is_ipv6: bool,
) -> nom::IResult<&[u8], EndpointAddr> {
    let (remain, flags) = be_u8(input)?;
    let (remain, sequence) = be_varint(remain)?;
    match (is_relay, is_ipv6) {
        (true, true) => {
            let (remain, outer) = be_socket_addr_v6(remain)?;
            let (remain, agent) = be_socket_addr_v6(remain)?;
            let (remain, meta) = be_endpoint_meta(remain, flags, sequence)?;
            Ok((remain, EndpointAddr::EE6 { meta, outer, agent }))
        }
        (true, false) => {
            let (remain, outer) = be_socket_addr_v4(remain)?;
            let (remain, agent) = be_socket_addr_v4(remain)?;
            let (remain, meta) = be_endpoint_meta(remain, flags, sequence)?;
            Ok((remain, EndpointAddr::EE { meta, outer, agent }))
        }
        (false, true) => {
            let (remain, addr) = be_socket_addr_v6(remain)?;
            let (remain, meta) = be_endpoint_meta(remain, flags, sequence)?;
            Ok((remain, EndpointAddr::E6 { meta, addr }))
        }
        (false, false) => {
            let (remain, addr) = be_socket_addr_v4(remain)?;
            let (remain, meta) = be_endpoint_meta(remain, flags, sequence)?;
            Ok((remain, EndpointAddr::E { meta, addr }))
        }
    }
}

/// 兼容解析 EndpointAddr：
///
/// - 当 `rdlen` 匹配 Legacy 的固定长度时，按地址-only 解析，并补全默认 `EndpointMeta`
/// - 否则按 Modern v0（带 `flags` + `sequence`）解析
///
/// 注意：
/// - Legacy 与 Modern 的开头字节序列不同，不能通过窥探 `flags` 来可靠区分
/// - 这里依赖 `RDLENGTH` 的长度判别，避免把端口高字节误当成 `flags`
pub(crate) fn be_endpoint_addr_compat(
    input: &[u8],
    is_relay: bool,
    is_ipv6: bool,
    rdlen: u16,
) -> nom::IResult<&[u8], EndpointAddr> {
    let legacy_len = match (is_relay, is_ipv6) {
        (false, false) => 2 + 4,
        (true, false) => (2 + 4) * 2,
        (false, true) => 2 + 16,
        (true, true) => (2 + 16) * 2,
    };

    if rdlen as usize == legacy_len {
        let meta = EndpointMeta {
            flags: 0,
            sequence: VarInt::from_u32(0),
            signature: None,
        };
        return match (is_relay, is_ipv6) {
            (true, true) => {
                let (remain, outer) = be_socket_addr_v6(input)?;
                let (remain, agent) = be_socket_addr_v6(remain)?;
                Ok((remain, EndpointAddr::EE6 { meta, outer, agent }))
            }
            (true, false) => {
                let (remain, outer) = be_socket_addr_v4(input)?;
                let (remain, agent) = be_socket_addr_v4(remain)?;
                Ok((remain, EndpointAddr::EE { meta, outer, agent }))
            }
            (false, true) => {
                let (remain, addr) = be_socket_addr_v6(input)?;
                Ok((remain, EndpointAddr::E6 { meta, addr }))
            }
            (false, false) => {
                let (remain, addr) = be_socket_addr_v4(input)?;
                Ok((remain, EndpointAddr::E { meta, addr }))
            }
        };
    }

    be_endpoint_addr(input, is_relay, is_ipv6)
}

fn be_endpoint_meta(input: &[u8], flags: u8, sequence: VarInt) -> IResult<&[u8], EndpointMeta> {
    if (flags & EndpointAddr::FLAG_SIGNED) != EndpointAddr::FLAG_SIGNED {
        if !input.is_empty() {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
        }
        return Ok((
            input,
            EndpointMeta {
                flags,
                sequence,
                signature: None,
            },
        ));
    }

    if input.is_empty() {
        return Ok((
            input,
            EndpointMeta {
                flags,
                sequence,
                signature: None,
            },
        ));
    }

    let (remain, scheme_u16) = be_u16(input)?;
    let (remain, sig_len) = be_varint(remain)?;
    let sig_len = usize::try_from(sig_len.into_inner())
        .map_err(|_| nom::Err::Error(make_error(remain, ErrorKind::TooLarge)))?;
    let (remain, sig) = take(sig_len)(remain)?;
    Ok((
        remain,
        EndpointMeta {
            flags,
            sequence,
            signature: Some(EndpointSignature {
                scheme: scheme_u16,
                signature: sig.to_vec(),
            }),
        },
    ))
}

pub trait WriteSocketAddr {
    fn put_socket_addr_v4(&mut self, addr: &SocketAddrV4);

    fn put_socket_addr_v6(&mut self, addr: &SocketAddrV6);

    fn put_socket_addr(&mut self, addr: &SocketAddr) {
        match addr {
            SocketAddr::V4(v4) => self.put_socket_addr_v4(v4),
            SocketAddr::V6(v6) => self.put_socket_addr_v6(v6),
        }
    }
}

impl<T: BufMut> WriteSocketAddr for T {
    fn put_socket_addr_v4(&mut self, addr: &SocketAddrV4) {
        self.put_u16(addr.port());
        self.put_u32(u32::from(*addr.ip()));
    }

    fn put_socket_addr_v6(&mut self, addr: &SocketAddrV6) {
        self.put_u16(addr.port());
        self.put_u128(u128::from(*addr.ip()));
    }
}

pub fn be_socket_addr_v4(input: &[u8]) -> IResult<&[u8], SocketAddrV4> {
    flat_map(be_u16, |port| {
        map(be_ipv4_addr, move |ip| SocketAddrV4::new(ip, port))
    })
    .parse(input)
}

pub fn be_socket_addr_v6(input: &[u8]) -> IResult<&[u8], SocketAddrV6> {
    flat_map(be_u16, |port| {
        map(be_ipv6_addr, move |ip| SocketAddrV6::new(ip, port, 0, 0))
    })
    .parse(input)
}

pub fn be_ipv4_addr(input: &[u8]) -> IResult<&[u8], Ipv4Addr> {
    map(be_u32, Ipv4Addr::from).parse(input)
}

pub fn be_ipv6_addr(input: &[u8]) -> IResult<&[u8], Ipv6Addr> {
    map(be_u128, Ipv6Addr::from).parse(input)
}

pub fn be_ip_addr(is_v6: bool) -> impl Fn(&[u8]) -> IResult<&[u8], IpAddr> {
    move |input| match is_v6 {
        true => map(be_u128, |ip| IpAddr::V6(Ipv6Addr::from(ip))).parse(input),
        false => map(be_u32, |ip| IpAddr::V4(Ipv4Addr::from(ip))).parse(input),
    }
}

impl Display for EndpointAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EndpointAddr::E { addr, .. } => write!(f, "{addr}"),
            EndpointAddr::EE { outer, agent, .. } => write!(f, "{outer}-{agent}"),
            EndpointAddr::E6 { addr, .. } => write!(f, "{addr}"),
            EndpointAddr::EE6 { outer, agent, .. } => write!(f, "{outer}-{agent}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };

    use bytes::BytesMut;
    use ring::signature::KeyPair;
    use rustls::sign::Signer;

    use super::*;

    #[test]
    fn legacy_endpoint_v4_direct_without_meta() {
        let port = 5353u16;
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&port.to_be_bytes());
        buf.extend_from_slice(&u32::from(ip).to_be_bytes());
        let (remain, decoded) = be_endpoint_addr_compat(&buf, false, false, 6).unwrap();
        assert!(remain.is_empty());
        assert_eq!(
            decoded,
            EndpointAddr::direct_v4(SocketAddrV4::new(ip, port))
        );
    }

    #[test]
    fn legacy_endpoint_v4_relay_without_meta() {
        let outer = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1000);
        let agent = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 2000);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&outer.port().to_be_bytes());
        buf.extend_from_slice(&u32::from(*outer.ip()).to_be_bytes());
        buf.extend_from_slice(&agent.port().to_be_bytes());
        buf.extend_from_slice(&u32::from(*agent.ip()).to_be_bytes());
        let (remain, decoded) = be_endpoint_addr_compat(&buf, true, false, 12).unwrap();
        assert!(remain.is_empty());
        assert_eq!(decoded, EndpointAddr::relay_v4(outer, agent));
    }

    #[test]
    fn flag_bit_ops_work() {
        let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 5353);
        let mut ep = EndpointAddr::E {
            meta: EndpointMeta {
                flags: 0b0011_1111,
                sequence: VarInt::from_u32(0),
                signature: None,
            },
            addr,
        };

        assert!(!ep.is_main());
        assert!(!ep.is_signed());

        ep.set_main(true);
        assert!(ep.is_main());
        assert_eq!(ep.meta().flags, 0b1011_1111);

        ep.set_signed(true);
        assert!(ep.is_signed());
        assert_eq!(ep.meta().flags, 0b1111_1111);

        ep.set_main(false);
        assert!(!ep.is_main());
        assert!(ep.is_signed());
        assert_eq!(ep.meta().flags, 0b0111_1111);

        ep.set_signed(false);
        assert!(!ep.is_signed());
        assert_eq!(ep.meta().flags, 0b0011_1111);
    }

    #[test]
    fn varint_roundtrip_and_len() {
        fn roundtrip(v: u64) {
            let v = VarInt::from_u64(v).unwrap();
            let mut buf = BytesMut::new();
            buf.put_varint(v);
            assert_eq!(buf.len(), v.encoding_size());
            let (remain, decoded) = be_varint(&buf).unwrap();
            assert!(remain.is_empty());
            assert_eq!(decoded, v);
        }

        for v in [
            0u64,
            1,
            63,
            64,
            16383,
            16384,
            (1 << 30) - 1,
            1 << 30,
            (1 << 62) - 1,
        ] {
            roundtrip(v);
        }
    }

    #[test]
    fn varint_rejects_overflow_and_incomplete() {
        assert!(VarInt::from_u64((1 << 62) + 1).is_err());

        let incomplete = [0b01_000000u8];
        match be_varint(&incomplete) {
            Err(nom::Err::Incomplete(_)) => {}
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }

    #[test]
    fn endpoint_encode_decode_roundtrip() {
        let v4_outer = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1000);
        let v4_agent = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 2000);
        let v6_outer = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3000, 0, 0);
        let v6_agent = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 4000, 0, 0);

        let cases = [
            (
                EndpointAddr::E {
                    meta: EndpointMeta {
                        flags: 0b1100_0000,
                        sequence: VarInt::from_u32(0),
                        signature: None,
                    },
                    addr: v4_outer,
                },
                false,
                false,
            ),
            (
                EndpointAddr::EE {
                    meta: EndpointMeta {
                        flags: 0b0100_0000,
                        sequence: VarInt::from_u32(127),
                        signature: None,
                    },
                    outer: v4_outer,
                    agent: v4_agent,
                },
                true,
                false,
            ),
            (
                EndpointAddr::E6 {
                    meta: EndpointMeta {
                        flags: 0b1000_0000,
                        sequence: VarInt::from_u32(128),
                        signature: None,
                    },
                    addr: v6_outer,
                },
                false,
                true,
            ),
            (
                EndpointAddr::EE6 {
                    meta: EndpointMeta {
                        flags: 0,
                        sequence: VarInt::from_u64((1 << 62) - 1).unwrap(),
                        signature: None,
                    },
                    outer: v6_outer,
                    agent: v6_agent,
                },
                true,
                true,
            ),
        ];

        for (ep, is_relay, is_ipv6) in cases {
            let mut buf = BytesMut::new();
            buf.put_endpoint_addr(&ep);
            assert_eq!(buf.len(), ep.encpding_size());

            let (remain, decoded) = be_endpoint_addr(&buf, is_relay, is_ipv6).unwrap();
            assert!(remain.is_empty());
            assert_eq!(decoded, ep);
        }
    }

    #[test]
    fn endpoint_signature_roundtrip_and_verify() {
        #[derive(Debug)]
        struct Ed25519Key(Arc<ring::signature::Ed25519KeyPair>);

        #[derive(Debug)]
        struct Ed25519Signer(Arc<ring::signature::Ed25519KeyPair>);

        impl Signer for Ed25519Signer {
            fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
                Ok(self.0.sign(message).as_ref().to_vec())
            }

            fn scheme(&self) -> SignatureScheme {
                SignatureScheme::ED25519
            }
        }

        impl SigningKey for Ed25519Key {
            fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
                offered
                    .contains(&SignatureScheme::ED25519)
                    .then(|| Box::new(Ed25519Signer(self.0.clone())) as Box<dyn Signer>)
            }

            fn algorithm(&self) -> rustls::SignatureAlgorithm {
                rustls::SignatureAlgorithm::ED25519
            }
        }

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair =
            Arc::new(ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap());
        let key = Ed25519Key(keypair.clone());

        let mut spki = Vec::with_capacity(44);
        spki.extend_from_slice(&[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ]);
        spki.extend_from_slice(keypair.public_key().as_ref());

        let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5353);
        let mut ep = EndpointAddr::direct_v4(addr);
        ep.set_main(true);
        ep.sign_with(&key, SignatureScheme::ED25519).unwrap();

        let mut buf = BytesMut::new();
        buf.put_endpoint_addr(&ep);
        assert_eq!(buf.len(), ep.encpding_size());

        let (remain, decoded) = be_endpoint_addr(&buf, false, false).unwrap();
        assert!(remain.is_empty());
        assert!(decoded.is_signed());
        assert!(decoded.signature().is_some());
        assert!(
            decoded
                .verify_signature(SubjectPublicKeyInfoDer::from(spki.as_slice()))
                .unwrap()
        );

        let mut tampered = decoded.clone();
        tampered.set_main(false);
        assert!(
            !tampered
                .verify_signature(SubjectPublicKeyInfoDer::from(spki.as_slice()))
                .unwrap()
        );
    }
}
