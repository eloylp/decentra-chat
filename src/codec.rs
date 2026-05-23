use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor, Read};
use thiserror::Error;

pub const TYPE_DISCOVERY_ANNOUNCE: u8 = 1;
pub const TYPE_KEY_EXCHANGE_REQ: u8 = 2;
pub const TYPE_KEY_EXCHANGE_RESP: u8 = 3;
pub const TYPE_CHAT_MESSAGE: u8 = 4;
pub const TYPE_MESSAGE_ACK: u8 = 5;

#[derive(Debug, PartialEq, Eq, Clone, Error)]
pub enum CodecError {
    #[error("unexpected end of DC wire message")]
    UnexpectedEof,
    #[error("unknown DC message type id {0}")]
    UnknownTypeId(u8),
}

impl From<io::Error> for CodecError {
    fn from(_: io::Error) -> Self {
        Self::UnexpectedEof
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct DiscoveryAnnounce {
    pub version: u8,
    pub address: [u8; 4],
    pub port: u16,
    pub nick: Vec<u8>,
    pub key_fingerprint: [u8; 32],
}

#[derive(Debug, PartialEq, Clone)]
pub struct KeyExchangeReq {
    pub version: u8,
}

#[derive(Debug, PartialEq, Clone)]
pub struct KeyExchangeResp {
    pub version: u8,
    pub key_data: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ChatMessage {
    pub version: u8,
    pub uuid: [u8; 16],
    pub conv_uuid: [u8; 16],
    pub conv_type: u8,
    pub prev_hash: [u8; 32],
    pub timestamp: u32,
    pub source: [u8; 32],
    pub destination: [u8; 32],
    pub headers: Vec<u8>,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct MessageAck {
    pub version: u8,
    pub uuid: [u8; 16],
    pub message_hash: [u8; 32],
    pub acknowledger: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum Message {
    DiscoveryAnnounce(DiscoveryAnnounce),
    KeyExchangeReq(KeyExchangeReq),
    KeyExchangeResp(KeyExchangeResp),
    ChatMessage(ChatMessage),
    MessageAck(MessageAck),
}

impl Message {
    /// Returns the stable user-facing name for this protocol message variant.
    pub fn name(&self) -> &'static str {
        match self {
            Self::DiscoveryAnnounce(_) => "discovery announce",
            Self::KeyExchangeReq(_) => "key-exchange request",
            Self::KeyExchangeResp(_) => "key-exchange response",
            Self::ChatMessage(_) => "chat message",
            Self::MessageAck(_) => "message ack",
        }
    }
}

impl TryFrom<&[u8]> for DiscoveryAnnounce {
    type Error = CodecError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let mut r = Cursor::new(buf);
        read_type_id(&mut r, TYPE_DISCOVERY_ANNOUNCE)?;

        let message = Self {
            version: r.read_u8()?,
            address: read_array(&mut r)?,
            port: r.read_u16::<BigEndian>()?,
            nick: read_vec_u8(&mut r)?,
            key_fingerprint: read_array(&mut r)?,
        };
        ensure_finished(&r)?;
        Ok(message)
    }
}

impl From<DiscoveryAnnounce> for Vec<u8> {
    fn from(message: DiscoveryAnnounce) -> Self {
        assert!(message.nick.len() <= u8::MAX as usize);

        let mut out = Vec::with_capacity(1 + 1 + 4 + 2 + 1 + message.nick.len() + 32);
        out.write_u8(TYPE_DISCOVERY_ANNOUNCE).unwrap();
        out.write_u8(message.version).unwrap();
        out.extend_from_slice(&message.address);
        out.write_u16::<BigEndian>(message.port).unwrap();
        out.write_u8(message.nick.len() as u8).unwrap();
        out.extend_from_slice(&message.nick);
        out.extend_from_slice(&message.key_fingerprint);
        out
    }
}

impl TryFrom<&[u8]> for KeyExchangeReq {
    type Error = CodecError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let mut r = Cursor::new(buf);
        read_type_id(&mut r, TYPE_KEY_EXCHANGE_REQ)?;

        let message = Self {
            version: r.read_u8()?,
        };
        ensure_finished(&r)?;
        Ok(message)
    }
}

impl From<KeyExchangeReq> for Vec<u8> {
    fn from(message: KeyExchangeReq) -> Self {
        let mut out = Vec::with_capacity(2);
        out.write_u8(TYPE_KEY_EXCHANGE_REQ).unwrap();
        out.write_u8(message.version).unwrap();
        out
    }
}

impl TryFrom<&[u8]> for KeyExchangeResp {
    type Error = CodecError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let mut r = Cursor::new(buf);
        read_type_id(&mut r, TYPE_KEY_EXCHANGE_RESP)?;

        let message = Self {
            version: r.read_u8()?,
            key_data: read_vec_u16(&mut r)?,
        };
        ensure_finished(&r)?;
        Ok(message)
    }
}

impl From<KeyExchangeResp> for Vec<u8> {
    fn from(message: KeyExchangeResp) -> Self {
        assert!(message.key_data.len() <= u16::MAX as usize);

        let mut out = Vec::with_capacity(1 + 1 + 2 + message.key_data.len());
        out.write_u8(TYPE_KEY_EXCHANGE_RESP).unwrap();
        out.write_u8(message.version).unwrap();
        out.write_u16::<BigEndian>(message.key_data.len() as u16)
            .unwrap();
        out.extend_from_slice(&message.key_data);
        out
    }
}

impl TryFrom<&[u8]> for ChatMessage {
    type Error = CodecError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let mut r = Cursor::new(buf);
        read_type_id(&mut r, TYPE_CHAT_MESSAGE)?;

        let message = Self {
            version: r.read_u8()?,
            uuid: read_array(&mut r)?,
            conv_uuid: read_array(&mut r)?,
            conv_type: r.read_u8()?,
            prev_hash: read_array(&mut r)?,
            timestamp: r.read_u32::<BigEndian>()?,
            source: read_array(&mut r)?,
            destination: read_array(&mut r)?,
            headers: read_vec_u16(&mut r)?,
            data: read_vec_u32(&mut r)?,
            signature: read_vec_u16(&mut r)?,
        };
        ensure_finished(&r)?;
        Ok(message)
    }
}

impl From<ChatMessage> for Vec<u8> {
    fn from(message: ChatMessage) -> Self {
        assert!(message.headers.len() <= u16::MAX as usize);
        assert!(message.data.len() <= u32::MAX as usize);
        assert!(message.signature.len() <= u16::MAX as usize);

        let mut out = Vec::with_capacity(
            1 + 1
                + 16
                + 16
                + 1
                + 32
                + 4
                + 32
                + 32
                + 2
                + message.headers.len()
                + 4
                + message.data.len()
                + 2
                + message.signature.len(),
        );
        out.write_u8(TYPE_CHAT_MESSAGE).unwrap();
        out.write_u8(message.version).unwrap();
        out.extend_from_slice(&message.uuid);
        out.extend_from_slice(&message.conv_uuid);
        out.write_u8(message.conv_type).unwrap();
        out.extend_from_slice(&message.prev_hash);
        out.write_u32::<BigEndian>(message.timestamp).unwrap();
        out.extend_from_slice(&message.source);
        out.extend_from_slice(&message.destination);
        out.write_u16::<BigEndian>(message.headers.len() as u16)
            .unwrap();
        out.extend_from_slice(&message.headers);
        out.write_u32::<BigEndian>(message.data.len() as u32)
            .unwrap();
        out.extend_from_slice(&message.data);
        out.write_u16::<BigEndian>(message.signature.len() as u16)
            .unwrap();
        out.extend_from_slice(&message.signature);
        out
    }
}

impl TryFrom<&[u8]> for MessageAck {
    type Error = CodecError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let mut r = Cursor::new(buf);
        read_type_id(&mut r, TYPE_MESSAGE_ACK)?;

        let message = Self {
            version: r.read_u8()?,
            uuid: read_array(&mut r)?,
            message_hash: read_array(&mut r)?,
            acknowledger: read_array(&mut r)?,
            signature: read_vec_u16(&mut r)?,
        };
        ensure_finished(&r)?;
        Ok(message)
    }
}

impl From<MessageAck> for Vec<u8> {
    fn from(message: MessageAck) -> Self {
        assert!(message.signature.len() <= u16::MAX as usize);

        let mut out = Vec::with_capacity(1 + 1 + 16 + 32 + 32 + 2 + message.signature.len());
        out.write_u8(TYPE_MESSAGE_ACK).unwrap();
        out.write_u8(message.version).unwrap();
        out.extend_from_slice(&message.uuid);
        out.extend_from_slice(&message.message_hash);
        out.extend_from_slice(&message.acknowledger);
        out.write_u16::<BigEndian>(message.signature.len() as u16)
            .unwrap();
        out.extend_from_slice(&message.signature);
        out
    }
}

impl TryFrom<&[u8]> for Message {
    type Error = CodecError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let type_id = *buf.first().ok_or(CodecError::UnexpectedEof)?;

        match type_id {
            TYPE_DISCOVERY_ANNOUNCE => {
                DiscoveryAnnounce::try_from(buf).map(Self::DiscoveryAnnounce)
            }
            TYPE_KEY_EXCHANGE_REQ => KeyExchangeReq::try_from(buf).map(Self::KeyExchangeReq),
            TYPE_KEY_EXCHANGE_RESP => KeyExchangeResp::try_from(buf).map(Self::KeyExchangeResp),
            TYPE_CHAT_MESSAGE => ChatMessage::try_from(buf).map(Self::ChatMessage),
            TYPE_MESSAGE_ACK => MessageAck::try_from(buf).map(Self::MessageAck),
            unknown => Err(CodecError::UnknownTypeId(unknown)),
        }
    }
}

impl From<Message> for Vec<u8> {
    fn from(message: Message) -> Self {
        match message {
            Message::DiscoveryAnnounce(message) => message.into(),
            Message::KeyExchangeReq(message) => message.into(),
            Message::KeyExchangeResp(message) => message.into(),
            Message::ChatMessage(message) => message.into(),
            Message::MessageAck(message) => message.into(),
        }
    }
}

fn read_array<const N: usize>(r: &mut impl Read) -> Result<[u8; N], CodecError> {
    let mut buf = [0; N];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_type_id(r: &mut Cursor<&[u8]>, expected: u8) -> Result<(), CodecError> {
    let actual = r.read_u8()?;
    if actual == expected {
        Ok(())
    } else {
        Err(CodecError::UnknownTypeId(actual))
    }
}

fn read_vec_u8(r: &mut Cursor<&[u8]>) -> Result<Vec<u8>, CodecError> {
    let len = r.read_u8()? as usize;
    read_vec(r, len)
}

fn read_vec_u16(r: &mut Cursor<&[u8]>) -> Result<Vec<u8>, CodecError> {
    let len = r.read_u16::<BigEndian>()? as usize;
    read_vec(r, len)
}

fn read_vec_u32(r: &mut Cursor<&[u8]>) -> Result<Vec<u8>, CodecError> {
    let len = r.read_u32::<BigEndian>()? as usize;
    read_vec(r, len)
}

fn read_vec(r: &mut Cursor<&[u8]>, len: usize) -> Result<Vec<u8>, CodecError> {
    if remaining(r)? < len {
        return Err(CodecError::UnexpectedEof);
    }

    let mut buf = vec![0; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn ensure_finished(r: &Cursor<&[u8]>) -> Result<(), CodecError> {
    if remaining(r)? == 0 {
        Ok(())
    } else {
        Err(CodecError::UnexpectedEof)
    }
}

fn remaining(r: &Cursor<&[u8]>) -> Result<usize, CodecError> {
    r.get_ref()
        .len()
        .checked_sub(r.position() as usize)
        .ok_or(CodecError::UnexpectedEof)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_16(seed: u8) -> [u8; 16] {
        [seed; 16]
    }

    fn bytes_32(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn message_names_are_stable() {
        let cases = [
            (
                Message::DiscoveryAnnounce(DiscoveryAnnounce {
                    version: 0,
                    address: [0; 4],
                    port: 0,
                    nick: Vec::new(),
                    key_fingerprint: [0; 32],
                }),
                "discovery announce",
            ),
            (
                Message::KeyExchangeReq(KeyExchangeReq { version: 0 }),
                "key-exchange request",
            ),
            (
                Message::KeyExchangeResp(KeyExchangeResp {
                    version: 0,
                    key_data: Vec::new(),
                }),
                "key-exchange response",
            ),
            (
                Message::ChatMessage(ChatMessage {
                    version: 0,
                    uuid: [0; 16],
                    conv_uuid: [0; 16],
                    conv_type: 0,
                    prev_hash: [0; 32],
                    timestamp: 0,
                    source: [0; 32],
                    destination: [0; 32],
                    headers: Vec::new(),
                    data: Vec::new(),
                    signature: Vec::new(),
                }),
                "chat message",
            ),
            (
                Message::MessageAck(MessageAck {
                    version: 0,
                    uuid: [0; 16],
                    message_hash: [0; 32],
                    acknowledger: [0; 32],
                    signature: Vec::new(),
                }),
                "message ack",
            ),
        ];

        for (message, expected_name) in cases {
            assert_eq!(message.name(), expected_name);
        }
    }

    #[test]
    fn codec_error_display_strings_are_stable() {
        let cases = [
            (
                CodecError::UnexpectedEof,
                "unexpected end of DC wire message",
            ),
            (
                CodecError::UnknownTypeId(0xff),
                "unknown DC message type id 255",
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn discovery_announce_round_trips() {
        let message = DiscoveryAnnounce {
            version: 1,
            address: [192, 168, 1, 44],
            port: 40091,
            nick: b"alice".to_vec(),
            key_fingerprint: bytes_32(0xaa),
        };

        let encoded: Vec<u8> = message.clone().into();

        assert_eq!(DiscoveryAnnounce::try_from(encoded.as_slice()), Ok(message));
    }

    #[test]
    fn key_exchange_req_round_trips() {
        let message = KeyExchangeReq { version: 2 };

        let encoded: Vec<u8> = message.clone().into();

        assert_eq!(encoded, vec![TYPE_KEY_EXCHANGE_REQ, 2]);
        assert_eq!(KeyExchangeReq::try_from(encoded.as_slice()), Ok(message));
    }

    #[test]
    fn key_exchange_resp_round_trips() {
        let message = KeyExchangeResp {
            version: 3,
            key_data: b"public key bytes".to_vec(),
        };

        let encoded: Vec<u8> = message.clone().into();

        assert_eq!(KeyExchangeResp::try_from(encoded.as_slice()), Ok(message));
    }

    #[test]
    fn chat_message_round_trips() {
        let message = ChatMessage {
            version: 4,
            uuid: bytes_16(0x10),
            conv_uuid: bytes_16(0x20),
            conv_type: 1,
            prev_hash: bytes_32(0x30),
            timestamp: 1_716_232_415,
            source: bytes_32(0x40),
            destination: bytes_32(0x50),
            headers: b"Content-Type: application/octet-stream".to_vec(),
            data: b"encrypted payload".to_vec(),
            signature: b"detached signature".to_vec(),
        };

        let encoded: Vec<u8> = message.clone().into();

        assert_eq!(ChatMessage::try_from(encoded.as_slice()), Ok(message));
    }

    #[test]
    fn message_ack_round_trips() {
        let message = MessageAck {
            version: 5,
            uuid: bytes_16(0x60),
            message_hash: bytes_32(0x70),
            acknowledger: bytes_32(0x80),
            signature: b"ack signature".to_vec(),
        };

        let encoded: Vec<u8> = message.clone().into();

        assert_eq!(MessageAck::try_from(encoded.as_slice()), Ok(message));
    }

    #[test]
    fn message_enum_round_trips() {
        let messages = [
            Message::DiscoveryAnnounce(DiscoveryAnnounce {
                version: 1,
                address: [10, 0, 0, 1],
                port: 40091,
                nick: b"bob".to_vec(),
                key_fingerprint: bytes_32(1),
            }),
            Message::KeyExchangeReq(KeyExchangeReq { version: 1 }),
            Message::KeyExchangeResp(KeyExchangeResp {
                version: 1,
                key_data: b"key".to_vec(),
            }),
            Message::ChatMessage(ChatMessage {
                version: 1,
                uuid: bytes_16(2),
                conv_uuid: bytes_16(3),
                conv_type: 2,
                prev_hash: bytes_32(4),
                timestamp: 42,
                source: bytes_32(5),
                destination: bytes_32(6),
                headers: b"h".to_vec(),
                data: b"d".to_vec(),
                signature: b"s".to_vec(),
            }),
            Message::MessageAck(MessageAck {
                version: 1,
                uuid: bytes_16(7),
                message_hash: bytes_32(8),
                acknowledger: bytes_32(9),
                signature: b"sig".to_vec(),
            }),
        ];

        for message in messages {
            let encoded: Vec<u8> = message.clone().into();
            assert_eq!(Message::try_from(encoded.as_slice()), Ok(message));
        }
    }

    #[test]
    fn discovery_announce_rejects_empty_input() {
        assert_eq!(
            DiscoveryAnnounce::try_from(&[][..]),
            Err(CodecError::UnexpectedEof)
        );
    }

    #[test]
    fn discovery_announce_rejects_unknown_type_id() {
        assert_eq!(
            DiscoveryAnnounce::try_from(&[0xff][..]),
            Err(CodecError::UnknownTypeId(0xff))
        );
    }
}
