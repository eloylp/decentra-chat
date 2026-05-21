use std::fmt;
use std::net::Ipv4Addr;

pub const CURRENT_VERSION: u8 = 1;

pub type UuidBytes = [u8; 16];
pub type HashBytes = [u8; 32];
pub type Fingerprint = HashBytes;

const TYPE_DISCOVERY_ANNOUNCE: u8 = 1;
const TYPE_KEY_EXCHANGE_REQ: u8 = 2;
const TYPE_KEY_EXCHANGE_RESP: u8 = 3;
const TYPE_CHAT_MESSAGE: u8 = 4;
const TYPE_MESSAGE_ACK: u8 = 5;

/// Error returned when DC wire bytes cannot be encoded or decoded safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    EmptyInput,
    Truncated {
        field: &'static str,
        expected_at_least: usize,
        actual: usize,
    },
    TrailingData {
        trailing_bytes: usize,
    },
    WrongType {
        expected: u8,
        actual: u8,
    },
    UnknownType(u8),
    UnsupportedVersion(u8),
    FieldTooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "input is empty; expected a DC message type byte"),
            Self::Truncated {
                field,
                expected_at_least,
                actual,
            } => write!(
                f,
                "input is truncated while reading {field}; expected at least {expected_at_least} bytes, got {actual}"
            ),
            Self::TrailingData { trailing_bytes } => {
                write!(f, "message has {trailing_bytes} unexpected trailing byte(s)")
            }
            Self::WrongType { expected, actual } => {
                write!(f, "wrong message type: expected {expected}, got {actual}")
            }
            Self::UnknownType(message_type) => {
                write!(f, "unknown message type {message_type}")
            }
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported message version {version}")
            }
            Self::FieldTooLong { field, max, actual } => write!(
                f,
                "{field} is too long for the wire format; max {max} bytes, got {actual}"
            ),
        }
    }
}

impl std::error::Error for CodecError {}

/// Type-1 UDP multicast peer discovery announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryAnnounce {
    pub version: u8,
    pub address: Ipv4Addr,
    pub port: u16,
    pub nick: Vec<u8>,
    pub key_fingerprint: Fingerprint,
}

/// Type-2 TCP request for a peer's public key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyExchangeReq {
    pub version: u8,
}

/// Type-3 TCP response containing PEM-encoded public key bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyExchangeResp {
    pub version: u8,
    pub key_data: Vec<u8>,
}

/// Type-4 TCP chat message with opaque encrypted payload and signature bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    pub version: u8,
    pub uuid: UuidBytes,
    pub conv_uuid: UuidBytes,
    pub conv_type: u8,
    pub prev_hash: HashBytes,
    pub timestamp: u32,
    pub source: Fingerprint,
    pub destination: Fingerprint,
    pub headers: Vec<u8>,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Type-5 TCP acknowledgement for a verified chat message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageAck {
    pub version: u8,
    pub uuid: UuidBytes,
    pub message_hash: HashBytes,
    pub acknowledger: Fingerprint,
    pub signature: Vec<u8>,
}

/// Any known DecentraChat wire message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    DiscoveryAnnounce(DiscoveryAnnounce),
    KeyExchangeReq(KeyExchangeReq),
    KeyExchangeResp(KeyExchangeResp),
    ChatMessage(ChatMessage),
    MessageAck(MessageAck),
}

impl DiscoveryAnnounce {
    pub fn to_bytes(&self) -> Result<Vec<u8>, CodecError> {
        ensure_version(self.version)?;
        ensure_u8_len("nick", self.nick.len())?;

        let mut bytes = Vec::with_capacity(2 + 4 + 2 + 1 + self.nick.len() + 32);
        bytes.push(TYPE_DISCOVERY_ANNOUNCE);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.address.octets());
        bytes.extend_from_slice(&self.port.to_be_bytes());
        bytes.push(self.nick.len() as u8);
        bytes.extend_from_slice(&self.nick);
        bytes.extend_from_slice(&self.key_fingerprint);
        Ok(bytes)
    }

    pub fn from_bytes(input: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(input);
        reader.expect_type(TYPE_DISCOVERY_ANNOUNCE)?;
        let version = reader.version()?;
        let address = Ipv4Addr::from(reader.array::<4>("address")?);
        let port = reader.u16("port")?;
        let nick_len = reader.u8("nick len")? as usize;
        let nick = reader.bytes("nick", nick_len)?.to_vec();
        let key_fingerprint = reader.array::<32>("key fingerprint")?;
        reader.finish()?;

        Ok(Self {
            version,
            address,
            port,
            nick,
            key_fingerprint,
        })
    }
}

impl KeyExchangeReq {
    pub fn to_bytes(&self) -> Result<Vec<u8>, CodecError> {
        ensure_version(self.version)?;
        Ok(vec![TYPE_KEY_EXCHANGE_REQ, self.version])
    }

    pub fn from_bytes(input: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(input);
        reader.expect_type(TYPE_KEY_EXCHANGE_REQ)?;
        let version = reader.version()?;
        reader.finish()?;
        Ok(Self { version })
    }
}

impl KeyExchangeResp {
    pub fn to_bytes(&self) -> Result<Vec<u8>, CodecError> {
        ensure_version(self.version)?;
        ensure_u16_len("key data", self.key_data.len())?;

        let mut bytes = Vec::with_capacity(2 + 2 + self.key_data.len());
        bytes.push(TYPE_KEY_EXCHANGE_RESP);
        bytes.push(self.version);
        bytes.extend_from_slice(&(self.key_data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.key_data);
        Ok(bytes)
    }

    pub fn from_bytes(input: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(input);
        reader.expect_type(TYPE_KEY_EXCHANGE_RESP)?;
        let version = reader.version()?;
        let key_len = reader.u16("key len")? as usize;
        let key_data = reader.bytes("key data", key_len)?.to_vec();
        reader.finish()?;
        Ok(Self { version, key_data })
    }
}

impl ChatMessage {
    pub fn to_bytes(&self) -> Result<Vec<u8>, CodecError> {
        ensure_version(self.version)?;
        ensure_u16_len("headers", self.headers.len())?;
        ensure_u32_len("data", self.data.len())?;
        ensure_u16_len("signature", self.signature.len())?;

        let mut bytes = Vec::with_capacity(
            2 + 16
                + 16
                + 1
                + 32
                + 4
                + 32
                + 32
                + 2
                + self.headers.len()
                + 4
                + self.data.len()
                + 2
                + self.signature.len(),
        );
        bytes.push(TYPE_CHAT_MESSAGE);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.uuid);
        bytes.extend_from_slice(&self.conv_uuid);
        bytes.push(self.conv_type);
        bytes.extend_from_slice(&self.prev_hash);
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.source);
        bytes.extend_from_slice(&self.destination);
        bytes.extend_from_slice(&(self.headers.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.headers);
        bytes.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }

    pub fn from_bytes(input: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(input);
        reader.expect_type(TYPE_CHAT_MESSAGE)?;
        let version = reader.version()?;
        let uuid = reader.array::<16>("uuid")?;
        let conv_uuid = reader.array::<16>("conv uuid")?;
        let conv_type = reader.u8("conv type")?;
        let prev_hash = reader.array::<32>("prev hash")?;
        let timestamp = reader.u32("timestamp")?;
        let source = reader.array::<32>("source")?;
        let destination = reader.array::<32>("destination")?;
        let headers_len = reader.u16("headers len")? as usize;
        let headers = reader.bytes("headers", headers_len)?.to_vec();
        let data_len = reader.u32("data len")? as usize;
        let data = reader.bytes("data", data_len)?.to_vec();
        let signature_len = reader.u16("signature len")? as usize;
        let signature = reader.bytes("signature", signature_len)?.to_vec();
        reader.finish()?;

        Ok(Self {
            version,
            uuid,
            conv_uuid,
            conv_type,
            prev_hash,
            timestamp,
            source,
            destination,
            headers,
            data,
            signature,
        })
    }
}

impl MessageAck {
    pub fn to_bytes(&self) -> Result<Vec<u8>, CodecError> {
        ensure_version(self.version)?;
        ensure_u16_len("signature", self.signature.len())?;

        let mut bytes = Vec::with_capacity(2 + 16 + 32 + 32 + 2 + self.signature.len());
        bytes.push(TYPE_MESSAGE_ACK);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.uuid);
        bytes.extend_from_slice(&self.message_hash);
        bytes.extend_from_slice(&self.acknowledger);
        bytes.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }

    pub fn from_bytes(input: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(input);
        reader.expect_type(TYPE_MESSAGE_ACK)?;
        let version = reader.version()?;
        let uuid = reader.array::<16>("uuid")?;
        let message_hash = reader.array::<32>("message hash")?;
        let acknowledger = reader.array::<32>("acknowledger")?;
        let signature_len = reader.u16("signature len")? as usize;
        let signature = reader.bytes("signature", signature_len)?.to_vec();
        reader.finish()?;

        Ok(Self {
            version,
            uuid,
            message_hash,
            acknowledger,
            signature,
        })
    }
}

impl Message {
    pub fn to_bytes(&self) -> Result<Vec<u8>, CodecError> {
        match self {
            Self::DiscoveryAnnounce(message) => message.to_bytes(),
            Self::KeyExchangeReq(message) => message.to_bytes(),
            Self::KeyExchangeResp(message) => message.to_bytes(),
            Self::ChatMessage(message) => message.to_bytes(),
            Self::MessageAck(message) => message.to_bytes(),
        }
    }

    pub fn from_bytes(input: &[u8]) -> Result<Self, CodecError> {
        let message_type = input.first().copied().ok_or(CodecError::EmptyInput)?;

        match message_type {
            TYPE_DISCOVERY_ANNOUNCE => {
                DiscoveryAnnounce::from_bytes(input).map(Self::DiscoveryAnnounce)
            }
            TYPE_KEY_EXCHANGE_REQ => KeyExchangeReq::from_bytes(input).map(Self::KeyExchangeReq),
            TYPE_KEY_EXCHANGE_RESP => {
                KeyExchangeResp::from_bytes(input).map(Self::KeyExchangeResp)
            }
            TYPE_CHAT_MESSAGE => ChatMessage::from_bytes(input).map(Self::ChatMessage),
            TYPE_MESSAGE_ACK => MessageAck::from_bytes(input).map(Self::MessageAck),
            unknown => Err(CodecError::UnknownType(unknown)),
        }
    }
}

impl From<DiscoveryAnnounce> for Message {
    fn from(message: DiscoveryAnnounce) -> Self {
        Self::DiscoveryAnnounce(message)
    }
}

impl From<KeyExchangeReq> for Message {
    fn from(message: KeyExchangeReq) -> Self {
        Self::KeyExchangeReq(message)
    }
}

impl From<KeyExchangeResp> for Message {
    fn from(message: KeyExchangeResp) -> Self {
        Self::KeyExchangeResp(message)
    }
}

impl From<ChatMessage> for Message {
    fn from(message: ChatMessage) -> Self {
        Self::ChatMessage(message)
    }
}

impl From<MessageAck> for Message {
    fn from(message: MessageAck) -> Self {
        Self::MessageAck(message)
    }
}

fn ensure_u8_len(field: &'static str, len: usize) -> Result<(), CodecError> {
    if len > u8::MAX as usize {
        Err(CodecError::FieldTooLong {
            field,
            max: u8::MAX as usize,
            actual: len,
        })
    } else {
        Ok(())
    }
}

fn ensure_version(version: u8) -> Result<(), CodecError> {
    if version == CURRENT_VERSION {
        Ok(())
    } else {
        Err(CodecError::UnsupportedVersion(version))
    }
}

fn ensure_u16_len(field: &'static str, len: usize) -> Result<(), CodecError> {
    if len > u16::MAX as usize {
        Err(CodecError::FieldTooLong {
            field,
            max: u16::MAX as usize,
            actual: len,
        })
    } else {
        Ok(())
    }
}

fn ensure_u32_len(field: &'static str, len: usize) -> Result<(), CodecError> {
    if len > u32::MAX as usize {
        Err(CodecError::FieldTooLong {
            field,
            max: u32::MAX as usize,
            actual: len,
        })
    } else {
        Ok(())
    }
}

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn expect_type(&mut self, expected: u8) -> Result<(), CodecError> {
        let actual = self.u8("type")?;
        if actual == expected {
            Ok(())
        } else {
            Err(CodecError::WrongType { expected, actual })
        }
    }

    fn version(&mut self) -> Result<u8, CodecError> {
        let version = self.u8("version")?;
        if version == CURRENT_VERSION {
            Ok(version)
        } else {
            Err(CodecError::UnsupportedVersion(version))
        }
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, CodecError> {
        Ok(self.bytes(field, 1)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, CodecError> {
        Ok(u16::from_be_bytes(self.array(field)?))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(self.array(field)?))
    }

    fn array<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N], CodecError> {
        let bytes = self.bytes(field, N)?;
        let mut value = [0; N];
        value.copy_from_slice(bytes);
        Ok(value)
    }

    fn bytes(&mut self, field: &'static str, len: usize) -> Result<&'a [u8], CodecError> {
        let end = self.position.checked_add(len).ok_or(CodecError::Truncated {
            field,
            expected_at_least: usize::MAX,
            actual: self.input.len(),
        })?;

        if self.input.len() < end {
            return Err(CodecError::Truncated {
                field,
                expected_at_least: end,
                actual: self.input.len(),
            });
        }

        let bytes = &self.input[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), CodecError> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(CodecError::TrailingData {
                trailing_bytes: self.input.len() - self.position,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_16(seed: u8) -> UuidBytes {
        [seed; 16]
    }

    fn bytes_32(seed: u8) -> HashBytes {
        [seed; 32]
    }

    #[test]
    fn discovery_announce_round_trips() {
        let message = DiscoveryAnnounce {
            version: CURRENT_VERSION,
            address: Ipv4Addr::new(192, 168, 1, 42),
            port: 40091,
            nick: b"alice@example.test".to_vec(),
            key_fingerprint: bytes_32(0xaa),
        };

        let encoded = message.to_bytes().unwrap();

        assert_eq!(encoded[0], 1);
        assert_eq!(encoded[1], CURRENT_VERSION);
        assert_eq!(encoded.len(), 2 + 4 + 2 + 1 + message.nick.len() + 32);
        assert_eq!(DiscoveryAnnounce::from_bytes(&encoded).unwrap(), message);
    }

    #[test]
    fn key_exchange_req_round_trips() {
        let message = KeyExchangeReq {
            version: CURRENT_VERSION,
        };

        let encoded = message.to_bytes().unwrap();

        assert_eq!(encoded, vec![2, CURRENT_VERSION]);
        assert_eq!(KeyExchangeReq::from_bytes(&encoded).unwrap(), message);
    }

    #[test]
    fn key_exchange_resp_round_trips() {
        let message = KeyExchangeResp {
            version: CURRENT_VERSION,
            key_data: b"-----BEGIN PGP PUBLIC KEY BLOCK-----".to_vec(),
        };

        let encoded = message.to_bytes().unwrap();

        assert_eq!(encoded[0], 3);
        assert_eq!(
            u16::from_be_bytes([encoded[2], encoded[3]]) as usize,
            message.key_data.len()
        );
        assert_eq!(KeyExchangeResp::from_bytes(&encoded).unwrap(), message);
    }

    #[test]
    fn chat_message_round_trips() {
        let message = ChatMessage {
            version: CURRENT_VERSION,
            uuid: bytes_16(0x11),
            conv_uuid: bytes_16(0x22),
            conv_type: 1,
            prev_hash: bytes_32(0),
            timestamp: 1_716_232_415,
            source: bytes_32(0x33),
            destination: bytes_32(0x44),
            headers: b"Reply-To-UUID: 00000000-0000-4000-8000-000000000000\r\n".to_vec(),
            data: b"opaque OpenPGP message bytes".to_vec(),
            signature: b"detached-signature".to_vec(),
        };

        let encoded = message.to_bytes().unwrap();

        assert_eq!(encoded[0], 4);
        assert_eq!(ChatMessage::from_bytes(&encoded).unwrap(), message);
    }

    #[test]
    fn message_ack_round_trips() {
        let message = MessageAck {
            version: CURRENT_VERSION,
            uuid: bytes_16(0x55),
            message_hash: bytes_32(0x66),
            acknowledger: bytes_32(0x77),
            signature: b"ack-signature".to_vec(),
        };

        let encoded = message.to_bytes().unwrap();

        assert_eq!(encoded[0], 5);
        assert_eq!(MessageAck::from_bytes(&encoded).unwrap(), message);
    }

    #[test]
    fn message_enum_decodes_all_known_types() {
        let messages = vec![
            Message::from(DiscoveryAnnounce {
                version: CURRENT_VERSION,
                address: Ipv4Addr::new(10, 0, 0, 1),
                port: 40091,
                nick: b"alice".to_vec(),
                key_fingerprint: bytes_32(1),
            }),
            Message::from(KeyExchangeReq {
                version: CURRENT_VERSION,
            }),
            Message::from(KeyExchangeResp {
                version: CURRENT_VERSION,
                key_data: b"public-key".to_vec(),
            }),
            Message::from(ChatMessage {
                version: CURRENT_VERSION,
                uuid: bytes_16(2),
                conv_uuid: bytes_16(3),
                conv_type: 1,
                prev_hash: bytes_32(4),
                timestamp: 42,
                source: bytes_32(5),
                destination: bytes_32(6),
                headers: b"Content-Type: application/pgp-encrypted\r\n".to_vec(),
                data: b"ciphertext".to_vec(),
                signature: b"signature".to_vec(),
            }),
            Message::from(MessageAck {
                version: CURRENT_VERSION,
                uuid: bytes_16(7),
                message_hash: bytes_32(8),
                acknowledger: bytes_32(9),
                signature: b"signature".to_vec(),
            }),
        ];

        for message in messages {
            let encoded = message.to_bytes().unwrap();
            assert_eq!(Message::from_bytes(&encoded).unwrap(), message);
        }
    }

    #[test]
    fn rejects_zero_length_input() {
        assert_eq!(Message::from_bytes(&[]), Err(CodecError::EmptyInput));
    }

    #[test]
    fn rejects_unrecognized_type_id() {
        assert_eq!(Message::from_bytes(&[99, CURRENT_VERSION]), Err(CodecError::UnknownType(99)));
    }

    #[test]
    fn rejects_truncated_message() {
        let err = DiscoveryAnnounce::from_bytes(&[1, CURRENT_VERSION, 127, 0]).unwrap_err();

        assert_eq!(
            err,
            CodecError::Truncated {
                field: "address",
                expected_at_least: 6,
                actual: 4
            }
        );
    }

    #[test]
    fn rejects_trailing_data() {
        let err = KeyExchangeReq::from_bytes(&[2, CURRENT_VERSION, 0]).unwrap_err();

        assert_eq!(err, CodecError::TrailingData { trailing_bytes: 1 });
    }

    #[test]
    fn rejects_unsupported_version() {
        let err = KeyExchangeReq::from_bytes(&[2, CURRENT_VERSION + 1]).unwrap_err();

        assert_eq!(err, CodecError::UnsupportedVersion(CURRENT_VERSION + 1));
    }

    #[test]
    fn rejects_wrong_type_for_specific_decoder() {
        let err = KeyExchangeReq::from_bytes(&[3, CURRENT_VERSION]).unwrap_err();

        assert_eq!(
            err,
            CodecError::WrongType {
                expected: 2,
                actual: 3
            }
        );
    }

    #[test]
    fn rejects_overlong_nick() {
        let message = DiscoveryAnnounce {
            version: CURRENT_VERSION,
            address: Ipv4Addr::LOCALHOST,
            port: 40091,
            nick: vec![b'a'; 256],
            key_fingerprint: bytes_32(1),
        };

        assert_eq!(
            message.to_bytes(),
            Err(CodecError::FieldTooLong {
                field: "nick",
                max: 255,
                actual: 256
            })
        );
    }
}
