use crate::{
    codec::{self, ChatMessage, Message},
    crypto::{self, CryptoError},
    discovery::Fingerprint,
};
use pgp::composed::{SignedPublicKey, SignedSecretKey};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use uuid::{Uuid, Version};

const WIRE_CHAT_VERSION: u8 = 1;
const MAX_CHAT_FRAME_LEN: usize = 16 * 1024 * 1024;
const DEFAULT_TIMESTAMP_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Fields supplied by the caller when constructing a type-4 chat message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundChatMessage {
    pub conversation_uuid: Uuid,
    pub conversation_type: u8,
    pub previous_hash: [u8; 32],
    pub headers: Vec<u8>,
    pub plaintext: Vec<u8>,
}

/// A decrypted type-4 chat message accepted by the receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedChatMessage {
    pub message_uuid: Uuid,
    pub conversation_uuid: Uuid,
    pub conversation_type: u8,
    pub previous_hash: [u8; 32],
    pub timestamp: u32,
    pub source: Fingerprint,
    pub destination: Fingerprint,
    pub headers: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub message_hash: [u8; 32],
}

/// Validation inputs that are not fully self-describing in the wire message.
#[derive(Debug, Clone)]
pub struct ChatValidation {
    pub sender_fingerprint: Fingerprint,
    pub receiver_fingerprint: Fingerprint,
    pub expected_previous_hash: [u8; 32],
    pub timestamp_window: Duration,
}

impl ChatValidation {
    pub fn new(
        sender_fingerprint: Fingerprint,
        receiver_fingerprint: Fingerprint,
        expected_previous_hash: [u8; 32],
    ) -> Self {
        Self {
            sender_fingerprint,
            receiver_fingerprint,
            expected_previous_hash,
            timestamp_window: DEFAULT_TIMESTAMP_WINDOW,
        }
    }

    pub fn with_timestamp_window(mut self, timestamp_window: Duration) -> Self {
        self.timestamp_window = timestamp_window;
        self
    }
}

/// Errors returned while building, sending, receiving, or validating type-4 messages.
#[derive(Debug, Error)]
pub enum ChatTransportError {
    #[error("TCP chat connection to {addr} failed: {source}")]
    Connect {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("TCP chat I/O failed while {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("TCP chat frame length {len} exceeds max {max}")]
    FrameTooLarge { len: usize, max: usize },
    #[error("TCP chat codec rejected message: {0}")]
    Codec(#[from] codec::CodecError),
    #[error("expected chat message, received {received}")]
    UnexpectedMessage { received: &'static str },
    #[error("chat message signature verification failed: {0}")]
    Signature(#[source] CryptoError),
    #[error("chat message encryption failed: {0}")]
    Encrypt(#[source] CryptoError),
    #[error("chat message decryption failed: {0}")]
    Decrypt(#[source] CryptoError),
    #[error("chat message UUID is not version 4")]
    InvalidMessageUuid,
    #[error("conversation UUID is not version 4")]
    InvalidConversationUuid,
    #[error("chat message source fingerprint does not match expected peer")]
    SourceMismatch,
    #[error("chat message destination fingerprint does not match local identity")]
    DestinationMismatch,
    #[error("chat message previous hash does not match expected conversation head")]
    PreviousHashMismatch,
    #[error("chat message timestamp is outside the accepted window")]
    TimestampOutOfWindow,
    #[error("system clock is before the Unix epoch")]
    InvalidSystemTime,
    #[error("current Unix timestamp does not fit in the wire u32 timestamp field")]
    TimestampOverflow,
}

/// Construct an encrypted, DC-signed type-4 chat message.
pub fn build_chat_message(
    outbound: OutboundChatMessage,
    sender_secret_key: &SignedSecretKey,
    sender_fingerprint: Fingerprint,
    receiver_fingerprint: Fingerprint,
    receiver_public_key: &SignedPublicKey,
) -> Result<ChatMessage, ChatTransportError> {
    let encrypted_payload = crypto::encrypt(receiver_public_key, &outbound.plaintext)
        .map_err(ChatTransportError::Encrypt)?;
    let timestamp = current_wire_timestamp()?;
    let mut message = ChatMessage {
        version: WIRE_CHAT_VERSION,
        uuid: *Uuid::new_v4().as_bytes(),
        conv_uuid: *outbound.conversation_uuid.as_bytes(),
        conv_type: outbound.conversation_type,
        prev_hash: outbound.previous_hash,
        timestamp,
        source: sender_fingerprint,
        destination: receiver_fingerprint,
        headers: outbound.headers,
        data: encrypted_payload,
        signature: Vec::new(),
    };

    let signature = crypto::sign(sender_secret_key, &chat_signature_digest(&message))
        .map_err(ChatTransportError::Signature)?;
    message.signature = signature;
    Ok(message)
}

/// Send one encrypted, signed type-4 message to a peer over TCP.
pub async fn send_chat_message(
    peer_addr: SocketAddr,
    message: ChatMessage,
) -> Result<(), ChatTransportError> {
    let mut stream = TcpStream::connect(peer_addr)
        .await
        .map_err(|source| ChatTransportError::Connect {
            addr: peer_addr,
            source,
        })?;
    write_message(&mut stream, Message::ChatMessage(message)).await
}

/// Read, validate, decrypt, and accept a type-4 chat message from a stream.
pub async fn receive_chat_message(
    stream: &mut TcpStream,
    local_secret_key: &SignedSecretKey,
    sender_public_key: &SignedPublicKey,
    validation: &ChatValidation,
) -> Result<AcceptedChatMessage, ChatTransportError> {
    let message = read_message(stream).await?;
    let Message::ChatMessage(message) = message else {
        return Err(ChatTransportError::UnexpectedMessage {
            received: message_name(&message),
        });
    };

    accept_chat_message(message, local_secret_key, sender_public_key, validation)
}

pub fn accept_chat_message(
    message: ChatMessage,
    local_secret_key: &SignedSecretKey,
    sender_public_key: &SignedPublicKey,
    validation: &ChatValidation,
) -> Result<AcceptedChatMessage, ChatTransportError> {
    validate_uuid_v4(message.uuid).map_err(|_| ChatTransportError::InvalidMessageUuid)?;
    validate_uuid_v4(message.conv_uuid).map_err(|_| ChatTransportError::InvalidConversationUuid)?;
    if message.source != validation.sender_fingerprint {
        return Err(ChatTransportError::SourceMismatch);
    }
    if message.destination != validation.receiver_fingerprint {
        return Err(ChatTransportError::DestinationMismatch);
    }
    if message.prev_hash != validation.expected_previous_hash {
        return Err(ChatTransportError::PreviousHashMismatch);
    }
    validate_timestamp(message.timestamp, validation.timestamp_window)?;

    crypto::verify(
        sender_public_key,
        &chat_signature_digest(&message),
        &message.signature,
    )
    .map_err(ChatTransportError::Signature)?;

    let plaintext = crypto::decrypt(local_secret_key, &message.data)
        .map_err(ChatTransportError::Decrypt)?;
    let message_hash = chat_message_hash(&message);

    Ok(AcceptedChatMessage {
        message_uuid: Uuid::from_bytes(message.uuid),
        conversation_uuid: Uuid::from_bytes(message.conv_uuid),
        conversation_type: message.conv_type,
        previous_hash: message.prev_hash,
        timestamp: message.timestamp,
        source: message.source,
        destination: message.destination,
        headers: message.headers,
        plaintext,
        message_hash,
    })
}

async fn read_message(stream: &mut TcpStream) -> Result<Message, ChatTransportError> {
    let len = stream
        .read_u32()
        .await
        .map_err(|source| ChatTransportError::Io {
            operation: "reading frame length",
            source,
        })? as usize;
    if len > MAX_CHAT_FRAME_LEN {
        return Err(ChatTransportError::FrameTooLarge {
            len,
            max: MAX_CHAT_FRAME_LEN,
        });
    }

    let mut bytes = vec![0_u8; len];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|source| ChatTransportError::Io {
            operation: "reading frame payload",
            source,
        })?;

    Message::try_from(bytes.as_slice()).map_err(ChatTransportError::Codec)
}

async fn write_message(stream: &mut TcpStream, message: Message) -> Result<(), ChatTransportError> {
    let bytes: Vec<u8> = message.into();
    if bytes.len() > MAX_CHAT_FRAME_LEN {
        return Err(ChatTransportError::FrameTooLarge {
            len: bytes.len(),
            max: MAX_CHAT_FRAME_LEN,
        });
    }

    stream
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|source| ChatTransportError::Io {
            operation: "writing frame length",
            source,
        })?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|source| ChatTransportError::Io {
            operation: "writing frame payload",
            source,
        })?;
    stream.flush().await.map_err(|source| ChatTransportError::Io {
        operation: "flushing frame",
        source,
    })
}

fn chat_signature_payload(message: &ChatMessage) -> Vec<u8> {
    let mut signed = message.clone();
    signed.signature.clear();
    signed.into()
}

fn chat_signature_digest(message: &ChatMessage) -> [u8; 32] {
    Sha256::digest(chat_signature_payload(message)).into()
}

fn chat_message_hash(message: &ChatMessage) -> [u8; 32] {
    Sha256::digest(chat_signature_payload(message)).into()
}

fn validate_uuid_v4(bytes: [u8; 16]) -> Result<(), ()> {
    let uuid = Uuid::from_bytes(bytes);
    if uuid.get_version() == Some(Version::Random) {
        Ok(())
    } else {
        Err(())
    }
}

fn validate_timestamp(timestamp: u32, window: Duration) -> Result<(), ChatTransportError> {
    let now = unix_timestamp()?;
    let timestamp = i64::from(timestamp);
    let window =
        i64::try_from(window.as_secs()).map_err(|_| ChatTransportError::TimestampOutOfWindow)?;
    let earliest = now.saturating_sub(window);
    let latest = now.saturating_add(window);
    if (earliest..=latest).contains(&timestamp) {
        Ok(())
    } else {
        Err(ChatTransportError::TimestampOutOfWindow)
    }
}

fn current_wire_timestamp() -> Result<u32, ChatTransportError> {
    u32::try_from(unix_timestamp()?).map_err(|_| ChatTransportError::TimestampOverflow)
}

fn unix_timestamp() -> Result<i64, ChatTransportError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ChatTransportError::InvalidSystemTime)?;
    i64::try_from(duration.as_secs()).map_err(|_| ChatTransportError::InvalidSystemTime)
}

fn message_name(message: &Message) -> &'static str {
    match message {
        Message::DiscoveryAnnounce(_) => "discovery announce",
        Message::KeyExchangeReq(_) => "key-exchange request",
        Message::KeyExchangeResp(_) => "key-exchange response",
        Message::ChatMessage(_) => "chat message",
        Message::MessageAck(_) => "message ack",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{public_key_to_bytes, KeyPair};
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    fn fingerprint(keypair: &KeyPair) -> Fingerprint {
        let public_key = public_key_to_bytes(&keypair.public).expect("serialize public key");
        crypto::fingerprint(&public_key)
    }

    fn outbound(previous_hash: [u8; 32]) -> OutboundChatMessage {
        OutboundChatMessage {
            conversation_uuid: Uuid::new_v4(),
            conversation_type: 1,
            previous_hash,
            headers: b"Content-Type: text/plain".to_vec(),
            plaintext: b"hello over encrypted tcp".to_vec(),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loopback_accepts_encrypted_signed_chat_message() {
        let sender = KeyPair::generate().expect("generate sender");
        let receiver = KeyPair::generate().expect("generate receiver");
        let sender_fingerprint = fingerprint(&sender);
        let receiver_fingerprint = fingerprint(&receiver);
        let previous_hash = [0x42; 32];
        let validation =
            ChatValidation::new(sender_fingerprint, receiver_fingerprint, previous_hash);
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind receiver");
        let addr = listener.local_addr().expect("listener addr");
        let receiver_secret = receiver.secret.clone();
        let sender_public = sender.public.clone();
        let receiver_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept chat");
            receive_chat_message(&mut stream, &receiver_secret, &sender_public, &validation)
                .await
                .expect("receive chat")
        });

        let message = build_chat_message(
            outbound(previous_hash),
            &sender.secret,
            sender_fingerprint,
            receiver_fingerprint,
            &receiver.public,
        )
        .expect("build chat");
        send_chat_message(addr, message).await.expect("send chat");
        let accepted = timeout(Duration::from_secs(10), receiver_task)
            .await
            .expect("receive should finish")
            .expect("receiver task");

        assert_eq!(accepted.source, sender_fingerprint);
        assert_eq!(accepted.destination, receiver_fingerprint);
        assert_eq!(accepted.previous_hash, previous_hash);
        assert_eq!(accepted.plaintext, b"hello over encrypted tcp");
        assert_eq!(
            accepted.message_uuid.get_version(),
            Some(Version::Random)
        );
        assert_eq!(
            accepted.conversation_uuid.get_version(),
            Some(Version::Random)
        );
    }

    #[test]
    fn rejects_invalid_signature_before_decrypting() {
        let sender = KeyPair::generate().expect("generate sender");
        let receiver = KeyPair::generate().expect("generate receiver");
        let other = KeyPair::generate().expect("generate other signer");
        let sender_fingerprint = fingerprint(&sender);
        let receiver_fingerprint = fingerprint(&receiver);
        let previous_hash = [0x24; 32];
        let validation =
            ChatValidation::new(sender_fingerprint, receiver_fingerprint, previous_hash);
        let mut message = build_chat_message(
            outbound(previous_hash),
            &sender.secret,
            sender_fingerprint,
            receiver_fingerprint,
            &receiver.public,
        )
        .expect("build chat");
        message.signature =
            crypto::sign(&other.secret, &chat_signature_digest(&message)).expect("resign");

        let error = accept_chat_message(message, &receiver.secret, &sender.public, &validation)
            .expect_err("invalid signature is rejected");

        assert!(matches!(error, ChatTransportError::Signature(_)));
    }

    #[test]
    fn rejects_mismatched_previous_hash() {
        let sender = KeyPair::generate().expect("generate sender");
        let receiver = KeyPair::generate().expect("generate receiver");
        let sender_fingerprint = fingerprint(&sender);
        let receiver_fingerprint = fingerprint(&receiver);
        let message = build_chat_message(
            outbound([0x11; 32]),
            &sender.secret,
            sender_fingerprint,
            receiver_fingerprint,
            &receiver.public,
        )
        .expect("build chat");
        let validation = ChatValidation::new(sender_fingerprint, receiver_fingerprint, [0x22; 32]);

        let error = accept_chat_message(message, &receiver.secret, &sender.public, &validation)
            .expect_err("wrong previous hash is rejected");

        assert!(matches!(error, ChatTransportError::PreviousHashMismatch));
    }
}
