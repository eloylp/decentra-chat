use crate::{
    codec::{self, ChatMessage, Message},
    crypto,
    discovery::Fingerprint,
};
use pgp::composed::{SignedPublicKey, SignedSecretKey};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
};

const WIRE_CHAT_VERSION: u8 = 1;
const CONVERSATION_TYPE_DIRECT: u8 = 1;
const MAX_CHAT_FRAME_LEN: usize = 8 * 1024 * 1024;
const TIMESTAMP_WINDOW_SECS: i64 = 5 * 60;

/// Local signing and decryption identity for TCP chat-message transport.
#[derive(Clone)]
pub struct LocalChatIdentity {
    pub fingerprint: Fingerprint,
    pub secret_key: SignedSecretKey,
}

/// Peer identity required to encrypt outgoing messages and verify incoming ones.
#[derive(Clone)]
pub struct PeerChatIdentity {
    pub fingerprint: Fingerprint,
    pub public_key: SignedPublicKey,
}

/// Inputs used to build a type-4 chat message.
pub struct OutgoingChatMessage {
    pub conversation_uuid: [u8; 16],
    pub previous_hash: [u8; 32],
    pub headers: Vec<u8>,
    pub plaintext: Vec<u8>,
}

/// Accepted type-4 chat message after signature validation and decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedChatMessage {
    pub uuid: [u8; 16],
    pub conversation_uuid: [u8; 16],
    pub previous_hash: [u8; 32],
    pub timestamp: u32,
    pub source: Fingerprint,
    pub destination: Fingerprint,
    pub headers: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub message_hash: [u8; 32],
}

/// Running TCP receiver for encrypted signed type-4 messages.
pub struct ChatMessageService {
    local_addr: SocketAddr,
    task: JoinHandle<()>,
    accepted_rx: mpsc::Receiver<ReceivedChatMessage>,
}

/// Errors returned by encrypted signed chat-message transport.
#[derive(Debug, Error)]
pub enum ChatTransportError {
    #[error("TCP chat listener bind failed at {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("TCP chat local address is unavailable: {0}")]
    LocalAddr(#[source] std::io::Error),
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
    #[error("chat message version {version} is unsupported")]
    UnsupportedVersion { version: u8 },
    #[error("chat message conversation type {conv_type} is unsupported")]
    UnsupportedConversationType { conv_type: u8 },
    #[error("chat message id is not a UUID v4")]
    InvalidMessageUuid,
    #[error("chat conversation id is not a UUID v4")]
    InvalidConversationUuid,
    #[error("chat previous hash did not match expected linkage input")]
    PreviousHashMismatch,
    #[error("chat message source fingerprint did not match expected peer")]
    SourceMismatch,
    #[error("chat message destination fingerprint did not match local identity")]
    DestinationMismatch,
    #[error("chat message timestamp is outside the accepted window")]
    TimestampOutOfWindow,
    #[error("chat headers are too large: {len} bytes, max 65535")]
    HeadersTooLarge { len: usize },
    #[error("chat message signature verification failed: {0}")]
    Signature(#[source] crypto::CryptoError),
    #[error("chat payload encryption failed: {0}")]
    Encrypt(#[source] crypto::CryptoError),
    #[error("chat payload decryption failed: {0}")]
    Decrypt(#[source] crypto::CryptoError),
    #[error("system clock is before the Unix epoch")]
    InvalidSystemTime,
}

impl ChatMessageService {
    /// Bind a TCP listener that accepts encrypted signed type-4 chat messages
    /// from `peer` and decrypts them with `local`.
    pub async fn start(
        listen_addr: SocketAddr,
        local: LocalChatIdentity,
        peer: PeerChatIdentity,
        expected_previous_hash: [u8; 32],
    ) -> Result<Self, ChatTransportError> {
        let listener = TcpListener::bind(listen_addr)
            .await
            .map_err(|source| ChatTransportError::Bind {
                addr: listen_addr,
                source,
            })?;
        let local_addr = listener
            .local_addr()
            .map_err(ChatTransportError::LocalAddr)?;
        let (accepted_tx, accepted_rx) = mpsc::channel(16);

        let task = tokio::spawn(async move {
            listener_loop(listener, local, peer, expected_previous_hash, accepted_tx).await;
        });

        Ok(Self {
            local_addr,
            task,
            accepted_rx,
        })
    }

    /// Return the bound address. This is especially useful when tests bind port 0.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Wait for the next accepted and decrypted message.
    pub async fn recv(&mut self) -> Option<ReceivedChatMessage> {
        self.accepted_rx.recv().await
    }
}

impl Drop for ChatMessageService {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Build, encrypt, sign, and send one type-4 chat message to a TCP peer.
pub async fn send_chat_message(
    peer_addr: SocketAddr,
    local: &LocalChatIdentity,
    peer: &PeerChatIdentity,
    outgoing: OutgoingChatMessage,
) -> Result<ChatMessage, ChatTransportError> {
    let message = build_chat_message(local, peer, outgoing)?;
    let mut stream = TcpStream::connect(peer_addr)
        .await
        .map_err(|source| ChatTransportError::Connect {
            addr: peer_addr,
            source,
        })?;

    write_message(&mut stream, Message::ChatMessage(message.clone())).await?;
    Ok(message)
}

/// Verify, decrypt, and hash a received type-4 chat message.
pub fn accept_chat_message(
    message: ChatMessage,
    local: &LocalChatIdentity,
    peer: &PeerChatIdentity,
    expected_previous_hash: [u8; 32],
) -> Result<ReceivedChatMessage, ChatTransportError> {
    validate_chat_message(&message, local, peer, expected_previous_hash)?;

    let signature_digest = chat_message_signature_digest(&message);
    crypto::verify(&peer.public_key, &signature_digest, &message.signature)
        .map_err(ChatTransportError::Signature)?;

    let plaintext = crypto::decrypt_from_peer(&local.secret_key, &message.data)
        .map_err(ChatTransportError::Decrypt)?;
    let message_hash = Sha256::digest(Vec::<u8>::from(message.clone())).into();

    Ok(ReceivedChatMessage {
        uuid: message.uuid,
        conversation_uuid: message.conv_uuid,
        previous_hash: message.prev_hash,
        timestamp: message.timestamp,
        source: message.source,
        destination: message.destination,
        headers: message.headers,
        plaintext,
        message_hash,
    })
}

fn build_chat_message(
    local: &LocalChatIdentity,
    peer: &PeerChatIdentity,
    outgoing: OutgoingChatMessage,
) -> Result<ChatMessage, ChatTransportError> {
    if !is_uuid_v4(&outgoing.conversation_uuid) {
        return Err(ChatTransportError::InvalidConversationUuid);
    }
    if outgoing.headers.len() > u16::MAX as usize {
        return Err(ChatTransportError::HeadersTooLarge {
            len: outgoing.headers.len(),
        });
    }

    let encrypted = crypto::encrypt_for_peer(&peer.public_key, &outgoing.plaintext)
        .map_err(ChatTransportError::Encrypt)?;
    let mut message = ChatMessage {
        version: WIRE_CHAT_VERSION,
        uuid: new_uuid_v4(),
        conv_uuid: outgoing.conversation_uuid,
        conv_type: CONVERSATION_TYPE_DIRECT,
        prev_hash: outgoing.previous_hash,
        timestamp: unix_timestamp_u32()?,
        source: local.fingerprint,
        destination: peer.fingerprint,
        headers: outgoing.headers,
        data: encrypted,
        signature: Vec::new(),
    };
    let signature_digest = chat_message_signature_digest(&message);
    message.signature = crypto::sign(&local.secret_key, &signature_digest)
        .map_err(ChatTransportError::Signature)?;

    Ok(message)
}

async fn listener_loop(
    listener: TcpListener,
    local: LocalChatIdentity,
    peer: PeerChatIdentity,
    expected_previous_hash: [u8; 32],
    accepted_tx: mpsc::Sender<ReceivedChatMessage>,
) {
    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let Ok((stream, _peer_addr)) = accept_result else {
                    continue;
                };
                let local = local.clone();
                let peer = peer.clone();
                let accepted_tx = accepted_tx.clone();
                connections.spawn(async move {
                    if let Ok(message) =
                        handle_connection(stream, &local, &peer, expected_previous_hash).await
                    {
                        let _ = accepted_tx.send(message).await;
                    }
                });
            }
            Some(_result) = connections.join_next() => {}
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    local: &LocalChatIdentity,
    peer: &PeerChatIdentity,
    expected_previous_hash: [u8; 32],
) -> Result<ReceivedChatMessage, ChatTransportError> {
    let message = read_message(&mut stream).await?;
    let Message::ChatMessage(message) = message else {
        return Err(ChatTransportError::UnexpectedMessage {
            received: message_name(&message),
        });
    };

    accept_chat_message(message, local, peer, expected_previous_hash)
}

fn validate_chat_message(
    message: &ChatMessage,
    local: &LocalChatIdentity,
    peer: &PeerChatIdentity,
    expected_previous_hash: [u8; 32],
) -> Result<(), ChatTransportError> {
    if message.version != WIRE_CHAT_VERSION {
        return Err(ChatTransportError::UnsupportedVersion {
            version: message.version,
        });
    }
    if message.conv_type != CONVERSATION_TYPE_DIRECT {
        return Err(ChatTransportError::UnsupportedConversationType {
            conv_type: message.conv_type,
        });
    }
    if !is_uuid_v4(&message.uuid) {
        return Err(ChatTransportError::InvalidMessageUuid);
    }
    if !is_uuid_v4(&message.conv_uuid) {
        return Err(ChatTransportError::InvalidConversationUuid);
    }
    if message.prev_hash != expected_previous_hash {
        return Err(ChatTransportError::PreviousHashMismatch);
    }
    if message.source != peer.fingerprint {
        return Err(ChatTransportError::SourceMismatch);
    }
    if message.destination != local.fingerprint {
        return Err(ChatTransportError::DestinationMismatch);
    }
    if !timestamp_in_window(message.timestamp)? {
        return Err(ChatTransportError::TimestampOutOfWindow);
    }
    Ok(())
}

fn chat_message_signed_bytes(message: &ChatMessage) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(message.version);
    out.extend_from_slice(&message.uuid);
    out.extend_from_slice(&message.conv_uuid);
    out.push(message.conv_type);
    out.extend_from_slice(&message.prev_hash);
    out.extend_from_slice(&message.timestamp.to_be_bytes());
    out.extend_from_slice(&message.source);
    out.extend_from_slice(&message.destination);
    out.extend_from_slice(&(message.headers.len() as u16).to_be_bytes());
    out.extend_from_slice(&message.headers);
    out.extend_from_slice(&(message.data.len() as u32).to_be_bytes());
    out.extend_from_slice(&message.data);
    out
}

fn chat_message_signature_digest(message: &ChatMessage) -> [u8; 32] {
    Sha256::digest(chat_message_signed_bytes(message)).into()
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

async fn write_message(
    stream: &mut TcpStream,
    message: Message,
) -> Result<(), ChatTransportError> {
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

fn new_uuid_v4() -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

fn is_uuid_v4(bytes: &[u8; 16]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
        && bytes[6] & 0xf0 == 0x40
        && bytes[8] & 0xc0 == 0x80
}

fn timestamp_in_window(timestamp: u32) -> Result<bool, ChatTransportError> {
    let now = unix_timestamp()?;
    let timestamp = i64::from(timestamp);
    Ok((now - timestamp).abs() <= TIMESTAMP_WINDOW_SECS)
}

fn unix_timestamp_u32() -> Result<u32, ChatTransportError> {
    u32::try_from(unix_timestamp()?).map_err(|_| ChatTransportError::InvalidSystemTime)
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
    use crate::crypto::{fingerprint, public_key_to_bytes, KeyPair};
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::time::{timeout, Duration};

    fn identities() -> (
        LocalChatIdentity,
        PeerChatIdentity,
        LocalChatIdentity,
        PeerChatIdentity,
    ) {
        let alice = KeyPair::generate().expect("alice keypair");
        let bob = KeyPair::generate().expect("bob keypair");
        let alice_public = public_key_to_bytes(&alice.public).expect("alice public bytes");
        let bob_public = public_key_to_bytes(&bob.public).expect("bob public bytes");
        let alice_fingerprint = fingerprint(&alice_public);
        let bob_fingerprint = fingerprint(&bob_public);

        (
            LocalChatIdentity {
                fingerprint: alice_fingerprint,
                secret_key: alice.secret,
            },
            PeerChatIdentity {
                fingerprint: bob_fingerprint,
                public_key: bob.public.clone(),
            },
            LocalChatIdentity {
                fingerprint: bob_fingerprint,
                secret_key: bob.secret,
            },
            PeerChatIdentity {
                fingerprint: alice_fingerprint,
                public_key: alice.public,
            },
        )
    }

    fn uuid_v4(seed: u8) -> [u8; 16] {
        let mut bytes = [seed; 16];
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        bytes
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loopback_peer_receives_encrypted_signed_message() {
        let (alice_local, bob_peer, bob_local, alice_peer) = identities();
        let previous_hash = [0x42; 32];
        let mut receiver = ChatMessageService::start(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            bob_local,
            alice_peer,
            previous_hash,
        )
        .await
        .expect("start chat receiver");

        let sent = send_chat_message(
            receiver.local_addr(),
            &alice_local,
            &bob_peer,
            OutgoingChatMessage {
                conversation_uuid: uuid_v4(0x11),
                previous_hash,
                headers: b"Content-Type: text/plain".to_vec(),
                plaintext: b"hello bob".to_vec(),
            },
        )
        .await
        .expect("send chat message");

        let received = timeout(Duration::from_secs(10), receiver.recv())
            .await
            .expect("receive should finish")
            .expect("accepted message");

        assert_eq!(received.uuid, sent.uuid);
        assert_eq!(received.conversation_uuid, sent.conv_uuid);
        assert_eq!(received.previous_hash, previous_hash);
        assert_eq!(received.source, alice_local.fingerprint);
        assert_eq!(received.destination, bob_peer.fingerprint);
        assert_eq!(received.headers, b"Content-Type: text/plain");
        assert_eq!(received.plaintext, b"hello bob");
        assert_ne!(sent.data, b"hello bob");
    }

    #[test]
    fn invalid_signature_is_rejected_before_decryption() {
        let (alice_local, bob_peer, bob_local, alice_peer) = identities();
        let previous_hash = [0x24; 32];
        let mut message = build_chat_message(
            &alice_local,
            &bob_peer,
            OutgoingChatMessage {
                conversation_uuid: uuid_v4(0x33),
                previous_hash,
                headers: Vec::new(),
                plaintext: b"tamper test".to_vec(),
            },
        )
        .expect("build message");
        message.signature[0] ^= 0xff;

        let error = accept_chat_message(message, &bob_local, &alice_peer, previous_hash)
            .expect_err("tampered signature should be rejected");

        assert!(matches!(error, ChatTransportError::Signature(_)));
    }

    #[test]
    fn previous_hash_mismatch_is_rejected() {
        let (alice_local, bob_peer, bob_local, alice_peer) = identities();
        let message = build_chat_message(
            &alice_local,
            &bob_peer,
            OutgoingChatMessage {
                conversation_uuid: uuid_v4(0x55),
                previous_hash: [0x10; 32],
                headers: Vec::new(),
                plaintext: b"bad chain".to_vec(),
            },
        )
        .expect("build message");

        let error = accept_chat_message(message, &bob_local, &alice_peer, [0x20; 32])
            .expect_err("wrong previous hash should be rejected");

        assert!(matches!(error, ChatTransportError::PreviousHashMismatch));
    }
}
