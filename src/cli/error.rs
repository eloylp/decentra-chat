use crate::{
    config::ConfigError,
    conversation_engine::ConversationEngineError,
    crypto,
    discovery::DiscoveryError,
    key_exchange::KeyExchangeError,
    message_transport::ChatTransportError,
    storage::StorageError,
};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("failed to load config from {path}: {source}")]
    LoadConfig {
        path: PathBuf,
        #[source]
        source: ConfigError,
    },
    #[error("failed to initialize SQLite storage at {path}: {source}")]
    InitializeStorage {
        path: PathBuf,
        #[source]
        source: StorageError,
    },
    #[error("config field `{field}` must be an IPv4 address for discovery, got {value}")]
    DiscoveryRequiresIpv4 {
        field: &'static str,
        value: IpAddr,
    },
    #[error("invalid discovery fingerprint: {0}")]
    InvalidFingerprint(String),
    #[error("invalid contact alias `{alias}`: use 1-64 visible characters without tabs, newlines, or leading/trailing spaces")]
    InvalidContactAlias { alias: String },
    #[error(
        "contact `{query}` is not in local storage; run `contact add --alias <ALIAS> --fingerprint <HEX>` first"
    )]
    MissingContact { query: String },
    #[error("contact `{alias}` is not trusted; run `contact trust {alias}` after verifying the fingerprint")]
    ContactNotTrusted { alias: String },
    #[error("contact `{alias}` has no stored public key; run `onboard --alias {alias} ...` or `key-request --peer <ADDR>` first")]
    ContactMissingPublicKey { alias: String },
    #[error(
        "contact alias `{alias}` is already pinned to fingerprint {existing_fingerprint}; refusing to replace it with {new_fingerprint}"
    )]
    ContactFingerprintChanged {
        alias: String,
        existing_fingerprint: String,
        new_fingerprint: String,
    },
    #[error(
        "peer at {peer} returned fingerprint {actual_fingerprint}, but discovery advertised {expected_fingerprint}; verify the peer before trusting it"
    )]
    OnboardFingerprintMismatch {
        peer: SocketAddr,
        expected_fingerprint: String,
        actual_fingerprint: String,
    },
    #[error("failed to persist contact: {0}")]
    PersistContact(#[source] StorageError),
    #[error("failed to read contacts: {0}")]
    ReadContacts(#[source] StorageError),
    #[error("discovery duration must be greater than zero")]
    InvalidDiscoveryDuration,
    #[error("discovery announcement interval must be greater than zero")]
    InvalidAnnounceInterval,
    #[error("failed to start discovery session: {0}")]
    StartDiscovery(#[from] DiscoveryError),
    #[error("failed to create async runtime for discovery: {0}")]
    CreateRuntime(#[source] io::Error),
    #[error("failed to read key file at {path}: {source}")]
    ReadKeyFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write key file at {path}: {source}")]
    WriteKeyFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to create key directory at {path}: {source}")]
    CreateKeyDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to prepare PGP key material: {0}")]
    Crypto(#[source] crypto::CryptoError),
    #[error("key service duration must be greater than zero")]
    InvalidKeyServeDuration,
    #[error("receive duration must be greater than zero")]
    InvalidReceiveDuration,
    #[error("chat duration must be greater than zero")]
    InvalidChatDuration,
    #[error("failed to read chat stdin: {0}")]
    ReadStdin(#[source] io::Error),
    #[error("invalid message hash: {0}")]
    InvalidMessageHash(String),
    #[error("invalid conversation UUID: {0}")]
    InvalidConversationUuid(String),
    #[error("peer key {fingerprint} is not in storage; run `key-request --peer <ADDR>` first")]
    MissingPeerKey { fingerprint: String },
    #[error("failed to persist message facts: {0}")]
    PersistMessage(#[source] StorageError),
    #[error(
        "conversation {conversation_uuid} is not in local storage; run `conversations` to list known conversations or receive/send a message first"
    )]
    MissingConversation { conversation_uuid: String },
    #[error(
        "conversation {conversation_uuid} has a broken prev_hash chain; inspect stored messages before relying on this history"
    )]
    BrokenConversationChain { conversation_uuid: String },
    #[error("failed to read conversation history: {0}")]
    ReadConversation(#[source] ConversationEngineError),
    #[error("failed to exchange peer key: {0}")]
    KeyExchange(#[from] KeyExchangeError),
    #[error("failed to send or receive encrypted message: {0}")]
    ChatTransport(#[from] ChatTransportError),
    #[error("receive timed out after {duration_ms} ms without an accepted message")]
    ReceiveTimedOut { duration_ms: u64 },
    #[error("failed to write CLI output: {0}")]
    WriteOutput(#[from] io::Error),
}
