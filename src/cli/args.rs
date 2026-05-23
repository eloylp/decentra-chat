use clap::{Parser, Subcommand};
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

#[derive(Debug, Parser)]
#[command(
    name = "decentra-chat",
    version,
    about = "Local-first peer-to-peer chat client",
    long_about = "DecentraChat is a local-first peer-to-peer chat client. The current command surface covers configuration and storage diagnostics, bounded LAN peer discovery, key exchange, one-message send/receive, and local conversation history."
)]
pub struct Cli {
    /// Path to config.toml. Defaults to DC_CONFIG or the platform config directory.
    #[arg(short, long, global = true, value_name = "PATH")]
    pub(crate) config: Option<PathBuf>,

    #[command(subcommand)]
    pub(crate) command: Option<CliCommand>,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum CliCommand {
    /// Load config, apply storage migrations, and print non-secret node settings.
    Status,
    /// Generate a local PGP identity for key exchange and message signing.
    Keygen(KeygenArgs),
    /// Serve the local public key over the TCP key-exchange protocol.
    KeyServe(KeyServeArgs),
    /// Request and store one peer public key over TCP.
    KeyRequest(KeyRequestArgs),
    /// Run bounded UDP multicast discovery and print the visible peer list.
    Discover(DiscoverArgs),
    /// Request a discovered peer key and store it as a local contact.
    Onboard(OnboardArgs),
    /// Receive and persist one encrypted signed message from a known peer.
    Receive(ReceiveArgs),
    /// Send one encrypted signed message to a known peer and persist its ACK.
    Send(SendArgs),
    /// Run a bounded stdin-driven chat session with one trusted contact.
    Chat(ChatArgs),
    /// List known conversations in local storage.
    Conversations,
    /// Show ordered message history for one conversation.
    History(HistoryArgs),
    /// Manage local contact aliases and pinned trust state.
    Contact(ContactArgs),
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct KeygenArgs {
    /// Path where the serialized secret key will be written.
    #[arg(long, value_name = "PATH")]
    pub(crate) secret_key: PathBuf,
    /// Path where the serialized public key will be written.
    #[arg(long, value_name = "PATH")]
    pub(crate) public_key: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct KeyServeArgs {
    /// Path to the serialized local public key.
    #[arg(long, value_name = "PATH")]
    pub(crate) public_key: PathBuf,
    /// TCP address used for key-exchange requests.
    #[arg(long, value_name = "ADDR")]
    pub(crate) listen: SocketAddr,
    /// Bounded service run length in milliseconds.
    #[arg(long, default_value_t = 30_000)]
    pub(crate) duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct KeyRequestArgs {
    /// TCP peer address serving the key-exchange protocol.
    #[arg(long, value_name = "ADDR")]
    pub(crate) peer: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct DiscoverArgs {
    /// Nickname advertised in discovery announcements.
    #[arg(long, default_value = "local")]
    pub(crate) nick: String,
    /// Hex-encoded 32-byte public-key fingerprint to advertise.
    #[arg(
        long,
        value_name = "HEX",
        default_value = "0000000000000000000000000000000000000000000000000000000000000000"
    )]
    pub(crate) fingerprint: String,
    /// TCP port advertised to peers for follow-up direct connections.
    #[arg(long, default_value_t = 0)]
    pub(crate) listen_port: u16,
    /// Local IPv4 interface used for multicast joins and sends.
    #[arg(long, value_name = "IPv4")]
    pub(crate) multicast_interface: Option<Ipv4Addr>,
    /// Bounded discovery run length in milliseconds.
    #[arg(long, default_value_t = 5_000)]
    pub(crate) duration_ms: u64,
    /// Announcement interval in milliseconds.
    #[arg(long, default_value_t = 1_000)]
    pub(crate) announce_interval_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct OnboardArgs {
    /// Stable local alias for this peer.
    #[arg(long, value_name = "ALIAS")]
    pub(crate) alias: String,
    /// Hex-encoded 32-byte fingerprint advertised by discovery.
    #[arg(long, value_name = "HEX")]
    pub(crate) fingerprint: String,
    /// TCP peer address serving the key-exchange protocol.
    #[arg(long, value_name = "ADDR")]
    pub(crate) peer: SocketAddr,
    /// Explicitly trust/pin the fetched key for this alias.
    #[arg(long)]
    pub(crate) trust: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct ReceiveArgs {
    /// Path to the serialized local secret key.
    #[arg(long, value_name = "PATH")]
    pub(crate) secret_key: PathBuf,
    /// Hex-encoded fingerprint of the expected sender public key in storage.
    #[arg(long, value_name = "HEX")]
    pub(crate) peer_fingerprint: String,
    /// TCP address used for one incoming chat message.
    #[arg(long, value_name = "ADDR")]
    pub(crate) listen: SocketAddr,
    /// Expected previous message hash as 64 hex characters.
    #[arg(
        long,
        value_name = "HEX",
        default_value = "0000000000000000000000000000000000000000000000000000000000000000"
    )]
    pub(crate) previous_hash: String,
    /// Bounded receive wait length in milliseconds.
    #[arg(long, default_value_t = 30_000)]
    pub(crate) duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct SendArgs {
    /// Path to the serialized local secret key.
    #[arg(long, value_name = "PATH")]
    pub(crate) secret_key: PathBuf,
    /// Hex-encoded fingerprint of the destination public key in storage.
    #[arg(long, value_name = "HEX")]
    pub(crate) peer_fingerprint: String,
    /// TCP peer address accepting chat messages.
    #[arg(long, value_name = "ADDR")]
    pub(crate) peer: SocketAddr,
    /// Conversation UUID as 32 hex characters or canonical hyphenated UUID.
    #[arg(long, value_name = "UUID")]
    pub(crate) conversation: Option<String>,
    /// Previous message hash as 64 hex characters.
    #[arg(
        long,
        value_name = "HEX",
        default_value = "0000000000000000000000000000000000000000000000000000000000000000"
    )]
    pub(crate) previous_hash: String,
    /// Plaintext message body to encrypt and send.
    #[arg(value_name = "TEXT")]
    pub(crate) message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct ChatArgs {
    /// Path to the serialized local secret key.
    #[arg(long, value_name = "PATH")]
    pub(crate) secret_key: PathBuf,
    /// Trusted contact alias or fingerprint to chat with.
    #[arg(long, value_name = "FINGERPRINT_OR_ALIAS")]
    pub(crate) contact: String,
    /// TCP peer address accepting chat messages.
    #[arg(long, value_name = "ADDR")]
    pub(crate) peer: SocketAddr,
    /// TCP address used to receive chat messages during the session.
    #[arg(long, value_name = "ADDR")]
    pub(crate) listen: SocketAddr,
    /// Conversation UUID as 32 hex characters or canonical hyphenated UUID.
    #[arg(long, value_name = "UUID")]
    pub(crate) conversation: String,
    /// Bounded session length in milliseconds.
    #[arg(long, default_value_t = 30_000)]
    pub(crate) duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct HistoryArgs {
    /// Conversation UUID as 32 hex characters or canonical hyphenated UUID.
    #[arg(long, value_name = "UUID")]
    pub(crate) conversation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct ContactArgs {
    #[command(subcommand)]
    pub(crate) command: ContactCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum ContactCommand {
    /// Add or update a local alias for a peer fingerprint.
    Add(ContactAddArgs),
    /// List local contacts.
    List,
    /// Show one contact by fingerprint or alias.
    Show(ContactLookupArgs),
    /// Mark one contact as explicitly trusted/pinned.
    Trust(ContactLookupArgs),
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct ContactAddArgs {
    /// Stable local alias for this peer.
    #[arg(long, value_name = "ALIAS")]
    pub(crate) alias: String,
    /// Hex-encoded 32-byte peer fingerprint.
    #[arg(long, value_name = "HEX")]
    pub(crate) fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct ContactLookupArgs {
    /// Hex-encoded 32-byte fingerprint or stored alias.
    #[arg(value_name = "FINGERPRINT_OR_ALIAS")]
    pub(crate) query: String,
}
