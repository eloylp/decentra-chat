use crate::{
    config::{default_config_path, Config, ConfigError},
    crypto::{self, public_key_to_bytes, KeyPair},
    discovery::{
        Discovery, DiscoveryError, DiscoverySettings, Fingerprint, LocalNode, PeerEntry,
    },
    key_exchange::{self, KeyExchangeError, KeyExchangeService, LocalKeyMaterial},
    message_transport::{
        self, ChatMessageService, ChatTransportError, LocalChatIdentity, OutgoingChatMessage,
        PeerChatIdentity,
    },
    storage::{AcceptedChatMessageInsert, Storage, StorageError},
};
use clap::{CommandFactory, Parser, Subcommand};
use pgp::composed::SignedSecretKey;
use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::{
    collections::HashMap,
    ffi::OsString,
    fs,
    io::{self, Write},
    path::PathBuf,
    time::{Duration, Instant},
};
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(
    name = "decentra-chat",
    version,
    about = "Local-first peer-to-peer chat client",
    long_about = "DecentraChat is a local-first peer-to-peer chat client. The current command surface bootstraps configuration, storage diagnostics, and bounded LAN peer discovery."
)]
pub struct Cli {
    /// Path to config.toml. Defaults to DC_CONFIG or the platform config directory.
    #[arg(short, long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<CliCommand>,
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
    /// Receive and persist one encrypted signed message from a known peer.
    Receive(ReceiveArgs),
    /// Send one encrypted signed message to a known peer and persist its ACK.
    Send(SendArgs),
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct KeygenArgs {
    /// Path where the serialized secret key will be written.
    #[arg(long, value_name = "PATH")]
    secret_key: PathBuf,
    /// Path where the serialized public key will be written.
    #[arg(long, value_name = "PATH")]
    public_key: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct KeyServeArgs {
    /// Path to the serialized local public key.
    #[arg(long, value_name = "PATH")]
    public_key: PathBuf,
    /// TCP address used for key-exchange requests.
    #[arg(long, value_name = "ADDR")]
    listen: SocketAddr,
    /// Bounded service run length in milliseconds.
    #[arg(long, default_value_t = 30_000)]
    duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct KeyRequestArgs {
    /// TCP peer address serving the key-exchange protocol.
    #[arg(long, value_name = "ADDR")]
    peer: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct DiscoverArgs {
    /// Nickname advertised in discovery announcements.
    #[arg(long, default_value = "local")]
    nick: String,
    /// Hex-encoded 32-byte public-key fingerprint to advertise.
    #[arg(
        long,
        value_name = "HEX",
        default_value = "0000000000000000000000000000000000000000000000000000000000000000"
    )]
    fingerprint: String,
    /// TCP port advertised to peers for follow-up direct connections.
    #[arg(long, default_value_t = 0)]
    listen_port: u16,
    /// Local IPv4 interface used for multicast joins and sends.
    #[arg(long, value_name = "IPv4")]
    multicast_interface: Option<Ipv4Addr>,
    /// Bounded discovery run length in milliseconds.
    #[arg(long, default_value_t = 5_000)]
    duration_ms: u64,
    /// Announcement interval in milliseconds.
    #[arg(long, default_value_t = 1_000)]
    announce_interval_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct ReceiveArgs {
    /// Path to the serialized local secret key.
    #[arg(long, value_name = "PATH")]
    secret_key: PathBuf,
    /// Hex-encoded fingerprint of the expected sender public key in storage.
    #[arg(long, value_name = "HEX")]
    peer_fingerprint: String,
    /// TCP address used for one incoming chat message.
    #[arg(long, value_name = "ADDR")]
    listen: SocketAddr,
    /// Expected previous message hash as 64 hex characters.
    #[arg(
        long,
        value_name = "HEX",
        default_value = "0000000000000000000000000000000000000000000000000000000000000000"
    )]
    previous_hash: String,
    /// Bounded receive wait length in milliseconds.
    #[arg(long, default_value_t = 30_000)]
    duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct SendArgs {
    /// Path to the serialized local secret key.
    #[arg(long, value_name = "PATH")]
    secret_key: PathBuf,
    /// Hex-encoded fingerprint of the destination public key in storage.
    #[arg(long, value_name = "HEX")]
    peer_fingerprint: String,
    /// TCP peer address accepting chat messages.
    #[arg(long, value_name = "ADDR")]
    peer: SocketAddr,
    /// Conversation UUID as 32 hex characters or canonical hyphenated UUID.
    #[arg(long, value_name = "UUID")]
    conversation: Option<String>,
    /// Previous message hash as 64 hex characters.
    #[arg(
        long,
        value_name = "HEX",
        default_value = "0000000000000000000000000000000000000000000000000000000000000000"
    )]
    previous_hash: String,
    /// Plaintext message body to encrypt and send.
    #[arg(value_name = "TEXT")]
    message: String,
}

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
    #[error("invalid message hash: {0}")]
    InvalidMessageHash(String),
    #[error("invalid conversation UUID: {0}")]
    InvalidConversationUuid(String),
    #[error("peer key {fingerprint} is not in storage; run `key-request --peer <ADDR>` first")]
    MissingPeerKey { fingerprint: String },
    #[error("failed to persist message facts: {0}")]
    PersistMessage(#[source] StorageError),
    #[error("failed to exchange peer key: {0}")]
    KeyExchange(#[from] KeyExchangeError),
    #[error("failed to send or receive encrypted message: {0}")]
    ChatTransport(#[from] ChatTransportError),
    #[error("receive timed out after {duration_ms} ms without an accepted message")]
    ReceiveTimedOut { duration_ms: u64 },
    #[error("failed to write CLI output: {0}")]
    WriteOutput(#[from] io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReport {
    pub config_path: PathBuf,
    pub multicast_group: String,
    pub discovery_port: u16,
    pub listen_addr: String,
    pub storage_path: PathBuf,
}

impl Cli {
    pub fn command_for_help() -> clap::Command {
        <Self as CommandFactory>::command()
    }

    fn command(&self) -> CliCommand {
        self.command.clone().unwrap_or(CliCommand::Status)
    }

    fn config_path(&self) -> PathBuf {
        self.config.clone().unwrap_or_else(default_config_path)
    }
}

pub fn run_from<I, T, W>(args: I, writer: W) -> Result<(), CliError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
    W: Write,
{
    let cli = Cli::parse_from(args);
    run(cli, writer)
}

pub fn run<W: Write>(cli: Cli, mut writer: W) -> Result<(), CliError> {
    match cli.command() {
        CliCommand::Status => {
            let report = load_status(cli.config_path())?;
            write_status(&mut writer, &report)?;
        }
        CliCommand::Keygen(args) => run_keygen(args, &mut writer)?,
        CliCommand::KeyServe(args) => {
            let runtime = runtime()?;
            runtime.block_on(run_key_serve(args, &mut writer))?;
        }
        CliCommand::KeyRequest(args) => {
            let runtime = runtime()?;
            runtime.block_on(run_key_request(cli.config_path(), args, &mut writer))?;
        }
        CliCommand::Discover(args) => {
            let runtime = runtime()?;
            runtime.block_on(run_discovery(cli.config_path(), args, &mut writer))?;
        }
        CliCommand::Receive(args) => {
            let runtime = runtime()?;
            runtime.block_on(run_receive(cli.config_path(), args, &mut writer))?;
        }
        CliCommand::Send(args) => {
            let runtime = runtime()?;
            runtime.block_on(run_send(cli.config_path(), args, &mut writer))?;
        }
    }
    Ok(())
}

fn runtime() -> Result<tokio::runtime::Runtime, CliError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CliError::CreateRuntime)
}

pub fn load_status(config_path: PathBuf) -> Result<StatusReport, CliError> {
    let config = Config::load_from_path(&config_path).map_err(|source| CliError::LoadConfig {
        path: config_path.clone(),
        source,
    })?;

    Storage::open(&config.storage_path).map_err(|source| CliError::InitializeStorage {
        path: config.storage_path.clone(),
        source,
    })?;

    Ok(StatusReport {
        config_path,
        multicast_group: config.multicast_group.to_string(),
        discovery_port: config.discovery_port,
        listen_addr: config.listen_addr.to_string(),
        storage_path: config.storage_path,
    })
}

pub fn write_status<W: Write>(writer: &mut W, report: &StatusReport) -> Result<(), io::Error> {
    writeln!(writer, "DecentraChat status")?;
    writeln!(writer, "config_path: {}", report.config_path.display())?;
    writeln!(writer, "multicast_group: {}", report.multicast_group)?;
    writeln!(writer, "discovery_port: {}", report.discovery_port)?;
    writeln!(writer, "listen_addr: {}", report.listen_addr)?;
    writeln!(writer, "storage_path: {}", report.storage_path.display())?;
    writeln!(writer, "storage: ready")?;
    Ok(())
}

fn run_keygen<W: Write>(args: KeygenArgs, writer: &mut W) -> Result<(), CliError> {
    let keypair = KeyPair::generate().map_err(CliError::Crypto)?;
    let secret = crypto::secret_key_to_bytes(&keypair.secret).map_err(CliError::Crypto)?;
    let public = public_key_to_bytes(&keypair.public).map_err(CliError::Crypto)?;
    write_file(&args.secret_key, &secret)?;
    write_file(&args.public_key, &public)?;

    writeln!(writer, "keygen: wrote secret_key={}", args.secret_key.display())?;
    writeln!(writer, "keygen: wrote public_key={}", args.public_key.display())?;
    writeln!(
        writer,
        "keygen: fingerprint={}",
        fingerprint_hex(&crypto::fingerprint(&public))
    )?;
    Ok(())
}

async fn run_key_serve<W: Write>(
    args: KeyServeArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    if args.duration_ms == 0 {
        return Err(CliError::InvalidKeyServeDuration);
    }
    let public_key = read_file(&args.public_key)?;
    let local_key = LocalKeyMaterial::from_public_key(public_key)?;
    let service = KeyExchangeService::start(args.listen, local_key).await?;

    writeln!(
        writer,
        "key-serve: listening on {} for {} ms",
        service.local_addr(),
        args.duration_ms
    )?;
    tokio::time::sleep(Duration::from_millis(args.duration_ms)).await;
    writeln!(writer, "key-serve: stopped")?;
    Ok(())
}

async fn run_key_request<W: Write>(
    config_path: PathBuf,
    args: KeyRequestArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let storage = open_storage(config_path)?;
    let peer = key_exchange::request_peer_key(args.peer, &storage).await?;

    writeln!(
        writer,
        "key-request: stored peer fingerprint={}",
        fingerprint_hex(&peer.fingerprint)
    )?;
    Ok(())
}

pub async fn run_discovery<W: Write>(
    config_path: PathBuf,
    args: DiscoverArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    if args.duration_ms == 0 {
        return Err(CliError::InvalidDiscoveryDuration);
    }
    if args.announce_interval_ms == 0 {
        return Err(CliError::InvalidAnnounceInterval);
    }

    let config = Config::load_from_path(&config_path).map_err(|source| CliError::LoadConfig {
        path: config_path.clone(),
        source,
    })?;
    Storage::open(&config.storage_path).map_err(|source| CliError::InitializeStorage {
        path: config.storage_path.clone(),
        source,
    })?;

    let multicast_group = require_ipv4("multicast_group", config.multicast_group)?;
    let listen_addr = require_ipv4("listen_addr", config.listen_addr)?;
    let settings = DiscoverySettings::new(multicast_group, config.discovery_port, listen_addr)
        .with_multicast_interface(args.multicast_interface.unwrap_or(Ipv4Addr::UNSPECIFIED))
        .with_announce_interval(Duration::from_millis(args.announce_interval_ms));
    let local_node = LocalNode {
        nick: args.nick.as_bytes().to_vec(),
        listen_port: args.listen_port,
        fingerprint: parse_fingerprint(&args.fingerprint)?,
        public_key_blob: None,
    };

    let discovery = Discovery::start(settings.clone(), local_node).await?;
    writeln!(
        writer,
        "discovery: running for {} ms on {}:{}",
        args.duration_ms, settings.multicast_group, settings.discovery_port
    )?;

    let started = Instant::now();
    let deadline = Duration::from_millis(args.duration_ms);
    let progress_interval = Duration::from_secs(1);
    loop {
        let elapsed = started.elapsed();
        if elapsed >= deadline {
            break;
        }

        let sleep_for = (deadline - elapsed).min(progress_interval);
        tokio::time::sleep(sleep_for).await;
        let elapsed_ms = started.elapsed().min(deadline).as_millis();
        writeln!(writer, "discovery: elapsed_ms={elapsed_ms}")?;
    }

    write_peer_list(writer, &discovery.registry_snapshot(), Instant::now())?;
    Ok(())
}

async fn run_receive<W: Write>(
    config_path: PathBuf,
    args: ReceiveArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    if args.duration_ms == 0 {
        return Err(CliError::InvalidReceiveDuration);
    }

    let storage = open_storage(config_path)?;
    let local = load_local_identity(&args.secret_key)?;
    let peer = load_peer_identity(&storage, &args.peer_fingerprint)?;
    let previous_hash = parse_hash(&args.previous_hash)?;
    let mut service = ChatMessageService::start(args.listen, local, peer, previous_hash).await?;

    writeln!(
        writer,
        "receive: listening on {} for {} ms",
        service.local_addr(),
        args.duration_ms
    )?;
    let received = tokio::time::timeout(
        Duration::from_millis(args.duration_ms),
        service.recv(),
    )
    .await
    .map_err(|_| CliError::ReceiveTimedOut {
        duration_ms: args.duration_ms,
    })?
    .ok_or(CliError::ReceiveTimedOut {
        duration_ms: args.duration_ms,
    })?;

    storage
        .insert_accepted_chat_message(AcceptedChatMessageInsert {
            conversation_uuid: received.conversation_uuid,
            message_uuid: received.uuid,
            previous_hash: received.previous_hash,
            message_hash: received.message_hash,
            sender: received.source,
            sent_at: i64::from(received.timestamp),
            headers: received.headers,
            encrypted_payload: received.encrypted_payload,
            decrypted_payload: received.plaintext,
            reply_to: None,
        })
        .map_err(CliError::PersistMessage)?;

    writeln!(
        writer,
        "receive: accepted message_uuid={} message_hash={}",
        uuid_hex(&received.uuid),
        fingerprint_hex(&received.message_hash)
    )?;
    Ok(())
}

async fn run_send<W: Write>(
    config_path: PathBuf,
    args: SendArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let storage = open_storage(config_path)?;
    let local = load_local_identity(&args.secret_key)?;
    let peer = load_peer_identity(&storage, &args.peer_fingerprint)?;
    let conversation_uuid = match args.conversation {
        Some(value) => parse_uuid(&value)?,
        None => new_uuid_v4(),
    };
    let previous_hash = parse_hash(&args.previous_hash)?;
    let plaintext = args.message.into_bytes();

    let (message, ack) = message_transport::send_chat_message_and_record_ack(
        args.peer,
        &local,
        &peer,
        OutgoingChatMessage {
            conversation_uuid,
            previous_hash,
            headers: b"Content-Type: text/plain".to_vec(),
            plaintext: plaintext.clone(),
        },
        &storage,
    )
    .await?;
    storage
        .insert_accepted_chat_message(AcceptedChatMessageInsert {
            conversation_uuid: message.conv_uuid,
            message_uuid: message.uuid,
            previous_hash: message.prev_hash,
            message_hash: ack.message_hash,
            sender: message.source,
            sent_at: i64::from(message.timestamp),
            headers: message.headers,
            encrypted_payload: message.data,
            decrypted_payload: plaintext,
            reply_to: None,
        })
        .map_err(CliError::PersistMessage)?;

    writeln!(
        writer,
        "send: delivered message_uuid={} acked_by={}",
        uuid_hex(&ack.message_uuid),
        fingerprint_hex(&ack.acknowledger)
    )?;
    Ok(())
}

fn open_storage(config_path: PathBuf) -> Result<Storage, CliError> {
    let config = Config::load_from_path(&config_path).map_err(|source| CliError::LoadConfig {
        path: config_path.clone(),
        source,
    })?;
    Storage::open(&config.storage_path).map_err(|source| CliError::InitializeStorage {
        path: config.storage_path,
        source,
    })
}

fn require_ipv4(field: &'static str, value: IpAddr) -> Result<Ipv4Addr, CliError> {
    match value {
        IpAddr::V4(value) => Ok(value),
        IpAddr::V6(_) => Err(CliError::DiscoveryRequiresIpv4 { field, value }),
    }
}

fn parse_fingerprint(input: &str) -> Result<Fingerprint, CliError> {
    if input.len() != 64 {
        return Err(CliError::InvalidFingerprint(
            "expected exactly 64 hex characters".to_owned(),
        ));
    }

    let mut fingerprint = [0_u8; 32];
    for (index, chunk) in input.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_value(chunk[0]).ok_or_else(|| {
            CliError::InvalidFingerprint(format!(
                "invalid hex character at byte {}",
                index * 2
            ))
        })?;
        let low = hex_value(chunk[1]).ok_or_else(|| {
            CliError::InvalidFingerprint(format!(
                "invalid hex character at byte {}",
                index * 2 + 1
            ))
        })?;
        fingerprint[index] = (high << 4) | low;
    }
    Ok(fingerprint)
}

fn parse_hash(input: &str) -> Result<[u8; 32], CliError> {
    parse_fixed_hex::<32>(input).map_err(CliError::InvalidMessageHash)
}

fn parse_uuid(input: &str) -> Result<[u8; 16], CliError> {
    let mut hex = String::with_capacity(32);
    for byte in input.bytes() {
        if byte != b'-' {
            hex.push(byte as char);
        }
    }
    if hex.len() != 32 {
        return Err(CliError::InvalidConversationUuid(
            "expected 32 hex characters or a hyphenated UUID".to_owned(),
        ));
    }

    let uuid = parse_fixed_hex::<16>(&hex).map_err(CliError::InvalidConversationUuid)?;
    if !is_uuid_v4(&uuid) {
        return Err(CliError::InvalidConversationUuid(
            "expected a non-zero UUID v4".to_owned(),
        ));
    }
    Ok(uuid)
}

fn parse_fixed_hex<const N: usize>(input: &str) -> Result<[u8; N], String> {
    if input.len() != N * 2 {
        return Err(format!("expected exactly {} hex characters", N * 2));
    }

    let mut out = [0_u8; N];
    for (index, chunk) in input.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_value(chunk[0])
            .ok_or_else(|| format!("invalid hex character at byte {}", index * 2))?;
        let low = hex_value(chunk[1])
            .ok_or_else(|| format!("invalid hex character at byte {}", index * 2 + 1))?;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

fn load_local_identity(path: &PathBuf) -> Result<LocalChatIdentity, CliError> {
    let secret_key = load_secret_key(path)?;
    let public_key = signed_public_key_bytes(&secret_key)?;
    Ok(LocalChatIdentity {
        fingerprint: crypto::fingerprint(&public_key),
        secret_key,
    })
}

fn load_secret_key(path: &PathBuf) -> Result<SignedSecretKey, CliError> {
    let bytes = read_file(path)?;
    crypto::secret_key_from_bytes(&bytes).map_err(CliError::Crypto)
}

fn signed_public_key_bytes(secret_key: &SignedSecretKey) -> Result<Vec<u8>, CliError> {
    let public = secret_key.clone().into();
    public_key_to_bytes(&public).map_err(CliError::Crypto)
}

fn load_peer_identity(
    storage: &Storage,
    fingerprint: &str,
) -> Result<PeerChatIdentity, CliError> {
    let parsed = parse_fingerprint(fingerprint)?;
    let Some(record) = storage
        .get_peer_key(parsed)
        .map_err(CliError::PersistMessage)?
    else {
        return Err(CliError::MissingPeerKey {
            fingerprint: fingerprint.to_owned(),
        });
    };
    let public_key =
        crypto::public_key_from_bytes(&record.public_key).map_err(CliError::Crypto)?;
    Ok(PeerChatIdentity {
        fingerprint: record.fingerprint,
        public_key,
    })
}

fn read_file(path: &PathBuf) -> Result<Vec<u8>, CliError> {
    fs::read(path).map_err(|source| CliError::ReadKeyFile {
        path: path.clone(),
        source,
    })
}

fn write_file(path: &PathBuf, bytes: &[u8]) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| CliError::CreateKeyDirectory {
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| CliError::WriteKeyFile {
            path: path.clone(),
            source,
        })?;
    file.write_all(bytes).map_err(|source| CliError::WriteKeyFile {
        path: path.clone(),
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

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn write_peer_list<W: Write>(
    writer: &mut W,
    peers: &HashMap<Fingerprint, PeerEntry>,
    now: Instant,
) -> Result<(), io::Error> {
    writeln!(writer, "peers: {}", peers.len())?;
    writeln!(writer, "nick\tfingerprint\taddress\tlast_seen_ms_ago")?;

    let mut peers = peers.values().collect::<Vec<_>>();
    peers.sort_by(|left, right| {
        left.nick
            .cmp(&right.nick)
            .then_with(|| left.listen_addr.cmp(&right.listen_addr))
            .then_with(|| left.fingerprint.cmp(&right.fingerprint))
    });

    for peer in peers {
        writeln!(
            writer,
            "{}\t{}\t{}\t{}",
            peer.nick,
            fingerprint_hex(&peer.fingerprint),
            peer.listen_addr,
            now.saturating_duration_since(peer.last_seen).as_millis()
        )?;
    }
    Ok(())
}

fn fingerprint_hex(fingerprint: &Fingerprint) -> String {
    let mut output = String::with_capacity(64);
    for byte in fingerprint {
        output.push(nibble_hex(byte >> 4));
        output.push(nibble_hex(byte & 0x0f));
    }
    output
}

fn uuid_hex(uuid: &[u8; 16]) -> String {
    let mut output = String::with_capacity(32);
    for byte in uuid {
        output.push(nibble_hex(byte >> 4));
        output.push(nibble_hex(byte & 0x0f));
    }
    output
}

fn nibble_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => unreachable!("nibble value is always <= 15"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::fs;
    use std::thread;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::time::Duration as StdDuration;
    use crate::storage::PeerKeyUpsert;

    static NEXT_DISCOVERY_PORT: AtomicU16 = AtomicU16::new(43091);
    static NEXT_TCP_PORT: AtomicU16 = AtomicU16::new(51091);

    #[test]
    fn parses_status_subcommand_with_config_path() {
        let cli = Cli::parse_from(["decentra-chat", "--config", "config.toml", "status"]);

        assert_eq!(cli.command(), CliCommand::Status);
        assert_eq!(cli.config_path(), PathBuf::from("config.toml"));
    }

    #[test]
    fn no_arguments_default_to_status() {
        let cli = Cli::parse_from(["decentra-chat"]);

        assert_eq!(cli.command(), CliCommand::Status);
    }

    #[test]
    fn help_output_documents_status_and_config() {
        let mut help = Vec::new();
        Cli::command_for_help()
            .write_long_help(&mut help)
            .expect("write help");
        let help = String::from_utf8(help).expect("help is UTF-8");

        assert!(help.contains("Usage: decentra-chat [OPTIONS] [COMMAND]"));
        assert!(help.contains("--config <PATH>"));
        assert!(help.contains("status"));
        assert!(help.contains("keygen"));
        assert!(help.contains("key-serve"));
        assert!(help.contains("key-request"));
        assert!(help.contains("discover"));
        assert!(help.contains("receive"));
        assert!(help.contains("send"));

        let mut command = Cli::command_for_help();
        let discover = command
            .find_subcommand_mut("discover")
            .expect("discover subcommand");
        let mut discover_help = Vec::new();
        discover
            .write_long_help(&mut discover_help)
            .expect("write discover help");
        let discover_help = String::from_utf8(discover_help).expect("help is UTF-8");

        assert!(discover_help.contains("--duration-ms <DURATION_MS>"));
    }

    #[test]
    fn parses_send_subcommand_with_message_options() {
        let cli = Cli::parse_from([
            "decentra-chat",
            "--config",
            "config.toml",
            "send",
            "--secret-key",
            "alice.secret",
            "--peer-fingerprint",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--peer",
            "127.0.0.1:52001",
            "--conversation",
            "11111111-1111-4111-8111-111111111111",
            "--previous-hash",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "hello bob",
        ]);

        assert_eq!(
            cli.command(),
            CliCommand::Send(SendArgs {
                secret_key: PathBuf::from("alice.secret"),
                peer_fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
                peer: "127.0.0.1:52001".parse().expect("socket addr"),
                conversation: Some("11111111-1111-4111-8111-111111111111".to_owned()),
                previous_hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_owned(),
                message: "hello bob".to_owned(),
            })
        );
    }

    #[test]
    fn status_opens_storage_and_prints_non_secret_settings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage_path = dir.path().join("state").join("chat.sqlite3");
        let config_path = dir.path().join("config.toml");
        fs::write(
            &config_path,
            format!(
                r#"
multicast_group = "239.255.40.92"
discovery_port = 41000
listen_addr = "127.0.0.1"
storage_path = "{}"
"#,
                storage_path.display()
            ),
        )
        .expect("write config");
        let mut output = Vec::new();

        run_from(
            [
                "decentra-chat",
                "--config",
                config_path.to_str().expect("utf-8 path"),
                "status",
            ],
            &mut output,
        )
        .expect("status succeeds");

        assert!(storage_path.exists());
        let output = String::from_utf8(output).expect("status output is UTF-8");
        assert!(output.contains("DecentraChat status"));
        assert!(output.contains("multicast_group: 239.255.40.92"));
        assert!(output.contains("discovery_port: 41000"));
        assert!(output.contains("listen_addr: 127.0.0.1"));
        assert!(output.contains(&format!("storage_path: {}", storage_path.display())));
        assert!(output.contains("storage: ready"));
    }

    #[test]
    fn invalid_config_error_names_path_and_field() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.toml");
        fs::write(&config_path, "multicast_group = \"not an ip\"\n").expect("write config");

        let error = load_status(config_path.clone()).expect_err("config is invalid");
        let error = error.to_string();

        assert!(error.contains(&config_path.display().to_string()));
        assert!(error.contains("multicast_group"));
        assert!(error.contains("valid IP address"));
    }

    #[test]
    fn parses_discover_subcommand_with_bounded_options() {
        let cli = Cli::parse_from([
            "decentra-chat",
            "--config",
            "config.toml",
            "discover",
            "--nick",
            "alice",
            "--fingerprint",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--listen-port",
            "51001",
            "--multicast-interface",
            "127.0.0.1",
            "--duration-ms",
            "25",
            "--announce-interval-ms",
            "10",
        ]);

        assert_eq!(
            cli.command(),
            CliCommand::Discover(DiscoverArgs {
                nick: "alice".to_owned(),
                fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
                listen_port: 51001,
                multicast_interface: Some(Ipv4Addr::LOCALHOST),
                duration_ms: 25,
                announce_interval_ms: 10,
            })
        );
    }

    #[test]
    fn bounded_discover_prints_progress_and_peer_list() {
        let port = NEXT_DISCOVERY_PORT.fetch_add(1, Ordering::Relaxed);
        let dir = tempfile::tempdir().expect("tempdir");
        let storage_path = dir.path().join("state").join("chat.sqlite3");
        let config_path = dir.path().join("config.toml");
        fs::write(
            &config_path,
            format!(
                r#"
multicast_group = "239.255.40.91"
discovery_port = {port}
listen_addr = "127.0.0.1"
storage_path = "{}"
"#,
                storage_path.display()
            ),
        )
        .expect("write config");
        let fingerprint = "1111111111111111111111111111111111111111111111111111111111111111";
        let mut output = Vec::new();

        run_from(
            [
                "decentra-chat",
                "--config",
                config_path.to_str().expect("utf-8 path"),
                "discover",
                "--nick",
                "alice",
                "--fingerprint",
                fingerprint,
                "--listen-port",
                "51001",
                "--multicast-interface",
                "127.0.0.1",
                "--duration-ms",
                "150",
                "--announce-interval-ms",
                "25",
            ],
            &mut output,
        )
        .expect("bounded discovery succeeds");

        let output = String::from_utf8(output).expect("discovery output is UTF-8");
        assert!(output.contains("discovery: running for 150 ms"));
        assert!(output.contains("discovery: elapsed_ms="));
        assert!(output.contains("peers:"));
        assert!(output.contains("nick\tfingerprint\taddress\tlast_seen_ms_ago"));
        assert!(output.contains("alice"));
        assert!(output.contains(fingerprint));
        assert!(output.contains("127.0.0.1:51001"));
    }

    #[test]
    fn invalid_discovery_fingerprint_is_actionable() {
        let error = parse_fingerprint("not-hex").expect_err("fingerprint is invalid");

        assert!(error.to_string().contains("64 hex characters"));
    }

    #[test]
    fn send_without_stored_peer_key_is_actionable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (secret_key, _public_key, _fingerprint) = write_identity(dir.path(), "alice");
        let storage_path = dir.path().join("state").join("sender.sqlite3");
        let config_path = write_config(dir.path(), "sender.toml", &storage_path);
        let mut output = Vec::new();

        let error = run_from(
            [
                "decentra-chat",
                "--config",
                config_path.to_str().expect("utf-8 path"),
                "send",
                "--secret-key",
                secret_key.to_str().expect("utf-8 path"),
                "--peer-fingerprint",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--peer",
                "127.0.0.1:1",
                "hello",
            ],
            &mut output,
        )
        .expect_err("peer key is missing");

        assert!(error.to_string().contains("run `key-request --peer <ADDR>` first"));
    }

    #[test]
    fn bounded_cli_send_receive_loopback_persists_messages_and_ack() {
        let port = NEXT_TCP_PORT.fetch_add(1, Ordering::Relaxed);
        let addr = format!("127.0.0.1:{port}");
        let dir = tempfile::tempdir().expect("tempdir");
        let (alice_secret, alice_public, alice_fingerprint) = write_identity(dir.path(), "alice");
        let (bob_secret, bob_public, bob_fingerprint) = write_identity(dir.path(), "bob");
        let sender_storage_path = dir.path().join("sender.sqlite3");
        let receiver_storage_path = dir.path().join("receiver.sqlite3");
        let sender_config = write_config(dir.path(), "sender.toml", &sender_storage_path);
        let receiver_config = write_config(dir.path(), "receiver.toml", &receiver_storage_path);
        seed_peer_key(&sender_storage_path, bob_fingerprint, &bob_public);
        seed_peer_key(&receiver_storage_path, alice_fingerprint, &alice_public);
        let conversation = "11111111-1111-4111-8111-111111111111";

        let receiver_config_for_thread = receiver_config.clone();
        let bob_secret_for_thread = bob_secret.clone();
        let alice_fingerprint_arg = fingerprint_hex(&alice_fingerprint);
        let addr_for_thread = addr.clone();
        let receiver = thread::spawn(move || {
            let mut output = Vec::new();
            let result = run_from(
                [
                    "decentra-chat",
                    "--config",
                    receiver_config_for_thread.to_str().expect("utf-8 path"),
                    "receive",
                    "--secret-key",
                    bob_secret_for_thread.to_str().expect("utf-8 path"),
                    "--peer-fingerprint",
                    &alice_fingerprint_arg,
                    "--listen",
                    &addr_for_thread,
                    "--duration-ms",
                    "5000",
                ],
                &mut output,
            );
            (result, String::from_utf8(output).expect("receive output is UTF-8"))
        });
        thread::sleep(StdDuration::from_millis(500));

        let mut sender_output = Vec::new();
        run_from(
            [
                "decentra-chat",
                "--config",
                sender_config.to_str().expect("utf-8 path"),
                "send",
                "--secret-key",
                alice_secret.to_str().expect("utf-8 path"),
                "--peer-fingerprint",
                &fingerprint_hex(&bob_fingerprint),
                "--peer",
                &addr,
                "--conversation",
                conversation,
                "hello bob",
            ],
            &mut sender_output,
        )
        .expect("send succeeds");
        let (receive_result, receiver_output) = receiver.join().expect("receive thread joins");
        receive_result.expect("receive succeeds");

        let sender_output = String::from_utf8(sender_output).expect("send output is UTF-8");
        assert!(sender_output.contains("send: delivered"));
        assert!(receiver_output.contains("receive: accepted"));

        let conversation_uuid = parse_uuid(conversation).expect("conversation uuid");
        let sender_storage = Storage::open(&sender_storage_path).expect("open sender storage");
        let receiver_storage = Storage::open(&receiver_storage_path).expect("open receiver storage");
        let sender_messages = sender_storage
            .accepted_messages_by_conversation(conversation_uuid)
            .expect("sender messages");
        let receiver_messages = receiver_storage
            .accepted_messages_by_conversation(conversation_uuid)
            .expect("receiver messages");

        assert_eq!(sender_messages.len(), 1);
        assert_eq!(receiver_messages.len(), 1);
        assert_eq!(sender_messages[0].decrypted_payload, b"hello bob");
        assert_eq!(receiver_messages[0].decrypted_payload, b"hello bob");
        assert_eq!(sender_messages[0].acknowledged_at.is_some(), true);
        assert_eq!(receiver_messages[0].acknowledged_at, None);
    }

    fn write_identity(
        dir: &std::path::Path,
        name: &str,
    ) -> (PathBuf, PathBuf, Fingerprint) {
        let keypair = KeyPair::generate().expect("generate keypair");
        let secret = crypto::secret_key_to_bytes(&keypair.secret).expect("serialize secret");
        let public = public_key_to_bytes(&keypair.public).expect("serialize public");
        let secret_path = dir.join(format!("{name}.secret"));
        let public_path = dir.join(format!("{name}.public"));
        fs::write(&secret_path, secret).expect("write secret");
        fs::write(&public_path, &public).expect("write public");
        (secret_path, public_path, crypto::fingerprint(&public))
    }

    fn write_config(
        dir: &std::path::Path,
        name: &str,
        storage_path: &std::path::Path,
    ) -> PathBuf {
        let config_path = dir.join(name);
        fs::write(
            &config_path,
            format!(
                r#"
multicast_group = "239.255.40.91"
discovery_port = 44091
listen_addr = "127.0.0.1"
storage_path = "{}"
"#,
                storage_path.display()
            ),
        )
        .expect("write config");
        config_path
    }

    fn seed_peer_key(
        storage_path: &std::path::Path,
        fingerprint: Fingerprint,
        public_key_path: &std::path::Path,
    ) {
        let storage = Storage::open(storage_path).expect("open storage");
        storage
            .upsert_peer_key(PeerKeyUpsert {
                fingerprint,
                nick: None,
                public_key: fs::read(public_key_path).expect("read public key"),
                last_seen: 1,
            })
            .expect("seed peer key");
    }
}
