use crate::{
    config::{default_config_path, Config, ConfigError},
    discovery::{
        Discovery, DiscoveryError, DiscoverySettings, Fingerprint, LocalNode, PeerEntry,
    },
    storage::{Storage, StorageError},
};
use clap::{CommandFactory, Parser, Subcommand};
use std::net::{IpAddr, Ipv4Addr};
use std::{
    collections::HashMap,
    ffi::OsString,
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
    /// Run bounded UDP multicast discovery and print the visible peer list.
    Discover(DiscoverArgs),
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
        CliCommand::Discover(args) => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(CliError::CreateRuntime)?;
            runtime.block_on(run_discovery(cli.config_path(), args, &mut writer))?;
        }
    }
    Ok(())
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
    use std::sync::atomic::{AtomicU16, Ordering};

    static NEXT_DISCOVERY_PORT: AtomicU16 = AtomicU16::new(43091);

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
        assert!(help.contains("discover"));

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
}
