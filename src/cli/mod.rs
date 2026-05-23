mod args;
mod commands;
mod error;
mod output;
mod parse;
mod status;

pub use args::{
    ChatArgs, Cli, CliCommand, ContactAddArgs, ContactArgs, ContactCommand, ContactLookupArgs,
    DiscoverArgs, HistoryArgs, KeyRequestArgs, KeyServeArgs, KeygenArgs, OnboardArgs, ReceiveArgs,
    SendArgs,
};
pub use commands::run_discovery;
pub use error::CliError;
pub use status::{load_status, write_status, StatusReport};

use crate::config::default_config_path;
use clap::{CommandFactory, Parser};
use std::{ffi::OsString, io::Write, path::PathBuf};

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
        CliCommand::Keygen(args) => commands::run_keygen(args, &mut writer)?,
        CliCommand::KeyServe(args) => {
            let runtime = runtime()?;
            runtime.block_on(commands::run_key_serve(args, &mut writer))?;
        }
        CliCommand::KeyRequest(args) => {
            let runtime = runtime()?;
            runtime.block_on(commands::run_key_request(cli.config_path(), args, &mut writer))?;
        }
        CliCommand::Discover(args) => {
            let runtime = runtime()?;
            runtime.block_on(commands::run_discovery(cli.config_path(), args, &mut writer))?;
        }
        CliCommand::Onboard(args) => {
            let runtime = runtime()?;
            runtime.block_on(commands::run_onboard(cli.config_path(), args, &mut writer))?;
        }
        CliCommand::Receive(args) => {
            let runtime = runtime()?;
            runtime.block_on(commands::run_receive(cli.config_path(), args, &mut writer))?;
        }
        CliCommand::Send(args) => {
            let runtime = runtime()?;
            runtime.block_on(commands::run_send(cli.config_path(), args, &mut writer))?;
        }
        CliCommand::Chat(args) => {
            let runtime = runtime()?;
            runtime.block_on(commands::run_chat(cli.config_path(), args, &mut writer))?;
        }
        CliCommand::Conversations => commands::run_conversations(cli.config_path(), &mut writer)?,
        CliCommand::History(args) => commands::run_history(cli.config_path(), args, &mut writer)?,
        CliCommand::Contact(args) => commands::run_contact(cli.config_path(), args, &mut writer)?,
    }
    Ok(())
}

fn runtime() -> Result<tokio::runtime::Runtime, CliError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CliError::CreateRuntime)
}

#[cfg(test)]
mod tests {
    use super::parse::{
        fingerprint_hex, parse_fingerprint, parse_uuid, uuid_hex, validate_cli_contact_alias,
    };
    use super::*;
    use crate::{
        crypto::{self, public_key_to_bytes, KeyPair},
        discovery::Fingerprint,
        storage::{
            AcceptedChatMessageInsert, MessageAckUpsert, PeerKeyUpsert, ReplyReference, Storage,
        },
    };
    use clap::Parser;
    use std::fs;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::thread;
    use std::time::Duration as StdDuration;

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
        assert!(help.contains("chat"));
        assert!(help.contains("conversations"));
        assert!(help.contains("history"));
        assert!(help.contains("contact"));

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
    fn parses_chat_subcommand_with_bounded_options() {
        let cli = Cli::parse_from([
            "decentra-chat",
            "--config",
            "config.toml",
            "chat",
            "--secret-key",
            "alice.secret",
            "--contact",
            "bob",
            "--peer",
            "127.0.0.1:52001",
            "--listen",
            "127.0.0.1:52002",
            "--conversation",
            "11111111-1111-4111-8111-111111111111",
            "--duration-ms",
            "250",
        ]);

        assert_eq!(
            cli.command(),
            CliCommand::Chat(ChatArgs {
                secret_key: PathBuf::from("alice.secret"),
                contact: "bob".to_owned(),
                peer: "127.0.0.1:52001".parse().expect("socket addr"),
                listen: "127.0.0.1:52002".parse().expect("socket addr"),
                conversation: "11111111-1111-4111-8111-111111111111".to_owned(),
                duration_ms: 250,
            })
        );
    }

    #[test]
    fn parses_history_subcommand_with_conversation_uuid() {
        let cli = Cli::parse_from([
            "decentra-chat",
            "--config",
            "config.toml",
            "history",
            "--conversation",
            "11111111-1111-4111-8111-111111111111",
        ]);

        assert_eq!(
            cli.command(),
            CliCommand::History(HistoryArgs {
                conversation: "11111111-1111-4111-8111-111111111111".to_owned(),
            })
        );
    }

    #[test]
    fn parses_contact_add_subcommand() {
        let cli = Cli::parse_from([
            "decentra-chat",
            "--config",
            "config.toml",
            "contact",
            "add",
            "--alias",
            "alice",
            "--fingerprint",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]);

        assert_eq!(
            cli.command(),
            CliCommand::Contact(ContactArgs {
                command: ContactCommand::Add(ContactAddArgs {
                    alias: "alice".to_owned(),
                    fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned(),
                }),
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
    fn conversations_lists_known_conversations() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage_path = dir.path().join("chat.sqlite3");
        let config_path = write_config(dir.path(), "config.toml", &storage_path);
        let conversation_uuid =
            parse_uuid("11111111-1111-4111-8111-111111111111").expect("conversation uuid");
        Storage::open(&storage_path)
            .expect("open storage")
            .ensure_conversation(conversation_uuid)
            .expect("ensure conversation");
        let mut output = Vec::new();

        run_from(
            [
                "decentra-chat",
                "--config",
                config_path.to_str().expect("utf-8 path"),
                "conversations",
            ],
            &mut output,
        )
        .expect("list conversations");

        let output = String::from_utf8(output).expect("output is UTF-8");
        assert!(output.contains("conversations: 1"));
        assert!(output.contains("conversation_uuid\tcreated_at\tupdated_at"));
        assert!(output.contains("11111111111141118111111111111111"));
    }

    #[test]
    fn contact_commands_add_list_show_and_trust() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage_path = dir.path().join("chat.sqlite3");
        let config_path = write_config(dir.path(), "config.toml", &storage_path);
        let fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut add_output = Vec::new();
        run_from(
            [
                "decentra-chat",
                "--config",
                config_path.to_str().expect("utf-8 path"),
                "contact",
                "add",
                "--alias",
                "alice",
                "--fingerprint",
                fingerprint,
            ],
            &mut add_output,
        )
        .expect("add contact");
        let add_output = String::from_utf8(add_output).expect("output is UTF-8");
        assert!(add_output.contains("contact: stored alias=alice"));
        assert!(add_output.contains("\tfalse\tuntrusted\t"));

        let mut trust_output = Vec::new();
        run_from(
            [
                "decentra-chat",
                "--config",
                config_path.to_str().expect("utf-8 path"),
                "contact",
                "trust",
                "alice",
            ],
            &mut trust_output,
        )
        .expect("trust contact");
        let trust_output = String::from_utf8(trust_output).expect("output is UTF-8");
        assert!(trust_output.contains("contact: trusted alias=alice"));
        assert!(trust_output.contains("\tfalse\ttrusted\t"));

        let mut list_output = Vec::new();
        run_from(
            [
                "decentra-chat",
                "--config",
                config_path.to_str().expect("utf-8 path"),
                "contact",
                "list",
            ],
            &mut list_output,
        )
        .expect("list contacts");
        let list_output = String::from_utf8(list_output).expect("output is UTF-8");
        assert!(list_output.contains("contacts: 1"));
        assert!(list_output.contains("alias\tfingerprint\tpublic_key_present\ttrust_state"));
        assert!(list_output.contains(&format!("alice\t{fingerprint}\tfalse\ttrusted")));

        let mut show_output = Vec::new();
        run_from(
            [
                "decentra-chat",
                "--config",
                config_path.to_str().expect("utf-8 path"),
                "contact",
                "show",
                fingerprint,
            ],
            &mut show_output,
        )
        .expect("show contact");
        let show_output = String::from_utf8(show_output).expect("output is UTF-8");
        assert!(show_output.contains("contact: alias=alice"));
        assert!(show_output.contains(&format!("alice\t{fingerprint}\tfalse\ttrusted")));
    }

    #[test]
    fn contact_alias_conflict_is_actionable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage_path = dir.path().join("chat.sqlite3");
        let config_path = write_config(dir.path(), "config.toml", &storage_path);
        let mut output = Vec::new();
        run_from(
            [
                "decentra-chat",
                "--config",
                config_path.to_str().expect("utf-8 path"),
                "contact",
                "add",
                "--alias",
                "alice",
                "--fingerprint",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ],
            &mut output,
        )
        .expect("add first contact");

        let error = run_from(
            [
                "decentra-chat",
                "--config",
                config_path.to_str().expect("utf-8 path"),
                "contact",
                "add",
                "--alias",
                "ALICE",
                "--fingerprint",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ],
            Vec::new(),
        )
        .expect_err("alias conflict");

        assert!(error.to_string().contains("already belongs to fingerprint"));
    }

    #[test]
    fn invalid_contact_inputs_are_actionable() {
        let error = validate_cli_contact_alias(" alice ".to_owned()).expect_err("invalid alias");
        assert!(error.to_string().contains("without tabs, newlines"));

        let error = parse_fingerprint("not-hex").expect_err("invalid fingerprint");
        assert!(error.to_string().contains("64 hex characters"));
    }

    #[test]
    fn history_displays_empty_conversation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage_path = dir.path().join("chat.sqlite3");
        let config_path = write_config(dir.path(), "config.toml", &storage_path);
        let conversation = "11111111-1111-4111-8111-111111111111";
        Storage::open(&storage_path)
            .expect("open storage")
            .ensure_conversation(parse_uuid(conversation).expect("conversation uuid"))
            .expect("ensure conversation");
        let mut output = Vec::new();

        run_from(
            [
                "decentra-chat",
                "--config",
                config_path.to_str().expect("utf-8 path"),
                "history",
                "--conversation",
                conversation,
            ],
            &mut output,
        )
        .expect("history succeeds");

        let output = String::from_utf8(output).expect("output is UTF-8");
        assert!(output.contains("messages=0"));
        assert!(output.contains(
            "message_uuid\tsender_fingerprint\ttimestamp\tdelivery_state\treply_state\tpayload"
        ));
    }

    #[test]
    fn history_uses_prev_hash_order_and_displays_ack_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage_path = dir.path().join("chat.sqlite3");
        let config_path = write_config(dir.path(), "config.toml", &storage_path);
        let conversation = "11111111-1111-4111-8111-111111111111";
        let conversation_uuid = parse_uuid(conversation).expect("conversation uuid");
        let first_uuid = [0x21; 16];
        let second_uuid = [0x22; 16];
        let first_hash = [0x31; 32];
        let second_hash = [0x32; 32];
        let storage = Storage::open(&storage_path).expect("open storage");
        storage
            .insert_accepted_chat_message(cli_accepted_message(
                conversation_uuid,
                second_uuid,
                first_hash,
                second_hash,
                200,
                b"second",
                None,
            ))
            .expect("insert second");
        storage
            .insert_accepted_chat_message(cli_accepted_message(
                conversation_uuid,
                first_uuid,
                [0; 32],
                first_hash,
                100,
                b"first",
                None,
            ))
            .expect("insert first");
        let ack = storage
            .upsert_message_ack(MessageAckUpsert {
                message_uuid: first_uuid,
                message_hash: first_hash,
                acknowledger: [0x41; 32],
                signature: vec![0x42],
            })
            .expect("insert ack");
        let mut output = Vec::new();

        run_from(
            [
                "decentra-chat",
                "--config",
                config_path.to_str().expect("utf-8 path"),
                "history",
                "--conversation",
                conversation,
            ],
            &mut output,
        )
        .expect("history succeeds");

        let output = String::from_utf8(output).expect("output is UTF-8");
        let first_index = output.find("\tfirst").expect("first payload");
        let second_index = output.find("\tsecond").expect("second payload");
        assert!(first_index < second_index);
        assert!(output.contains(&format!("acknowledged:{}", ack.acknowledged_at)));
        assert!(output.contains("\tunknown\tnone\tsecond"));
    }

    #[test]
    fn history_displays_unresolved_and_invalid_reply_states() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage_path = dir.path().join("chat.sqlite3");
        let config_path = write_config(dir.path(), "config.toml", &storage_path);
        let conversation = "11111111-1111-4111-8111-111111111111";
        let conversation_uuid = parse_uuid(conversation).expect("conversation uuid");
        let target_uuid = [0x51; 16];
        let target_hash = [0x52; 32];
        let unresolved_target = ReplyReference {
            message_uuid: [0x53; 16],
            message_hash: [0x54; 32],
        };
        let invalid_target = ReplyReference {
            message_uuid: target_uuid,
            message_hash: [0x55; 32],
        };
        let storage = Storage::open(&storage_path).expect("open storage");
        storage
            .insert_accepted_chat_message(cli_accepted_message(
                conversation_uuid,
                target_uuid,
                [0; 32],
                target_hash,
                100,
                b"target",
                None,
            ))
            .expect("insert target");
        storage
            .insert_accepted_chat_message(cli_accepted_message(
                conversation_uuid,
                [0x56; 16],
                target_hash,
                [0x57; 32],
                200,
                b"unresolved",
                Some(unresolved_target.clone()),
            ))
            .expect("insert unresolved reply");
        storage
            .insert_accepted_chat_message(cli_accepted_message(
                conversation_uuid,
                [0x58; 16],
                [0x57; 32],
                [0x59; 32],
                300,
                b"invalid",
                Some(invalid_target.clone()),
            ))
            .expect("insert invalid reply");
        let mut output = Vec::new();

        run_from(
            [
                "decentra-chat",
                "--config",
                config_path.to_str().expect("utf-8 path"),
                "history",
                "--conversation",
                conversation,
            ],
            &mut output,
        )
        .expect("history succeeds");

        let output = String::from_utf8(output).expect("output is UTF-8");
        assert!(output.contains(&format!(
            "unresolved:{}:{}",
            uuid_hex(&unresolved_target.message_uuid),
            fingerprint_hex(&unresolved_target.message_hash)
        )));
        assert!(output.contains(&format!(
            "invalid:{}:{}",
            uuid_hex(&invalid_target.message_uuid),
            fingerprint_hex(&invalid_target.message_hash)
        )));
    }

    #[test]
    fn missing_history_conversation_is_actionable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage_path = dir.path().join("chat.sqlite3");
        let config_path = write_config(dir.path(), "config.toml", &storage_path);

        let error = run_from(
            [
                "decentra-chat",
                "--config",
                config_path.to_str().expect("utf-8 path"),
                "history",
                "--conversation",
                "11111111-1111-4111-8111-111111111111",
            ],
            Vec::new(),
        )
        .expect_err("conversation is missing");

        assert!(error.to_string().contains("run `conversations`"));
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

    fn cli_accepted_message(
        conversation_uuid: [u8; 16],
        message_uuid: [u8; 16],
        previous_hash: [u8; 32],
        message_hash: [u8; 32],
        sent_at: i64,
        plaintext: &[u8],
        reply_to: Option<ReplyReference>,
    ) -> AcceptedChatMessageInsert {
        AcceptedChatMessageInsert {
            conversation_uuid,
            message_uuid,
            previous_hash,
            message_hash,
            sender: [0x61; 32],
            sent_at,
            headers: b"Content-Type: text/plain".to_vec(),
            encrypted_payload: vec![0x62],
            decrypted_payload: plaintext.to_vec(),
            reply_to,
        }
    }
}
