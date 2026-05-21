use crate::{
    config::{default_config_path, Config, ConfigError},
    storage::{Storage, StorageError},
};
use clap::{CommandFactory, Parser, Subcommand};
use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
};
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(
    name = "decentra-chat",
    version,
    about = "Local-first peer-to-peer chat client",
    long_about = "DecentraChat is a local-first peer-to-peer chat client. The current command surface bootstraps configuration and storage diagnostics without starting network services."
)]
pub struct Cli {
    /// Path to config.toml. Defaults to DC_CONFIG or the platform config directory.
    #[arg(short, long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Subcommand)]
pub enum CliCommand {
    /// Load config, apply storage migrations, and print non-secret node settings.
    Status,
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
        self.command.unwrap_or(CliCommand::Status)
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::fs;

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
}
