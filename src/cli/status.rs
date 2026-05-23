use super::CliError;
use crate::{config::Config, storage::Storage};
use std::{io, io::Write, path::PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReport {
    pub config_path: PathBuf,
    pub multicast_group: String,
    pub discovery_port: u16,
    pub listen_addr: String,
    pub storage_path: PathBuf,
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
