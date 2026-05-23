use super::CliError;
use crate::{
    config::Config,
    crypto::{self, public_key_to_bytes},
    discovery::Fingerprint,
    hex,
    message_transport::{LocalChatIdentity, PeerChatIdentity},
    storage::Storage,
    uuid,
};
use pgp::composed::SignedSecretKey;
use std::{
    fs,
    io::Write,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

pub(super) fn open_storage(config_path: PathBuf) -> Result<Storage, CliError> {
    let config = Config::load_from_path(&config_path).map_err(|source| CliError::LoadConfig {
        path: config_path.clone(),
        source,
    })?;
    Storage::open(&config.storage_path).map_err(|source| CliError::InitializeStorage {
        path: config.storage_path,
        source,
    })
}

pub(super) fn require_ipv4(field: &'static str, value: IpAddr) -> Result<Ipv4Addr, CliError> {
    match value {
        IpAddr::V4(value) => Ok(value),
        IpAddr::V6(_) => Err(CliError::DiscoveryRequiresIpv4 { field, value }),
    }
}

pub(super) fn parse_fingerprint(input: &str) -> Result<Fingerprint, CliError> {
    hex::parse_fixed_hex(input).map_err(CliError::InvalidFingerprint)
}

pub(super) fn validate_cli_contact_alias(alias: String) -> Result<String, CliError> {
    if alias.is_empty()
        || alias.trim() != alias
        || alias.len() > 64
        || alias
            .chars()
            .any(|character| character.is_control() || character == '\t')
    {
        return Err(CliError::InvalidContactAlias { alias });
    }
    Ok(alias)
}

pub(super) fn parse_hash(input: &str) -> Result<[u8; 32], CliError> {
    hex::parse_fixed_hex(input).map_err(CliError::InvalidMessageHash)
}

pub(super) fn parse_uuid(input: &str) -> Result<[u8; 16], CliError> {
    let uuid = hex::parse_hyphenated_fixed_hex(
        input,
        "expected 32 hex characters or a hyphenated UUID",
    )
    .map_err(CliError::InvalidConversationUuid)?;
    if !uuid::is_uuid_v4(&uuid) {
        return Err(CliError::InvalidConversationUuid(
            "expected a non-zero UUID v4".to_owned(),
        ));
    }
    Ok(uuid)
}

pub(super) fn load_local_identity(path: &PathBuf) -> Result<LocalChatIdentity, CliError> {
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

pub(super) fn load_peer_identity(
    storage: &Storage,
    fingerprint: &str,
) -> Result<PeerChatIdentity, CliError> {
    let parsed = parse_fingerprint(fingerprint)?;
    load_peer_identity_from_fingerprint(storage, parsed)
}

pub(super) fn load_peer_identity_from_fingerprint(
    storage: &Storage,
    fingerprint: Fingerprint,
) -> Result<PeerChatIdentity, CliError> {
    let Some(record) = storage
        .get_peer_key(fingerprint)
        .map_err(CliError::PersistMessage)?
    else {
        return Err(CliError::MissingPeerKey {
            fingerprint: fingerprint_hex(&fingerprint),
        });
    };
    let public_key =
        crypto::public_key_from_bytes(&record.public_key).map_err(CliError::Crypto)?;
    Ok(PeerChatIdentity {
        fingerprint: record.fingerprint,
        public_key,
    })
}

pub(super) fn read_file(path: &PathBuf) -> Result<Vec<u8>, CliError> {
    fs::read(path).map_err(|source| CliError::ReadKeyFile {
        path: path.clone(),
        source,
    })
}

pub(super) fn write_file(path: &PathBuf, bytes: &[u8]) -> Result<(), CliError> {
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

pub(super) fn fingerprint_hex(fingerprint: &Fingerprint) -> String {
    hex::lower_hex(fingerprint)
}

pub(super) fn uuid_hex(uuid: &[u8; 16]) -> String {
    hex::lower_hex(uuid)
}
