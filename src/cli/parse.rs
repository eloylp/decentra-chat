use super::CliError;
use crate::{
    config::Config,
    crypto::{self, public_key_to_bytes},
    discovery::Fingerprint,
    message_transport::{LocalChatIdentity, PeerChatIdentity},
    storage::Storage,
};
use pgp::composed::SignedSecretKey;
use rand::RngCore;
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
    parse_fixed_hex::<32>(input).map_err(CliError::InvalidMessageHash)
}

pub(super) fn parse_uuid(input: &str) -> Result<[u8; 16], CliError> {
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

pub(super) fn new_uuid_v4() -> [u8; 16] {
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

pub(super) fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(super) fn fingerprint_hex(fingerprint: &Fingerprint) -> String {
    let mut output = String::with_capacity(64);
    for byte in fingerprint {
        output.push(nibble_hex(byte >> 4));
        output.push(nibble_hex(byte & 0x0f));
    }
    output
}

pub(super) fn uuid_hex(uuid: &[u8; 16]) -> String {
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
