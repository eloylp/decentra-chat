use crate::discovery::Fingerprint;
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

const MIGRATION_001: &str = "001_peer_keys";

/// SQLite-backed local storage for DecentraChat peer data.
pub struct Storage {
    connection: Connection,
}

/// Peer public-key material persisted for key exchange and later messaging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerKeyRecord {
    pub fingerprint: Fingerprint,
    pub nick: Option<String>,
    pub public_key: Vec<u8>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub updated_at: i64,
}

/// Data accepted by the peer-key repository upsert operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerKeyUpsert {
    pub fingerprint: Fingerprint,
    pub nick: Option<String>,
    pub public_key: Vec<u8>,
    pub last_seen: i64,
}

/// Errors returned by SQLite storage initialization and repository operations.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("failed to create storage directory at {path}: {source}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to open SQLite database at {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("failed to apply SQLite migrations: {0}")]
    Migration(#[source] rusqlite::Error),
    #[error("failed to access peer key storage: {0}")]
    Repository(#[source] rusqlite::Error),
    #[error("peer public key must not be empty")]
    EmptyPublicKey,
    #[error("stored peer fingerprint must be 32 bytes, got {len}")]
    InvalidFingerprintLength { len: usize },
    #[error("system clock is before the Unix epoch")]
    InvalidSystemTime,
}

impl Storage {
    /// Open the SQLite database at `path` and apply all idempotent migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| StorageError::CreateDirectory {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
        }

        let mut connection = Connection::open(path).map_err(|source| StorageError::Open {
            path: path.to_path_buf(),
            source,
        })?;
        apply_migrations(&mut connection)?;

        Ok(Self { connection })
    }

    /// Insert or update a peer public key, preserving the original first-seen timestamp.
    pub fn upsert_peer_key(
        &self,
        upsert: PeerKeyUpsert,
    ) -> Result<PeerKeyRecord, StorageError> {
        if upsert.public_key.is_empty() {
            return Err(StorageError::EmptyPublicKey);
        }

        let now = unix_timestamp()?;
        self.connection
            .execute(
                "INSERT INTO peer_keys (
                    fingerprint, nick, public_key, first_seen, last_seen, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    nick = excluded.nick,
                    public_key = excluded.public_key,
                    last_seen = excluded.last_seen,
                    updated_at = excluded.updated_at",
                params![
                    &upsert.fingerprint[..],
                    upsert.nick.as_deref(),
                    upsert.public_key,
                    upsert.last_seen,
                    upsert.last_seen,
                    now,
                ],
            )
            .map_err(StorageError::Repository)?;

        self.get_peer_key(upsert.fingerprint)?
            .ok_or_else(|| StorageError::Repository(rusqlite::Error::QueryReturnedNoRows))
    }

    /// Fetch a peer public key by its stable DecentraChat fingerprint.
    pub fn get_peer_key(
        &self,
        fingerprint: Fingerprint,
    ) -> Result<Option<PeerKeyRecord>, StorageError> {
        self.connection
            .query_row(
                "SELECT fingerprint, nick, public_key, first_seen, last_seen, updated_at
                 FROM peer_keys
                 WHERE fingerprint = ?1",
                params![&fingerprint[..]],
                row_to_peer_key,
            )
            .optional()
            .map_err(StorageError::Repository)?
            .map(validate_record)
            .transpose()
    }
}

fn apply_migrations(connection: &mut Connection) -> Result<(), StorageError> {
    let transaction = connection.transaction().map_err(StorageError::Migration)?;

    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                name TEXT PRIMARY KEY,
                applied_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS peer_keys (
                fingerprint BLOB PRIMARY KEY CHECK(length(fingerprint) = 32),
                nick TEXT,
                public_key BLOB NOT NULL CHECK(length(public_key) > 0),
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_peer_keys_last_seen
                ON peer_keys(last_seen);",
        )
        .map_err(StorageError::Migration)?;

    transaction
        .execute(
            "INSERT OR IGNORE INTO schema_migrations (name, applied_at) VALUES (?1, ?2)",
            params![MIGRATION_001, unix_timestamp()?],
        )
        .map_err(StorageError::Migration)?;

    transaction.commit().map_err(StorageError::Migration)
}

fn row_to_peer_key(row: &rusqlite::Row<'_>) -> rusqlite::Result<PeerKeyRecord> {
    Ok(PeerKeyRecord {
        fingerprint: vec_to_fingerprint(row.get(0)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                32,
                rusqlite::types::Type::Blob,
                Box::new(error),
            )
        })?,
        nick: row.get(1)?,
        public_key: row.get(2)?,
        first_seen: row.get(3)?,
        last_seen: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

fn validate_record(record: PeerKeyRecord) -> Result<PeerKeyRecord, StorageError> {
    if record.public_key.is_empty() {
        return Err(StorageError::EmptyPublicKey);
    }
    Ok(record)
}

fn vec_to_fingerprint(bytes: Vec<u8>) -> Result<Fingerprint, StorageError> {
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| StorageError::InvalidFingerprintLength { len: bytes.len() })
}

fn unix_timestamp() -> Result<i64, StorageError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StorageError::InvalidSystemTime)?;
    i64::try_from(duration.as_secs()).map_err(|_| StorageError::InvalidSystemTime)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upsert(fingerprint: Fingerprint, nick: Option<&str>, last_seen: i64) -> PeerKeyUpsert {
        PeerKeyUpsert {
            fingerprint,
            nick: nick.map(str::to_owned),
            public_key: vec![1, 2, 3, 4],
            last_seen,
        }
    }

    #[test]
    fn open_creates_migration_tables() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("nested").join("dc.sqlite3");

        let storage = Storage::open(&db_path).expect("open storage");

        let migration_count: i64 = storage
            .connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE name = ?1",
                params![MIGRATION_001],
                |row| row.get(0),
            )
            .expect("query migration count");
        assert_eq!(migration_count, 1);
        assert!(db_path.exists());
    }

    #[test]
    fn migrations_are_idempotent_on_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("dc.sqlite3");

        Storage::open(&db_path).expect("first open");
        let storage = Storage::open(&db_path).expect("second open");

        let migration_count: i64 = storage
            .connection
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| row.get(0))
            .expect("query migration count");
        assert_eq!(migration_count, 1);
    }

    #[test]
    fn insert_and_fetch_peer_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");
        let fingerprint = [0xaa; 32];

        let record = storage
            .upsert_peer_key(upsert(fingerprint, Some("alice"), 100))
            .expect("insert peer key");
        let fetched = storage
            .get_peer_key(fingerprint)
            .expect("fetch peer key")
            .expect("stored key");

        assert_eq!(record, fetched);
        assert_eq!(fetched.fingerprint, fingerprint);
        assert_eq!(fetched.nick.as_deref(), Some("alice"));
        assert_eq!(fetched.public_key, vec![1, 2, 3, 4]);
        assert_eq!(fetched.first_seen, 100);
        assert_eq!(fetched.last_seen, 100);
    }

    #[test]
    fn update_preserves_first_seen_and_replaces_key_material() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");
        let fingerprint = [0xbb; 32];

        let initial = storage
            .upsert_peer_key(upsert(fingerprint, Some("alice"), 100))
            .expect("insert peer key");
        let updated = storage
            .upsert_peer_key(PeerKeyUpsert {
                fingerprint,
                nick: Some("alice-new".to_owned()),
                public_key: vec![9, 8, 7],
                last_seen: 250,
            })
            .expect("update peer key");

        assert_eq!(updated.first_seen, initial.first_seen);
        assert_eq!(updated.last_seen, 250);
        assert_eq!(updated.nick.as_deref(), Some("alice-new"));
        assert_eq!(updated.public_key, vec![9, 8, 7]);
        assert!(updated.updated_at >= initial.updated_at);
    }

    #[test]
    fn fetch_missing_peer_key_returns_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");

        let fetched = storage
            .get_peer_key([0xcc; 32])
            .expect("fetch missing peer key");

        assert_eq!(fetched, None);
    }

    #[test]
    fn empty_public_key_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");

        let error = storage
            .upsert_peer_key(PeerKeyUpsert {
                fingerprint: [0xdd; 32],
                nick: None,
                public_key: Vec::new(),
                last_seen: 100,
            })
            .expect_err("empty public key is invalid");

        assert!(matches!(error, StorageError::EmptyPublicKey));
    }
}
