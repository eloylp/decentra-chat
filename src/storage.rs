use crate::{discovery::Fingerprint, hex, time};
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

const MIGRATION_001: &str = "001_peer_keys";
const MIGRATION_002: &str = "002_message_acks";
const MIGRATION_003: &str = "003_conversation_messages";
const MIGRATION_004: &str = "004_reply_metadata";
const MIGRATION_005: &str = "005_contacts";

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

/// Local trust state for a pinned contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactTrustState {
    Untrusted,
    Trusted,
}

impl ContactTrustState {
    fn from_str(value: &str) -> Result<Self, StorageError> {
        match value {
            "untrusted" => Ok(Self::Untrusted),
            "trusted" => Ok(Self::Trusted),
            value => Err(StorageError::InvalidContactTrustState {
                value: value.to_owned(),
            }),
        }
    }
}

/// SQLite-backed contact and fingerprint-pinning record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRecord {
    pub alias: String,
    pub fingerprint: Fingerprint,
    pub public_key_present: bool,
    pub trust_state: ContactTrustState,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Data accepted by the contact repository upsert operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactUpsert {
    pub alias: String,
    pub fingerprint: Fingerprint,
}

/// Persisted delivery acknowledgement for one outbound chat message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageAckRecord {
    pub message_uuid: [u8; 16],
    pub message_hash: [u8; 32],
    pub acknowledger: Fingerprint,
    pub signature: Vec<u8>,
    pub acknowledged_at: i64,
}

/// Persisted conversation metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationRecord {
    pub conversation_uuid: [u8; 16],
    pub created_at: i64,
    pub updated_at: i64,
}

/// Data accepted by the ACK repository upsert operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageAckUpsert {
    pub message_uuid: [u8; 16],
    pub message_hash: [u8; 32],
    pub acknowledger: Fingerprint,
    pub signature: Vec<u8>,
}

/// Signed reply target metadata extracted from accepted chat-message headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyReference {
    pub message_uuid: [u8; 16],
    pub message_hash: [u8; 32],
}

/// Accepted chat message persisted for conversation reconstruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedChatMessageRecord {
    pub conversation_uuid: [u8; 16],
    pub message_uuid: [u8; 16],
    pub previous_hash: [u8; 32],
    pub message_hash: [u8; 32],
    pub sender: Fingerprint,
    pub sent_at: i64,
    pub received_at: i64,
    pub headers: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
    pub decrypted_payload: Vec<u8>,
    pub acknowledged_at: Option<i64>,
    pub reply_to: Option<ReplyReference>,
}

/// Data accepted by the conversation-message repository insert operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedChatMessageInsert {
    pub conversation_uuid: [u8; 16],
    pub message_uuid: [u8; 16],
    pub previous_hash: [u8; 32],
    pub message_hash: [u8; 32],
    pub sender: Fingerprint,
    pub sent_at: i64,
    pub headers: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
    pub decrypted_payload: Vec<u8>,
    pub reply_to: Option<ReplyReference>,
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
    #[error("contact alias must not be empty")]
    EmptyContactAlias,
    #[error(
        "contact alias `{alias}` is invalid: use 1-64 visible characters without tabs, newlines, or leading/trailing spaces"
    )]
    InvalidContactAlias { alias: String },
    #[error("contact alias `{alias}` already belongs to fingerprint {existing_fingerprint}")]
    ContactAliasConflict {
        alias: String,
        existing_fingerprint: String,
    },
    #[error("stored contact trust state `{value}` is unsupported")]
    InvalidContactTrustState { value: String },
    #[error("message ACK signature must not be empty")]
    EmptyAckSignature,
    #[error("stored message UUID must be 16 bytes, got {len}")]
    InvalidMessageUuidLength { len: usize },
    #[error("stored message hash must be 32 bytes, got {len}")]
    InvalidMessageHashLength { len: usize },
    #[error("stored peer fingerprint must be 32 bytes, got {len}")]
    InvalidFingerprintLength { len: usize },
    #[error("accepted chat message encrypted payload must not be empty")]
    EmptyEncryptedPayload,
    #[error("message UUID already exists with a different message hash")]
    DuplicateMessageUuid,
    #[error("message hash already exists for a different message UUID")]
    DuplicateMessageHash,
    #[error("conversation message chain cannot be resolved for conversation UUID")]
    UnresolvedConversationChain,
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
        self.connection
            .execute(
                "UPDATE contacts
                 SET public_key_present = 1,
                     updated_at = MAX(updated_at, ?2)
                 WHERE fingerprint = ?1",
                params![&upsert.fingerprint[..], now],
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

    /// Insert or update a contact alias for a fingerprint.
    pub fn upsert_contact(
        &self,
        upsert: ContactUpsert,
    ) -> Result<ContactRecord, StorageError> {
        let alias = validate_contact_alias(upsert.alias)?;
        if let Some(existing) = self.get_contact_by_alias(&alias)? {
            if existing.fingerprint != upsert.fingerprint {
                return Err(StorageError::ContactAliasConflict {
                    alias,
                    existing_fingerprint: fingerprint_hex(&existing.fingerprint),
                });
            }
        }

        let now = unix_timestamp()?;
        let public_key_present = self.peer_key_exists(upsert.fingerprint)?;
        self.connection
            .execute(
                "INSERT INTO contacts (
                    fingerprint, alias, public_key_present, trust_state, created_at, updated_at
                ) VALUES (?1, ?2, ?3, 'untrusted', ?4, ?4)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    alias = excluded.alias,
                    public_key_present = excluded.public_key_present,
                    updated_at = excluded.updated_at",
                params![
                    &upsert.fingerprint[..],
                    alias,
                    public_key_present,
                    now,
                ],
            )
            .map_err(StorageError::Repository)?;

        self.get_contact_by_fingerprint(upsert.fingerprint)?
            .ok_or_else(|| StorageError::Repository(rusqlite::Error::QueryReturnedNoRows))
    }

    /// Mark a contact as explicitly trusted/pinned.
    pub fn trust_contact(
        &self,
        fingerprint: Fingerprint,
    ) -> Result<Option<ContactRecord>, StorageError> {
        let now = unix_timestamp()?;
        self.connection
            .execute(
                "UPDATE contacts
                 SET trust_state = 'trusted',
                     public_key_present = EXISTS(
                        SELECT 1 FROM peer_keys WHERE peer_keys.fingerprint = contacts.fingerprint
                     ),
                     updated_at = ?2
                 WHERE fingerprint = ?1",
                params![&fingerprint[..], now],
            )
            .map_err(StorageError::Repository)?;
        self.get_contact_by_fingerprint(fingerprint)
    }

    /// Fetch a contact by fingerprint.
    pub fn get_contact_by_fingerprint(
        &self,
        fingerprint: Fingerprint,
    ) -> Result<Option<ContactRecord>, StorageError> {
        self.connection
            .query_row(
                "SELECT alias, fingerprint, public_key_present, trust_state, created_at, updated_at
                 FROM contacts
                 WHERE fingerprint = ?1",
                params![&fingerprint[..]],
                row_to_contact,
            )
            .optional()
            .map_err(StorageError::Repository)?
            .map(validate_contact_record)
            .transpose()
    }

    /// Fetch a contact by alias.
    pub fn get_contact_by_alias(
        &self,
        alias: &str,
    ) -> Result<Option<ContactRecord>, StorageError> {
        let alias = validate_contact_alias(alias.to_owned())?;
        self.connection
            .query_row(
                "SELECT alias, fingerprint, public_key_present, trust_state, created_at, updated_at
                 FROM contacts
                 WHERE alias = ?1 COLLATE NOCASE",
                params![alias],
                row_to_contact,
            )
            .optional()
            .map_err(StorageError::Repository)?
            .map(validate_contact_record)
            .transpose()
    }

    /// List contacts in deterministic alias order.
    pub fn list_contacts(&self) -> Result<Vec<ContactRecord>, StorageError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT alias, fingerprint, public_key_present, trust_state, created_at, updated_at
                 FROM contacts
                 ORDER BY alias COLLATE NOCASE, fingerprint",
            )
            .map_err(StorageError::Repository)?;

        let contacts = statement
            .query_map([], row_to_contact)
            .map_err(StorageError::Repository)?
            .map(|row| row.map_err(StorageError::Repository).and_then(validate_contact_record))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(contacts)
    }

    fn peer_key_exists(&self, fingerprint: Fingerprint) -> Result<bool, StorageError> {
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM peer_keys WHERE fingerprint = ?1)",
                params![&fingerprint[..]],
                |row| row.get::<_, bool>(0),
            )
            .map_err(StorageError::Repository)
    }

    /// Insert or update the signed ACK state for an outbound message UUID.
    pub fn upsert_message_ack(
        &self,
        upsert: MessageAckUpsert,
    ) -> Result<MessageAckRecord, StorageError> {
        if upsert.signature.is_empty() {
            return Err(StorageError::EmptyAckSignature);
        }

        let acknowledged_at = unix_timestamp()?;
        self.connection
            .execute(
                "INSERT INTO message_acks (
                    message_uuid, message_hash, acknowledger, signature, acknowledged_at
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT(message_uuid) DO UPDATE SET
                    message_hash = excluded.message_hash,
                    acknowledger = excluded.acknowledger,
                    signature = excluded.signature,
                    acknowledged_at = excluded.acknowledged_at",
                params![
                    &upsert.message_uuid[..],
                    &upsert.message_hash[..],
                    &upsert.acknowledger[..],
                    upsert.signature,
                    acknowledged_at,
                ],
            )
            .map_err(StorageError::Repository)?;

        self.get_message_ack(upsert.message_uuid)?
            .ok_or_else(|| StorageError::Repository(rusqlite::Error::QueryReturnedNoRows))
    }

    /// Fetch persisted ACK delivery state by the acknowledged message UUID.
    pub fn get_message_ack(
        &self,
        message_uuid: [u8; 16],
    ) -> Result<Option<MessageAckRecord>, StorageError> {
        self.connection
            .query_row(
                "SELECT message_uuid, message_hash, acknowledger, signature, acknowledged_at
                 FROM message_acks
                 WHERE message_uuid = ?1",
                params![&message_uuid[..]],
                row_to_message_ack,
            )
            .optional()
            .map_err(StorageError::Repository)?
            .map(validate_ack_record)
            .transpose()
    }

    /// Ensure a conversation row exists even before any messages have arrived.
    pub fn ensure_conversation(
        &self,
        conversation_uuid: [u8; 16],
    ) -> Result<ConversationRecord, StorageError> {
        let now = unix_timestamp()?;
        self.connection
            .execute(
                "INSERT OR IGNORE INTO conversations (
                    conversation_uuid, created_at, updated_at
                ) VALUES (?1, ?2, ?2)",
                params![&conversation_uuid[..], now],
            )
            .map_err(StorageError::Repository)?;

        self.get_conversation(conversation_uuid)?
            .ok_or_else(|| StorageError::Repository(rusqlite::Error::QueryReturnedNoRows))
    }

    /// Fetch persisted conversation metadata by conversation UUID.
    pub fn get_conversation(
        &self,
        conversation_uuid: [u8; 16],
    ) -> Result<Option<ConversationRecord>, StorageError> {
        self.connection
            .query_row(
                "SELECT conversation_uuid, created_at, updated_at
                 FROM conversations
                 WHERE conversation_uuid = ?1",
                params![&conversation_uuid[..]],
                row_to_conversation,
            )
            .optional()
            .map_err(StorageError::Repository)
    }

    /// List known conversations in deterministic update order.
    pub fn list_conversations(&self) -> Result<Vec<ConversationRecord>, StorageError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT conversation_uuid, created_at, updated_at
                 FROM conversations
                 ORDER BY updated_at DESC, created_at DESC, conversation_uuid",
            )
            .map_err(StorageError::Repository)?;

        let conversations = statement
            .query_map([], row_to_conversation)
            .map_err(StorageError::Repository)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::Repository)?;
        Ok(conversations)
    }

    /// Idempotently persist one accepted chat message and its conversation row.
    pub fn insert_accepted_chat_message(
        &self,
        insert: AcceptedChatMessageInsert,
    ) -> Result<AcceptedChatMessageRecord, StorageError> {
        if insert.encrypted_payload.is_empty() {
            return Err(StorageError::EmptyEncryptedPayload);
        }
        let reply_to = insert
            .reply_to
            .or_else(|| reply_reference_from_headers(&insert.headers));

        if let Some(existing) = self.get_accepted_chat_message(insert.message_uuid)? {
            if existing.message_hash == insert.message_hash {
                return Ok(existing);
            }
            return Err(StorageError::DuplicateMessageUuid);
        }

        let hash_owner = self
            .connection
            .query_row(
                "SELECT message_uuid
                 FROM accepted_chat_messages
                 WHERE message_hash = ?1",
                params![&insert.message_hash[..]],
                |row| vec_to_message_uuid(row.get(0)?).map_err(storage_error_to_sql_error),
            )
            .optional()
            .map_err(StorageError::Repository)?;
        if hash_owner.is_some_and(|message_uuid| message_uuid != insert.message_uuid) {
            return Err(StorageError::DuplicateMessageHash);
        }

        let received_at = unix_timestamp()?;
        self.connection
            .execute(
                "INSERT OR IGNORE INTO conversations (
                    conversation_uuid, created_at, updated_at
                ) VALUES (?1, ?2, ?2)",
                params![&insert.conversation_uuid[..], received_at],
            )
            .map_err(StorageError::Repository)?;
        self.connection
            .execute(
                "UPDATE conversations
                 SET updated_at = MAX(updated_at, ?2)
                 WHERE conversation_uuid = ?1",
                params![&insert.conversation_uuid[..], received_at],
            )
            .map_err(StorageError::Repository)?;

        self.connection
            .execute(
                "INSERT INTO accepted_chat_messages (
                    conversation_uuid,
                    message_uuid,
                    previous_hash,
                    message_hash,
                    sender,
                    sent_at,
                    received_at,
                    headers,
                    encrypted_payload,
                    decrypted_payload,
                    reply_to_uuid,
                    reply_to_hash
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    &insert.conversation_uuid[..],
                    &insert.message_uuid[..],
                    &insert.previous_hash[..],
                    &insert.message_hash[..],
                    &insert.sender[..],
                    insert.sent_at,
                    received_at,
                    insert.headers,
                    insert.encrypted_payload,
                    insert.decrypted_payload,
                    reply_to.as_ref().map(|reply| &reply.message_uuid[..]),
                    reply_to.as_ref().map(|reply| &reply.message_hash[..]),
                ],
            )
            .map_err(StorageError::Repository)?;

        self.get_accepted_chat_message(insert.message_uuid)?
            .ok_or_else(|| StorageError::Repository(rusqlite::Error::QueryReturnedNoRows))
    }

    /// Fetch an accepted chat message by message UUID.
    pub fn get_accepted_chat_message(
        &self,
        message_uuid: [u8; 16],
    ) -> Result<Option<AcceptedChatMessageRecord>, StorageError> {
        self.connection
            .query_row(
                "SELECT
                    accepted_chat_messages.conversation_uuid,
                    accepted_chat_messages.message_uuid,
                    accepted_chat_messages.previous_hash,
                    accepted_chat_messages.message_hash,
                    accepted_chat_messages.sender,
                    accepted_chat_messages.sent_at,
                    accepted_chat_messages.received_at,
                    accepted_chat_messages.headers,
                    accepted_chat_messages.encrypted_payload,
                    accepted_chat_messages.decrypted_payload,
                    accepted_chat_messages.reply_to_uuid,
                    accepted_chat_messages.reply_to_hash,
                    message_acks.acknowledged_at
                 FROM accepted_chat_messages
                 LEFT JOIN message_acks
                    ON message_acks.message_uuid = accepted_chat_messages.message_uuid
                    AND message_acks.message_hash = accepted_chat_messages.message_hash
                 WHERE accepted_chat_messages.message_uuid = ?1",
                params![&message_uuid[..]],
                row_to_accepted_chat_message,
            )
            .optional()
            .map_err(StorageError::Repository)?
            .map(validate_accepted_chat_message)
            .transpose()
    }

    /// Fetch accepted messages for a conversation in resolved `prev_hash` chain order.
    pub fn accepted_messages_by_conversation(
        &self,
        conversation_uuid: [u8; 16],
    ) -> Result<Vec<AcceptedChatMessageRecord>, StorageError> {
        let messages = self.accepted_messages_by_conversation_fallback_order(conversation_uuid)?;
        order_message_chain(messages)
    }

    /// Fetch accepted messages for a conversation in stable fallback order.
    pub fn accepted_messages_by_conversation_fallback_order(
        &self,
        conversation_uuid: [u8; 16],
    ) -> Result<Vec<AcceptedChatMessageRecord>, StorageError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT
                    accepted_chat_messages.conversation_uuid,
                    accepted_chat_messages.message_uuid,
                    accepted_chat_messages.previous_hash,
                    accepted_chat_messages.message_hash,
                    accepted_chat_messages.sender,
                    accepted_chat_messages.sent_at,
                    accepted_chat_messages.received_at,
                    accepted_chat_messages.headers,
                    accepted_chat_messages.encrypted_payload,
                    accepted_chat_messages.decrypted_payload,
                    accepted_chat_messages.reply_to_uuid,
                    accepted_chat_messages.reply_to_hash,
                    message_acks.acknowledged_at
                 FROM accepted_chat_messages
                 LEFT JOIN message_acks
                    ON message_acks.message_uuid = accepted_chat_messages.message_uuid
                    AND message_acks.message_hash = accepted_chat_messages.message_hash
                 WHERE accepted_chat_messages.conversation_uuid = ?1
                 ORDER BY accepted_chat_messages.sent_at,
                    accepted_chat_messages.received_at,
                    accepted_chat_messages.message_uuid",
            )
            .map_err(StorageError::Repository)?;

        let messages = statement
            .query_map(params![&conversation_uuid[..]], row_to_accepted_chat_message)
            .map_err(StorageError::Repository)?
            .map(|row| {
                row.map_err(StorageError::Repository)
                    .and_then(validate_accepted_chat_message)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(messages)
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
                ON peer_keys(last_seen);

            CREATE TABLE IF NOT EXISTS message_acks (
                message_uuid BLOB PRIMARY KEY CHECK(length(message_uuid) = 16),
                message_hash BLOB NOT NULL CHECK(length(message_hash) = 32),
                acknowledger BLOB NOT NULL CHECK(length(acknowledger) = 32),
                signature BLOB NOT NULL CHECK(length(signature) > 0),
                acknowledged_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_message_acks_acknowledger
                ON message_acks(acknowledger);

            CREATE TABLE IF NOT EXISTS conversations (
                conversation_uuid BLOB PRIMARY KEY CHECK(length(conversation_uuid) = 16),
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS accepted_chat_messages (
                message_uuid BLOB PRIMARY KEY CHECK(length(message_uuid) = 16),
                conversation_uuid BLOB NOT NULL CHECK(length(conversation_uuid) = 16),
                previous_hash BLOB NOT NULL CHECK(length(previous_hash) = 32),
                message_hash BLOB NOT NULL UNIQUE CHECK(length(message_hash) = 32),
                sender BLOB NOT NULL CHECK(length(sender) = 32),
                sent_at INTEGER NOT NULL,
                received_at INTEGER NOT NULL,
                headers BLOB NOT NULL,
                encrypted_payload BLOB NOT NULL CHECK(length(encrypted_payload) > 0),
                decrypted_payload BLOB NOT NULL,
                reply_to_uuid BLOB CHECK(reply_to_uuid IS NULL OR length(reply_to_uuid) = 16),
                reply_to_hash BLOB CHECK(reply_to_hash IS NULL OR length(reply_to_hash) = 32),
                FOREIGN KEY(conversation_uuid) REFERENCES conversations(conversation_uuid)
            );

            CREATE INDEX IF NOT EXISTS idx_accepted_chat_messages_conversation
                ON accepted_chat_messages(conversation_uuid);

            CREATE INDEX IF NOT EXISTS idx_accepted_chat_messages_previous_hash
                ON accepted_chat_messages(conversation_uuid, previous_hash);

            CREATE TABLE IF NOT EXISTS contacts (
                fingerprint BLOB PRIMARY KEY CHECK(length(fingerprint) = 32),
                alias TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK(length(alias) BETWEEN 1 AND 64),
                public_key_present INTEGER NOT NULL DEFAULT 0 CHECK(public_key_present IN (0, 1)),
                trust_state TEXT NOT NULL DEFAULT 'untrusted'
                    CHECK(trust_state IN ('untrusted', 'trusted')),
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_contacts_alias
                ON contacts(alias COLLATE NOCASE);

            UPDATE contacts
            SET public_key_present = EXISTS(
                SELECT 1 FROM peer_keys WHERE peer_keys.fingerprint = contacts.fingerprint
            );",
        )
        .map_err(StorageError::Migration)?;

    if !column_exists(&transaction, "accepted_chat_messages", "reply_to_uuid")? {
        transaction
            .execute_batch(
                "ALTER TABLE accepted_chat_messages
                    ADD COLUMN reply_to_uuid BLOB CHECK(reply_to_uuid IS NULL OR length(reply_to_uuid) = 16);",
            )
            .map_err(StorageError::Migration)?;
    }
    if !column_exists(&transaction, "accepted_chat_messages", "reply_to_hash")? {
        transaction
            .execute_batch(
                "ALTER TABLE accepted_chat_messages
                    ADD COLUMN reply_to_hash BLOB CHECK(reply_to_hash IS NULL OR length(reply_to_hash) = 32);",
            )
            .map_err(StorageError::Migration)?;
    }

    let now = unix_timestamp()?;
    for migration in [
        MIGRATION_001,
        MIGRATION_002,
        MIGRATION_003,
        MIGRATION_004,
        MIGRATION_005,
    ] {
        transaction
            .execute(
                "INSERT OR IGNORE INTO schema_migrations (name, applied_at) VALUES (?1, ?2)",
                params![migration, now],
            )
            .map_err(StorageError::Migration)?;
    }

    transaction.commit().map_err(StorageError::Migration)
}

fn column_exists(
    transaction: &rusqlite::Transaction<'_>,
    table: &str,
    column: &str,
) -> Result<bool, StorageError> {
    let mut statement = transaction
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(StorageError::Migration)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(StorageError::Migration)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StorageError::Migration)?;
    Ok(columns.iter().any(|name| name == column))
}

fn row_to_contact(row: &rusqlite::Row<'_>) -> rusqlite::Result<ContactRecord> {
    let trust_state = row
        .get::<_, String>(3)
        .and_then(|value| ContactTrustState::from_str(&value).map_err(storage_error_to_sql_error))?;
    Ok(ContactRecord {
        alias: row.get(0)?,
        fingerprint: vec_to_fingerprint(row.get(1)?).map_err(storage_error_to_sql_error)?,
        public_key_present: row.get(2)?,
        trust_state,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
    })
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

fn validate_contact_record(record: ContactRecord) -> Result<ContactRecord, StorageError> {
    validate_contact_alias(record.alias.clone())?;
    Ok(record)
}

fn validate_contact_alias(alias: String) -> Result<String, StorageError> {
    if alias.is_empty() {
        return Err(StorageError::EmptyContactAlias);
    }
    if alias.trim() != alias
        || alias.len() > 64
        || alias
            .chars()
            .any(|character| character.is_control() || character == '\t')
    {
        return Err(StorageError::InvalidContactAlias { alias });
    }
    Ok(alias)
}

fn row_to_message_ack(row: &rusqlite::Row<'_>) -> rusqlite::Result<MessageAckRecord> {
    Ok(MessageAckRecord {
        message_uuid: vec_to_message_uuid(row.get(0)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                16,
                rusqlite::types::Type::Blob,
                Box::new(error),
            )
        })?,
        message_hash: vec_to_message_hash(row.get(1)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                32,
                rusqlite::types::Type::Blob,
                Box::new(error),
            )
        })?,
        acknowledger: vec_to_fingerprint(row.get(2)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                32,
                rusqlite::types::Type::Blob,
                Box::new(error),
            )
        })?,
        signature: row.get(3)?,
        acknowledged_at: row.get(4)?,
    })
}

fn row_to_conversation(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConversationRecord> {
    Ok(ConversationRecord {
        conversation_uuid: vec_to_message_uuid(row.get(0)?).map_err(storage_error_to_sql_error)?,
        created_at: row.get(1)?,
        updated_at: row.get(2)?,
    })
}

fn row_to_accepted_chat_message(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<AcceptedChatMessageRecord> {
    let headers = row.get::<_, Vec<u8>>(7)?;
    let reply_to = row_to_reply_reference(row.get(10)?, row.get(11)?)
        .map_err(storage_error_to_sql_error)?
        .or_else(|| reply_reference_from_headers(&headers));

    Ok(AcceptedChatMessageRecord {
        conversation_uuid: vec_to_message_uuid(row.get(0)?).map_err(storage_error_to_sql_error)?,
        message_uuid: vec_to_message_uuid(row.get(1)?).map_err(storage_error_to_sql_error)?,
        previous_hash: vec_to_message_hash(row.get(2)?).map_err(storage_error_to_sql_error)?,
        message_hash: vec_to_message_hash(row.get(3)?).map_err(storage_error_to_sql_error)?,
        sender: vec_to_fingerprint(row.get(4)?).map_err(storage_error_to_sql_error)?,
        sent_at: row.get(5)?,
        received_at: row.get(6)?,
        headers,
        encrypted_payload: row.get(8)?,
        decrypted_payload: row.get(9)?,
        reply_to,
        acknowledged_at: row.get(12)?,
    })
}

fn validate_record(record: PeerKeyRecord) -> Result<PeerKeyRecord, StorageError> {
    if record.public_key.is_empty() {
        return Err(StorageError::EmptyPublicKey);
    }
    Ok(record)
}

fn validate_ack_record(record: MessageAckRecord) -> Result<MessageAckRecord, StorageError> {
    if record.signature.is_empty() {
        return Err(StorageError::EmptyAckSignature);
    }
    Ok(record)
}

fn validate_accepted_chat_message(
    record: AcceptedChatMessageRecord,
) -> Result<AcceptedChatMessageRecord, StorageError> {
    if record.encrypted_payload.is_empty() {
        return Err(StorageError::EmptyEncryptedPayload);
    }
    Ok(record)
}

fn row_to_reply_reference(
    uuid: Option<Vec<u8>>,
    hash: Option<Vec<u8>>,
) -> Result<Option<ReplyReference>, StorageError> {
    match (uuid, hash) {
        (Some(uuid), Some(hash)) => Ok(Some(ReplyReference {
            message_uuid: vec_to_message_uuid(uuid)?,
            message_hash: vec_to_message_hash(hash)?,
        })),
        _ => Ok(None),
    }
}

fn reply_reference_from_headers(headers: &[u8]) -> Option<ReplyReference> {
    let headers = std::str::from_utf8(headers).ok()?;
    let mut reply_uuid = None;
    let mut reply_hash = None;

    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("Reply-To-UUID") {
            reply_uuid = parse_uuid(value);
        } else if name.eq_ignore_ascii_case("Reply-To-Hash") {
            reply_hash = parse_hash(value);
        }
    }

    Some(ReplyReference {
        message_uuid: reply_uuid?,
        message_hash: reply_hash?,
    })
}

fn parse_uuid(input: &str) -> Option<[u8; 16]> {
    hex::parse_hyphenated_fixed_hex(input, "expected 32 hex characters").ok()
}

fn parse_hash(input: &str) -> Option<[u8; 32]> {
    hex::parse_fixed_hex(input).ok()
}

fn order_message_chain(
    messages: Vec<AcceptedChatMessageRecord>,
) -> Result<Vec<AcceptedChatMessageRecord>, StorageError> {
    if messages.len() <= 1 {
        return Ok(messages);
    }

    let zero_hash = [0u8; 32];
    let by_hash = messages
        .iter()
        .enumerate()
        .map(|(index, message)| (message.message_hash, index))
        .collect::<HashMap<_, _>>();
    if by_hash.len() != messages.len() {
        return Err(StorageError::UnresolvedConversationChain);
    }

    let mut child_by_previous_hash = HashMap::new();
    for (index, message) in messages.iter().enumerate() {
        if child_by_previous_hash
            .insert(message.previous_hash, index)
            .is_some()
        {
            return Err(StorageError::UnresolvedConversationChain);
        }
    }

    let starts = messages
        .iter()
        .enumerate()
        .filter(|(_, message)| {
            message.previous_hash == zero_hash || !by_hash.contains_key(&message.previous_hash)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let [mut current_index] = starts.as_slice() else {
        return Err(StorageError::UnresolvedConversationChain);
    };

    let mut visited = HashSet::new();
    let mut ordered = Vec::with_capacity(messages.len());
    loop {
        if !visited.insert(current_index) {
            return Err(StorageError::UnresolvedConversationChain);
        }

        let message = messages[current_index].clone();
        let next_hash = message.message_hash;
        ordered.push(message);

        let Some(next_index) = child_by_previous_hash.get(&next_hash).copied() else {
            break;
        };
        current_index = next_index;
    }

    if ordered.len() != messages.len() {
        return Err(StorageError::UnresolvedConversationChain);
    }

    Ok(ordered)
}

fn storage_error_to_sql_error(error: StorageError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Blob,
        Box::new(error),
    )
}

fn vec_to_fixed_array<const N: usize>(
    bytes: Vec<u8>,
    invalid_length: impl FnOnce(usize) -> StorageError,
) -> Result<[u8; N], StorageError> {
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| invalid_length(bytes.len()))
}

fn vec_to_message_uuid(bytes: Vec<u8>) -> Result<[u8; 16], StorageError> {
    vec_to_fixed_array(bytes, |len| StorageError::InvalidMessageUuidLength { len })
}

fn vec_to_message_hash(bytes: Vec<u8>) -> Result<[u8; 32], StorageError> {
    vec_to_fixed_array(bytes, |len| StorageError::InvalidMessageHashLength { len })
}

fn vec_to_fingerprint(bytes: Vec<u8>) -> Result<Fingerprint, StorageError> {
    vec_to_fixed_array(bytes, |len| StorageError::InvalidFingerprintLength { len })
}

fn unix_timestamp() -> Result<i64, StorageError> {
    time::unix_timestamp_secs().map_err(|_| StorageError::InvalidSystemTime)
}

fn fingerprint_hex(fingerprint: &Fingerprint) -> String {
    hex::lower_hex(fingerprint)
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

    fn accepted_message(
        conversation_uuid: [u8; 16],
        message_uuid: [u8; 16],
        previous_hash: [u8; 32],
        message_hash: [u8; 32],
    ) -> AcceptedChatMessageInsert {
        AcceptedChatMessageInsert {
            conversation_uuid,
            message_uuid,
            previous_hash,
            message_hash,
            sender: [0x42; 32],
            sent_at: 123,
            headers: vec![0x01, 0x02],
            encrypted_payload: vec![0x03, 0x04],
            decrypted_payload: b"hello".to_vec(),
            reply_to: None,
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
                "SELECT COUNT(*) FROM schema_migrations
                 WHERE name IN (?1, ?2, ?3, ?4, ?5)",
                params![
                    MIGRATION_001,
                    MIGRATION_002,
                    MIGRATION_003,
                    MIGRATION_004,
                    MIGRATION_005
                ],
                |row| row.get(0),
            )
            .expect("query migration count");
        assert_eq!(migration_count, 5);
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
        assert_eq!(migration_count, 5);
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
    fn upsert_and_list_contacts_preserves_trust_and_tracks_public_key_presence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");
        let fingerprint = [0xaa; 32];

        let contact = storage
            .upsert_contact(ContactUpsert {
                alias: "alice".to_owned(),
                fingerprint,
            })
            .expect("insert contact");
        assert_eq!(contact.trust_state, ContactTrustState::Untrusted);
        assert!(!contact.public_key_present);

        storage
            .trust_contact(fingerprint)
            .expect("trust contact")
            .expect("stored contact");
        storage
            .upsert_peer_key(upsert(fingerprint, Some("alice"), 100))
            .expect("insert peer key");
        let updated = storage
            .upsert_contact(ContactUpsert {
                alias: "alice-renamed".to_owned(),
                fingerprint,
            })
            .expect("update contact");

        assert_eq!(updated.trust_state, ContactTrustState::Trusted);
        assert!(updated.public_key_present);
        assert_eq!(
            storage.list_contacts().expect("list contacts"),
            vec![updated]
        );
    }

    #[test]
    fn contact_alias_cannot_move_to_another_fingerprint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");
        storage
            .upsert_contact(ContactUpsert {
                alias: "alice".to_owned(),
                fingerprint: [0xaa; 32],
            })
            .expect("insert contact");

        let error = storage
            .upsert_contact(ContactUpsert {
                alias: "ALICE".to_owned(),
                fingerprint: [0xbb; 32],
            })
            .expect_err("alias conflict");

        assert!(error.to_string().contains("already belongs to fingerprint"));
    }

    #[test]
    fn invalid_contact_alias_is_actionable() {
        let error = validate_contact_alias(" alice ".to_owned()).expect_err("invalid alias");

        assert!(error.to_string().contains("without tabs, newlines"));
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

    #[test]
    fn insert_and_fetch_message_ack() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");
        let message_uuid = [0x11; 16];
        let message_hash = [0x22; 32];
        let acknowledger = [0x33; 32];

        let record = storage
            .upsert_message_ack(MessageAckUpsert {
                message_uuid,
                message_hash,
                acknowledger,
                signature: vec![4, 5, 6],
            })
            .expect("insert message ack");
        let fetched = storage
            .get_message_ack(message_uuid)
            .expect("fetch message ack")
            .expect("stored ack");

        assert_eq!(record, fetched);
        assert_eq!(fetched.message_uuid, message_uuid);
        assert_eq!(fetched.message_hash, message_hash);
        assert_eq!(fetched.acknowledger, acknowledger);
        assert_eq!(fetched.signature, vec![4, 5, 6]);
    }

    #[test]
    fn later_migrations_are_idempotent_on_existing_peer_key_database() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("dc.sqlite3");

        {
            let connection = Connection::open(&db_path).expect("open raw db");
            connection
                .execute_batch(
                    "CREATE TABLE schema_migrations (
                        name TEXT PRIMARY KEY,
                        applied_at INTEGER NOT NULL
                    );
                    CREATE TABLE peer_keys (
                        fingerprint BLOB PRIMARY KEY CHECK(length(fingerprint) = 32),
                        nick TEXT,
                        public_key BLOB NOT NULL CHECK(length(public_key) > 0),
                        first_seen INTEGER NOT NULL,
                        last_seen INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL
                    );
                    INSERT INTO schema_migrations (name, applied_at)
                    VALUES ('001_peer_keys', 100);",
                )
                .expect("seed existing v0.2 db");
        }

        let storage = Storage::open(&db_path).expect("open migrated storage");
        let migration_count: i64 = storage
            .connection
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| row.get(0))
            .expect("query migration count");

        assert_eq!(migration_count, 5);
        storage
            .upsert_message_ack(MessageAckUpsert {
                message_uuid: [0x44; 16],
                message_hash: [0x55; 32],
                acknowledger: [0x66; 32],
                signature: vec![7, 8, 9],
            })
            .expect("insert ack after migration");
        storage
            .insert_accepted_chat_message(accepted_message(
                [0x10; 16],
                [0x11; 16],
                [0x00; 32],
                [0x12; 32],
            ))
            .expect("insert accepted message after migration");
        storage
            .upsert_contact(ContactUpsert {
                alias: "alice".to_owned(),
                fingerprint: [0x77; 32],
            })
            .expect("insert contact after migration");
    }

    #[test]
    fn empty_message_ack_signature_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");

        let error = storage
            .upsert_message_ack(MessageAckUpsert {
                message_uuid: [0x77; 16],
                message_hash: [0x88; 32],
                acknowledger: [0x99; 32],
                signature: Vec::new(),
            })
            .expect_err("empty ack signature is invalid");

        assert!(matches!(error, StorageError::EmptyAckSignature));
    }

    #[test]
    fn insert_and_fetch_accepted_chat_message() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");
        let conversation_uuid = [0x10; 16];
        let message_uuid = [0x11; 16];
        let previous_hash = [0x12; 32];
        let message_hash = [0x13; 32];

        let record = storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                message_uuid,
                previous_hash,
                message_hash,
            ))
            .expect("insert accepted message");
        let fetched = storage
            .get_accepted_chat_message(message_uuid)
            .expect("fetch accepted message")
            .expect("stored accepted message");

        assert_eq!(record, fetched);
        assert_eq!(fetched.conversation_uuid, conversation_uuid);
        assert_eq!(fetched.message_uuid, message_uuid);
        assert_eq!(fetched.previous_hash, previous_hash);
        assert_eq!(fetched.message_hash, message_hash);
        assert_eq!(fetched.sender, [0x42; 32]);
        assert_eq!(fetched.sent_at, 123);
        assert!(fetched.received_at >= fetched.sent_at);
        assert_eq!(fetched.headers, vec![0x01, 0x02]);
        assert_eq!(fetched.encrypted_payload, vec![0x03, 0x04]);
        assert_eq!(fetched.decrypted_payload, b"hello");
        assert_eq!(fetched.acknowledged_at, None);
        assert_eq!(fetched.reply_to, None);
    }

    #[test]
    fn reply_metadata_is_extracted_from_signed_headers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");
        let target_uuid = [
            0xbb, 0x55, 0x93, 0x10, 0x43, 0x87, 0x48, 0x78, 0xa5, 0x70, 0x7b, 0xdc, 0xbb,
            0x99, 0x02, 0x98,
        ];
        let target_hash = [
            0x92, 0xd0, 0x6d, 0x29, 0x3e, 0xfe, 0x37, 0x22, 0xf9, 0x57, 0x32, 0xce, 0x68,
            0xb2, 0xcc, 0xef, 0x33, 0xc1, 0xa8, 0x09, 0x00, 0x83, 0x7e, 0x99, 0xc9, 0x0e,
            0xf9, 0xfb, 0xde, 0x4a, 0x38, 0x12,
        ];
        let mut insert = accepted_message([0x90; 16], [0x91; 16], [0x00; 32], [0x92; 32]);
        insert.headers = b"Content-Type: text/plain\r\n\
            Reply-To-UUID: bb559310-4387-4878-a570-7bdcbb990298\r\n\
            Reply-To-Hash: 92d06d293efe3722f95732ce68b2ccef33c1a80900837e99c90ef9fbde4a3812\r\n"
            .to_vec();

        let fetched = storage
            .insert_accepted_chat_message(insert)
            .expect("insert accepted message");

        assert_eq!(
            fetched.reply_to,
            Some(ReplyReference {
                message_uuid: target_uuid,
                message_hash: target_hash,
            })
        );
    }

    #[test]
    fn duplicate_accepted_chat_message_insert_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");
        let insert = accepted_message([0x20; 16], [0x21; 16], [0x00; 32], [0x22; 32]);

        let first = storage
            .insert_accepted_chat_message(insert.clone())
            .expect("first insert");
        let second = storage
            .insert_accepted_chat_message(insert)
            .expect("duplicate insert");

        assert_eq!(second, first);
    }

    #[test]
    fn duplicate_message_uuid_with_different_hash_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");
        let conversation_uuid = [0x30; 16];
        let message_uuid = [0x31; 16];

        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                message_uuid,
                [0x00; 32],
                [0x32; 32],
            ))
            .expect("first insert");
        let error = storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                message_uuid,
                [0x00; 32],
                [0x33; 32],
            ))
            .expect_err("conflicting message hash");

        assert!(matches!(error, StorageError::DuplicateMessageUuid));
    }

    #[test]
    fn duplicate_message_hash_with_different_uuid_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");
        let conversation_uuid = [0x40; 16];
        let message_hash = [0x41; 32];

        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                [0x42; 16],
                [0x00; 32],
                message_hash,
            ))
            .expect("first insert");
        let error = storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                [0x43; 16],
                [0x00; 32],
                message_hash,
            ))
            .expect_err("conflicting message uuid");

        assert!(matches!(error, StorageError::DuplicateMessageHash));
    }

    #[test]
    fn accepted_messages_are_fetched_in_chain_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");
        let conversation_uuid = [0x50; 16];
        let first_hash = [0x51; 32];
        let second_hash = [0x52; 32];
        let third_hash = [0x53; 32];

        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                [0x54; 16],
                second_hash,
                third_hash,
            ))
            .expect("insert third");
        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                [0x55; 16],
                [0x00; 32],
                first_hash,
            ))
            .expect("insert first");
        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                [0x56; 16],
                first_hash,
                second_hash,
            ))
            .expect("insert second");

        let messages = storage
            .accepted_messages_by_conversation(conversation_uuid)
            .expect("fetch chain");

        assert_eq!(
            messages
                .iter()
                .map(|message| message.message_hash)
                .collect::<Vec<_>>(),
            vec![first_hash, second_hash, third_hash]
        );
    }

    #[test]
    fn accepted_messages_include_ack_delivery_linkage() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");
        let message_uuid = [0x61; 16];
        let message_hash = [0x62; 32];

        storage
            .insert_accepted_chat_message(accepted_message(
                [0x60; 16],
                message_uuid,
                [0x00; 32],
                message_hash,
            ))
            .expect("insert accepted message");
        let ack = storage
            .upsert_message_ack(MessageAckUpsert {
                message_uuid,
                message_hash,
                acknowledger: [0x63; 32],
                signature: vec![0x64],
            })
            .expect("insert ack");
        let fetched = storage
            .get_accepted_chat_message(message_uuid)
            .expect("fetch accepted message")
            .expect("stored message");

        assert_eq!(fetched.acknowledged_at, Some(ack.acknowledged_at));
    }

    #[test]
    fn conflicting_ack_hash_does_not_link_to_accepted_message() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");
        let conversation_uuid = [0x65; 16];
        let message_uuid = [0x66; 16];
        let ack_message_hash = [0x67; 32];
        let accepted_message_hash = [0x68; 32];

        let ack = storage
            .upsert_message_ack(MessageAckUpsert {
                message_uuid,
                message_hash: ack_message_hash,
                acknowledger: [0x69; 32],
                signature: vec![0x6a],
            })
            .expect("insert conflicting ack first");
        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                message_uuid,
                [0x00; 32],
                accepted_message_hash,
            ))
            .expect("insert accepted message with same uuid and different hash");

        let fetched = storage
            .get_accepted_chat_message(message_uuid)
            .expect("fetch accepted message")
            .expect("stored message");
        let messages = storage
            .accepted_messages_by_conversation(conversation_uuid)
            .expect("fetch conversation messages");
        let stored_ack = storage
            .get_message_ack(message_uuid)
            .expect("fetch original ack")
            .expect("stored ack");

        assert_eq!(fetched.acknowledged_at, None);
        assert_eq!(messages[0].acknowledged_at, None);
        assert_eq!(stored_ack, ack);
    }

    #[test]
    fn unresolved_conversation_chain_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");
        let conversation_uuid = [0x70; 16];

        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                [0x71; 16],
                [0x00; 32],
                [0x72; 32],
            ))
            .expect("insert first chain");
        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                [0x73; 16],
                [0x00; 32],
                [0x74; 32],
            ))
            .expect("insert second chain");
        let error = storage
            .accepted_messages_by_conversation(conversation_uuid)
            .expect_err("ambiguous chain should fail");

        assert!(matches!(error, StorageError::UnresolvedConversationChain));
    }
}
