use crate::{
    discovery::Fingerprint,
    storage::{AcceptedChatMessageRecord, ConversationRecord, Storage, StorageError},
};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

const ZERO_HASH: [u8; 32] = [0; 32];

/// In-process API for reading conversation metadata and ordered message history.
pub struct ConversationEngine<'a> {
    storage: &'a Storage,
}

/// Conversation metadata exposed to higher-level clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationSummary {
    pub conversation_uuid: [u8; 16],
    pub created_at: i64,
    pub updated_at: i64,
}

/// Delivery state known for a persisted message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryState {
    Unknown,
    Acknowledged { acknowledged_at: i64 },
}

/// Display-ready persisted message data and metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationMessage {
    pub sender_fingerprint: Fingerprint,
    pub message_uuid: [u8; 16],
    pub previous_hash: [u8; 32],
    pub message_hash: [u8; 32],
    pub timestamp: i64,
    pub received_at: i64,
    pub delivery_state: DeliveryState,
    pub display_payload: Vec<u8>,
}

/// Errors returned by the conversation-facing read API.
#[derive(Debug, Error)]
pub enum ConversationEngineError {
    #[error("conversation {conversation_uuid:?} does not exist")]
    MissingConversation { conversation_uuid: [u8; 16] },
    #[error("conversation {conversation_uuid:?} has an ambiguous or cyclic message chain")]
    BrokenChain { conversation_uuid: [u8; 16] },
    #[error("failed to read conversation storage: {0}")]
    Storage(#[from] StorageError),
}

impl<'a> ConversationEngine<'a> {
    /// Create a conversation reader over the existing local storage.
    pub fn new(storage: &'a Storage) -> Self {
        Self { storage }
    }

    /// List all known conversations by conversation UUID and persisted timestamps.
    pub fn list_conversations(&self) -> Result<Vec<ConversationSummary>, ConversationEngineError> {
        let summaries = self
            .storage
            .list_conversations()?
            .into_iter()
            .map(ConversationSummary::from)
            .collect::<Vec<_>>();
        Ok(summaries)
    }

    /// Fetch message history ordered by `prev_hash` linkage where possible.
    ///
    /// If a predecessor message is missing, the available chain segment is kept
    /// intact and disconnected segments are appended in persisted fallback order.
    /// Ambiguous forks and cycles are rejected as broken chains.
    pub fn message_history(
        &self,
        conversation_uuid: [u8; 16],
    ) -> Result<Vec<ConversationMessage>, ConversationEngineError> {
        if self
            .storage
            .get_conversation(conversation_uuid)?
            .is_none()
        {
            return Err(ConversationEngineError::MissingConversation {
                conversation_uuid,
            });
        }

        let messages = self
            .storage
            .accepted_messages_by_conversation_fallback_order(conversation_uuid)?;
        let ordered = order_history(conversation_uuid, messages)?;

        Ok(ordered.into_iter().map(ConversationMessage::from).collect())
    }
}

impl From<ConversationRecord> for ConversationSummary {
    fn from(record: ConversationRecord) -> Self {
        Self {
            conversation_uuid: record.conversation_uuid,
            created_at: record.created_at,
            updated_at: record.updated_at,
        }
    }
}

impl From<AcceptedChatMessageRecord> for ConversationMessage {
    fn from(record: AcceptedChatMessageRecord) -> Self {
        let delivery_state = record
            .acknowledged_at
            .map(|acknowledged_at| DeliveryState::Acknowledged { acknowledged_at })
            .unwrap_or(DeliveryState::Unknown);

        Self {
            sender_fingerprint: record.sender,
            message_uuid: record.message_uuid,
            previous_hash: record.previous_hash,
            message_hash: record.message_hash,
            timestamp: record.sent_at,
            received_at: record.received_at,
            delivery_state,
            display_payload: record.decrypted_payload,
        }
    }
}

fn order_history(
    conversation_uuid: [u8; 16],
    messages: Vec<AcceptedChatMessageRecord>,
) -> Result<Vec<AcceptedChatMessageRecord>, ConversationEngineError> {
    if messages.len() <= 1 {
        return Ok(messages);
    }

    let by_hash = messages
        .iter()
        .enumerate()
        .map(|(index, message)| (message.message_hash, index))
        .collect::<HashMap<_, _>>();
    if by_hash.len() != messages.len() {
        return Err(ConversationEngineError::BrokenChain {
            conversation_uuid,
        });
    }

    let mut child_by_previous_hash = HashMap::new();
    for (index, message) in messages.iter().enumerate() {
        if message.previous_hash == ZERO_HASH || !by_hash.contains_key(&message.previous_hash) {
            continue;
        }

        if child_by_previous_hash
            .insert(message.previous_hash, index)
            .is_some()
        {
            return Err(ConversationEngineError::BrokenChain {
                conversation_uuid,
            });
        }
    }

    let mut start_indexes = messages
        .iter()
        .enumerate()
        .filter(|(_, message)| {
            message.previous_hash == ZERO_HASH || !by_hash.contains_key(&message.previous_hash)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if start_indexes.is_empty() {
        return Err(ConversationEngineError::BrokenChain {
            conversation_uuid,
        });
    }

    start_indexes.sort_unstable();
    let mut visited = HashSet::new();
    let mut ordered = Vec::with_capacity(messages.len());

    for start_index in start_indexes {
        let mut current_index = start_index;
        loop {
            if !visited.insert(current_index) {
                return Err(ConversationEngineError::BrokenChain {
                    conversation_uuid,
                });
            }

            let message = messages[current_index].clone();
            let next_hash = message.message_hash;
            ordered.push(message);

            let Some(next_index) = child_by_previous_hash.get(&next_hash).copied() else {
                break;
            };
            current_index = next_index;
        }
    }

    if ordered.len() != messages.len() {
        return Err(ConversationEngineError::BrokenChain {
            conversation_uuid,
        });
    }

    Ok(ordered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{AcceptedChatMessageInsert, MessageAckUpsert};

    fn accepted_message(
        conversation_uuid: [u8; 16],
        message_uuid: [u8; 16],
        previous_hash: [u8; 32],
        message_hash: [u8; 32],
        sent_at: i64,
        plaintext: &[u8],
    ) -> AcceptedChatMessageInsert {
        AcceptedChatMessageInsert {
            conversation_uuid,
            message_uuid,
            previous_hash,
            message_hash,
            sender: [0x42; 32],
            sent_at,
            headers: vec![0x01],
            encrypted_payload: vec![0x02],
            decrypted_payload: plaintext.to_vec(),
        }
    }

    fn storage() -> (tempfile::TempDir, Storage) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("dc.sqlite3")).expect("open storage");
        (dir, storage)
    }

    #[test]
    fn list_conversations_returns_known_conversation_uuids() {
        let (_dir, storage) = storage();
        let first = [0x10; 16];
        let second = [0x20; 16];
        storage.ensure_conversation(first).expect("ensure first");
        storage.ensure_conversation(second).expect("ensure second");
        let engine = ConversationEngine::new(&storage);

        let summaries = engine
            .list_conversations()
            .expect("list conversations")
            .into_iter()
            .map(|summary| summary.conversation_uuid)
            .collect::<Vec<_>>();

        assert_eq!(summaries, vec![first, second]);
    }

    #[test]
    fn empty_conversation_has_empty_history() {
        let (_dir, storage) = storage();
        let conversation_uuid = [0x30; 16];
        storage
            .ensure_conversation(conversation_uuid)
            .expect("ensure conversation");
        let engine = ConversationEngine::new(&storage);

        let history = engine
            .message_history(conversation_uuid)
            .expect("empty history");

        assert!(history.is_empty());
    }

    #[test]
    fn missing_conversation_is_actionable_error() {
        let (_dir, storage) = storage();
        let conversation_uuid = [0x40; 16];
        let engine = ConversationEngine::new(&storage);

        let error = engine
            .message_history(conversation_uuid)
            .expect_err("missing conversation");

        assert!(matches!(
            error,
            ConversationEngineError::MissingConversation { conversation_uuid: uuid }
                if uuid == conversation_uuid
        ));
    }

    #[test]
    fn single_message_history_exposes_metadata_and_payload() {
        let (_dir, storage) = storage();
        let conversation_uuid = [0x50; 16];
        let message_uuid = [0x51; 16];
        let message_hash = [0x52; 32];
        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                message_uuid,
                ZERO_HASH,
                message_hash,
                123,
                b"hello",
            ))
            .expect("insert message");
        let ack = storage
            .upsert_message_ack(MessageAckUpsert {
                message_uuid,
                message_hash,
                acknowledger: [0x53; 32],
                signature: vec![0x54],
            })
            .expect("insert ack");
        let engine = ConversationEngine::new(&storage);

        let history = engine.message_history(conversation_uuid).expect("history");

        assert_eq!(history.len(), 1);
        assert_eq!(history[0].sender_fingerprint, [0x42; 32]);
        assert_eq!(history[0].message_uuid, message_uuid);
        assert_eq!(history[0].message_hash, message_hash);
        assert_eq!(history[0].timestamp, 123);
        assert_eq!(
            history[0].delivery_state,
            DeliveryState::Acknowledged {
                acknowledged_at: ack.acknowledged_at
            }
        );
        assert_eq!(history[0].display_payload, b"hello");
    }

    #[test]
    fn multi_message_history_uses_prev_hash_order() {
        let (_dir, storage) = storage();
        let conversation_uuid = [0x60; 16];
        let first_hash = [0x61; 32];
        let second_hash = [0x62; 32];
        let third_hash = [0x63; 32];
        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                [0x64; 16],
                second_hash,
                third_hash,
                300,
                b"third",
            ))
            .expect("insert third");
        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                [0x65; 16],
                ZERO_HASH,
                first_hash,
                100,
                b"first",
            ))
            .expect("insert first");
        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                [0x66; 16],
                first_hash,
                second_hash,
                200,
                b"second",
            ))
            .expect("insert second");
        let engine = ConversationEngine::new(&storage);

        let history = engine.message_history(conversation_uuid).expect("history");

        assert_eq!(
            history
                .iter()
                .map(|message| message.display_payload.as_slice())
                .collect::<Vec<_>>(),
            vec![b"first".as_slice(), b"second".as_slice(), b"third".as_slice()]
        );
    }

    #[test]
    fn missing_predecessor_uses_deterministic_fallback_segments() {
        let (_dir, storage) = storage();
        let conversation_uuid = [0x70; 16];
        let missing_hash = [0x71; 32];
        let orphan_hash = [0x72; 32];
        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                [0x73; 16],
                missing_hash,
                orphan_hash,
                100,
                b"orphan",
            ))
            .expect("insert orphan");
        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                [0x74; 16],
                orphan_hash,
                [0x75; 32],
                300,
                b"child",
            ))
            .expect("insert child");
        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                [0x76; 16],
                ZERO_HASH,
                [0x77; 32],
                200,
                b"complete",
            ))
            .expect("insert complete");
        let engine = ConversationEngine::new(&storage);

        let history = engine.message_history(conversation_uuid).expect("history");

        assert_eq!(
            history
                .iter()
                .map(|message| message.display_payload.as_slice())
                .collect::<Vec<_>>(),
            vec![
                b"orphan".as_slice(),
                b"child".as_slice(),
                b"complete".as_slice()
            ]
        );
    }

    #[test]
    fn forked_chain_is_broken_chain_error() {
        let (_dir, storage) = storage();
        let conversation_uuid = [0x80; 16];
        let first_hash = [0x81; 32];
        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                [0x82; 16],
                ZERO_HASH,
                first_hash,
                100,
                b"first",
            ))
            .expect("insert first");
        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                [0x83; 16],
                first_hash,
                [0x84; 32],
                200,
                b"second-a",
            ))
            .expect("insert second a");
        storage
            .insert_accepted_chat_message(accepted_message(
                conversation_uuid,
                [0x85; 16],
                first_hash,
                [0x86; 32],
                300,
                b"second-b",
            ))
            .expect("insert second b");
        let engine = ConversationEngine::new(&storage);

        let error = engine
            .message_history(conversation_uuid)
            .expect_err("fork is broken");

        assert!(matches!(
            error,
            ConversationEngineError::BrokenChain { conversation_uuid: uuid }
                if uuid == conversation_uuid
        ));
    }
}
