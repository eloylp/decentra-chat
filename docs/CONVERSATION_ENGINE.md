# Conversation Engine

The conversation engine is the v0.3 read model for persisted chat history. It sits between SQLite storage and the future CLI layer: storage keeps accepted protocol facts, and `ConversationEngine` turns those facts into conversation lists and display-ready message history.

This document describes what is implemented today in `src/storage.rs` and `src/conversation_engine.rs`.

## Setup

The engine works over an existing `Storage` handle:

```rust
use decentra_chat::{conversation_engine::ConversationEngine, storage::Storage};

let storage = Storage::open("decentra-chat.sqlite3")?;
let engine = ConversationEngine::new(&storage);
```

Run the current test suite with the larger stack used by the repository's v0.3 PRs:

```sh
RUST_MIN_STACK=16777216 cargo test
```

## Stored Facts

Accepted chat messages are persisted in `accepted_chat_messages`. Each row belongs to one conversation and stores the protocol fields needed to rebuild history:

| Field | Meaning |
|-------|---------|
| `conversation_uuid` | The protocol `conv_uuid`. This is the stable conversation index. |
| `message_uuid` | The protocol message UUID. This is unique in local storage. |
| `previous_hash` | The protocol `prev_hash`. A zero hash starts a chain segment. |
| `message_hash` | The verified hash of this accepted message. This is unique in local storage. |
| `sender` | The sender public-key fingerprint. |
| `sent_at` | The signed message timestamp. |
| `received_at` | The local persistence timestamp. |
| `headers` | Signed message headers as bytes. |
| `encrypted_payload` | The accepted encrypted payload bytes. |
| `decrypted_payload` | The display payload exposed to clients. |
| `reply_to_uuid` | Optional signed reply target UUID. |
| `reply_to_hash` | Optional signed reply target hash. |

`Storage::insert_accepted_chat_message` also ensures a row exists in `conversations`. Conversation timestamps are local persistence metadata: `created_at` is set when the conversation first appears, and `updated_at` advances when accepted messages are stored.

## Ordering

`ConversationEngine::message_history(conv_uuid)` reads accepted messages for one conversation and orders them by the `prev_hash` chain:

1. Build an index from each message's `message_hash` to its row.
2. Treat a zero `previous_hash`, or a `previous_hash` not found locally, as the start of an available chain segment.
3. Follow each segment from the current `message_hash` to the child whose `previous_hash` matches it.
4. Append disconnected segments in the deterministic fallback order returned by storage: `sent_at`, then `received_at`, then `message_uuid`.

This keeps locally available history readable even when an older predecessor has not arrived yet. The engine rejects ambiguous history instead of guessing. Duplicate hashes, forks where two messages point at the same predecessor, and cycles return `ConversationEngineError::BrokenChain`.

`Storage::accepted_messages_by_conversation` still exposes a stricter chain-ordered repository helper. The conversation engine uses `accepted_messages_by_conversation_fallback_order` so the UI-facing API can preserve incomplete but unambiguous segments.

## ACK State

ACKs are stored separately in `message_acks`. Accepted-message reads attach delivery state with a left join on both `message_uuid` and `message_hash`, so an ACK for the same UUID but a different hash does not mark the message as acknowledged.

The engine exposes this as `DeliveryState`:

| State | When it appears |
|-------|-----------------|
| `Unknown` | No matching ACK row exists for this message UUID and hash. |
| `Acknowledged { acknowledged_at }` | A matching signed ACK has been persisted. |

This is local delivery knowledge, not global consensus. It only says that this node has stored a valid ACK matching the accepted message identity.

## Reply Validation

Reply metadata comes from accepted, signed chat-message headers. Storage persists explicit `reply_to_uuid` and `reply_to_hash` fields when supplied by the caller, or extracts them from `Reply-To-UUID` and `Reply-To-Hash` headers when both parse successfully.

`ConversationEngine` validates the stored reply target when building message history:

| State | Meaning |
|-------|---------|
| `ReplyState::None` | The message has no complete reply target metadata. |
| `ReplyState::Valid { target }` | The target message exists, belongs to the same conversation, and has the referenced hash. |
| `ReplyState::Unresolved { target }` | The target message UUID is not present in local storage yet. |
| `ReplyState::Invalid { target }` | The target UUID exists but points to another conversation, or its stored hash does not match the signed target hash. |

The validation checks persisted accepted messages, not display text. That keeps the non-repudiation path tied to the signed protocol metadata accepted by the message pipeline.

## Developer Walkthrough

To reconstruct one conversation for display:

```rust
use decentra_chat::conversation_engine::{
    ConversationEngine, ConversationEngineError, DeliveryState, ReplyState,
};
use decentra_chat::storage::Storage;

fn render_conversation(
    storage: &Storage,
    conversation_uuid: [u8; 16],
) -> Result<(), ConversationEngineError> {
    let engine = ConversationEngine::new(storage);
    let history = engine.message_history(conversation_uuid)?;

    for message in history {
        let delivery = match message.delivery_state {
            DeliveryState::Unknown => "pending",
            DeliveryState::Acknowledged { .. } => "acknowledged",
        };

        let reply = match message.reply_state {
            ReplyState::None => "no reply target",
            ReplyState::Valid { .. } => "valid reply",
            ReplyState::Unresolved { .. } => "reply target missing locally",
            ReplyState::Invalid { .. } => "invalid reply target",
        };

        println!(
            "{:?} {} {} {:?}",
            message.sender_fingerprint,
            delivery,
            reply,
            String::from_utf8_lossy(&message.display_payload)
        );
    }

    Ok(())
}
```

For a missing conversation UUID, the engine returns `ConversationEngineError::MissingConversation`. For ambiguous or cyclic `prev_hash` graphs, it returns `ConversationEngineError::BrokenChain`. Storage access failures are wrapped as `ConversationEngineError::Storage`.

## Current Limits

- The engine is an in-process Rust API. There is no CLI conversation browser yet.
- Reply headers are parsed from UTF-8 header bytes with `Name: value` lines. Malformed or incomplete reply metadata is treated the same as no reply metadata.
- Conversation type exists in the wire protocol, but the current persisted conversation read model indexes by `conversation_uuid` only.
- The engine reconstructs local history. It does not synchronize missing predecessors or resolve forks across peers.
