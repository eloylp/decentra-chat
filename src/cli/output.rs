use super::parse::{fingerprint_hex, uuid_hex};
use crate::{
    conversation_engine::{ConversationMessage, DeliveryState, ReplyState},
    discovery::{Fingerprint, PeerEntry},
    storage::{ContactRecord, ContactTrustState},
};
use std::{
    collections::HashMap,
    io::{self, Write},
    time::Instant,
};

pub(super) fn write_contact_header<W: Write>(writer: &mut W) -> Result<(), io::Error> {
    writeln!(
        writer,
        "alias\tfingerprint\tpublic_key_present\ttrust_state\tcreated_at\tupdated_at"
    )
}

pub(super) fn write_contact<W: Write>(
    writer: &mut W,
    contact: &ContactRecord,
) -> Result<(), io::Error> {
    writeln!(
        writer,
        "{}\t{}\t{}\t{}\t{}\t{}",
        contact.alias,
        fingerprint_hex(&contact.fingerprint),
        contact.public_key_present,
        contact_trust_state_label(contact.trust_state),
        contact.created_at,
        contact.updated_at
    )
}
fn contact_trust_state_label(state: ContactTrustState) -> &'static str {
    match state {
        ContactTrustState::Untrusted => "untrusted",
        ContactTrustState::Trusted => "trusted",
    }
}

pub(super) fn write_history_message<W: Write>(
    writer: &mut W,
    message: &ConversationMessage,
) -> Result<(), io::Error> {
    writeln!(
        writer,
        "{}\t{}\t{}\t{}\t{}\t{}",
        uuid_hex(&message.message_uuid),
        fingerprint_hex(&message.sender_fingerprint),
        message.timestamp,
        delivery_state_label(&message.delivery_state),
        reply_state_label(&message.reply_state),
        escaped_payload(&message.display_payload)
    )
}

fn delivery_state_label(state: &DeliveryState) -> String {
    match state {
        DeliveryState::Unknown => "unknown".to_owned(),
        DeliveryState::Acknowledged { acknowledged_at } => {
            format!("acknowledged:{acknowledged_at}")
        }
    }
}

fn reply_state_label(state: &ReplyState) -> String {
    match state {
        ReplyState::None => "none".to_owned(),
        ReplyState::Valid { target } => format!(
            "valid:{}:{}",
            uuid_hex(&target.message_uuid),
            fingerprint_hex(&target.message_hash)
        ),
        ReplyState::Unresolved { target } => format!(
            "unresolved:{}:{}",
            uuid_hex(&target.message_uuid),
            fingerprint_hex(&target.message_hash)
        ),
        ReplyState::Invalid { target } => format!(
            "invalid:{}:{}",
            uuid_hex(&target.message_uuid),
            fingerprint_hex(&target.message_hash)
        ),
    }
}

fn escaped_payload(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}
pub(super) fn write_peer_list<W: Write>(
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
