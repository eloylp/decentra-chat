use super::{
    args::*,
    output::{write_contact, write_contact_header, write_history_message, write_peer_list},
    parse::{
        fingerprint_hex, load_local_identity, load_peer_identity,
        load_peer_identity_from_fingerprint, open_storage, parse_fingerprint, parse_hash,
        parse_uuid, read_file, require_ipv4, uuid_hex, validate_cli_contact_alias, write_file,
    },
    CliError,
};
use crate::{
    config::Config,
    conversation_engine::{ConversationEngine, ConversationEngineError, ConversationMessage},
    crypto::{self, public_key_to_bytes, KeyPair},
    discovery::{Discovery, DiscoverySettings, LocalNode},
    key_exchange::{self, KeyExchangeService, LocalKeyMaterial},
    message_transport::{self, ChatMessageService, OutgoingChatMessage},
    storage::{AcceptedChatMessageInsert, ContactRecord, ContactTrustState, ContactUpsert, Storage},
    uuid::new_uuid_v4,
};
use std::{
    io::Write,
    net::Ipv4Addr,
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    pin,
};

pub(super) fn run_keygen<W: Write>(args: KeygenArgs, writer: &mut W) -> Result<(), CliError> {
    let keypair = KeyPair::generate().map_err(CliError::Crypto)?;
    let secret = crypto::secret_key_to_bytes(&keypair.secret).map_err(CliError::Crypto)?;
    let public = public_key_to_bytes(&keypair.public).map_err(CliError::Crypto)?;
    write_file(&args.secret_key, &secret)?;
    write_file(&args.public_key, &public)?;

    writeln!(writer, "keygen: wrote secret_key={}", args.secret_key.display())?;
    writeln!(writer, "keygen: wrote public_key={}", args.public_key.display())?;
    writeln!(
        writer,
        "keygen: fingerprint={}",
        fingerprint_hex(&crypto::fingerprint(&public))
    )?;
    Ok(())
}

pub(super) async fn run_key_serve<W: Write>(
    args: KeyServeArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    if args.duration_ms == 0 {
        return Err(CliError::InvalidKeyServeDuration);
    }
    let public_key = read_file(&args.public_key)?;
    let local_key = LocalKeyMaterial::from_public_key(public_key)?;
    let service = KeyExchangeService::start(args.listen, local_key).await?;

    writeln!(
        writer,
        "key-serve: listening on {} for {} ms",
        service.local_addr(),
        args.duration_ms
    )?;
    tokio::time::sleep(Duration::from_millis(args.duration_ms)).await;
    writeln!(writer, "key-serve: stopped")?;
    Ok(())
}

pub(super) async fn run_key_request<W: Write>(
    config_path: PathBuf,
    args: KeyRequestArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let storage = open_storage(config_path)?;
    let peer = key_exchange::request_peer_key(args.peer, &storage).await?;

    writeln!(
        writer,
        "key-request: stored peer fingerprint={}",
        fingerprint_hex(&peer.fingerprint)
    )?;
    Ok(())
}

pub async fn run_discovery<W: Write>(
    config_path: PathBuf,
    args: DiscoverArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    if args.duration_ms == 0 {
        return Err(CliError::InvalidDiscoveryDuration);
    }
    if args.announce_interval_ms == 0 {
        return Err(CliError::InvalidAnnounceInterval);
    }

    let config = Config::load_from_path(&config_path).map_err(|source| CliError::LoadConfig {
        path: config_path.clone(),
        source,
    })?;
    Storage::open(&config.storage_path).map_err(|source| CliError::InitializeStorage {
        path: config.storage_path.clone(),
        source,
    })?;

    let multicast_group = require_ipv4("multicast_group", config.multicast_group)?;
    let listen_addr = require_ipv4("listen_addr", config.listen_addr)?;
    let settings = DiscoverySettings::new(multicast_group, config.discovery_port, listen_addr)
        .with_multicast_interface(args.multicast_interface.unwrap_or(Ipv4Addr::UNSPECIFIED))
        .with_announce_interval(Duration::from_millis(args.announce_interval_ms));
    let local_node = LocalNode {
        nick: args.nick.as_bytes().to_vec(),
        listen_port: args.listen_port,
        fingerprint: parse_fingerprint(&args.fingerprint)?,
        public_key_blob: None,
    };

    let discovery = Discovery::start(settings.clone(), local_node).await?;
    writeln!(
        writer,
        "discovery: running for {} ms on {}:{}",
        args.duration_ms, settings.multicast_group, settings.discovery_port
    )?;

    let started = Instant::now();
    let deadline = Duration::from_millis(args.duration_ms);
    let progress_interval = Duration::from_secs(1);
    loop {
        let elapsed = started.elapsed();
        if elapsed >= deadline {
            break;
        }

        let sleep_for = (deadline - elapsed).min(progress_interval);
        tokio::time::sleep(sleep_for).await;
        let elapsed_ms = started.elapsed().min(deadline).as_millis();
        writeln!(writer, "discovery: elapsed_ms={elapsed_ms}")?;
    }

    write_peer_list(writer, &discovery.registry_snapshot(), Instant::now())?;
    Ok(())
}

pub(super) async fn run_onboard<W: Write>(
    config_path: PathBuf,
    args: OnboardArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let alias = validate_cli_contact_alias(args.alias)?;
    let expected_fingerprint = parse_fingerprint(&args.fingerprint)?;
    let storage = open_storage(config_path)?;

    if let Some(existing) = storage
        .get_contact_by_alias(&alias)
        .map_err(CliError::ReadContacts)?
    {
        if existing.fingerprint != expected_fingerprint {
            return Err(CliError::ContactFingerprintChanged {
                alias,
                existing_fingerprint: fingerprint_hex(&existing.fingerprint),
                new_fingerprint: fingerprint_hex(&expected_fingerprint),
            });
        }
    }

    let peer = key_exchange::request_peer_key(args.peer, &storage).await?;
    if peer.fingerprint != expected_fingerprint {
        return Err(CliError::OnboardFingerprintMismatch {
            peer: args.peer,
            expected_fingerprint: fingerprint_hex(&expected_fingerprint),
            actual_fingerprint: fingerprint_hex(&peer.fingerprint),
        });
    }

    let mut contact = storage
        .upsert_contact(ContactUpsert {
            alias,
            fingerprint: expected_fingerprint,
        })
        .map_err(CliError::PersistContact)?;
    if args.trust {
        contact = storage
            .trust_contact(expected_fingerprint)
            .map_err(CliError::PersistContact)?
            .ok_or_else(|| CliError::MissingContact {
                query: fingerprint_hex(&expected_fingerprint),
            })?;
    }

    writeln!(
        writer,
        "onboard: stored alias={} fingerprint={} peer={}",
        contact.alias,
        fingerprint_hex(&contact.fingerprint),
        args.peer
    )?;
    if args.trust {
        writeln!(writer, "onboard: trusted=true")?;
    } else {
        writeln!(
            writer,
            "onboard: trusted=false; run `contact trust {}` after verifying the fingerprint",
            contact.alias
        )?;
    }
    write_contact_header(writer)?;
    write_contact(writer, &contact)?;
    Ok(())
}

pub(super) async fn run_receive<W: Write>(
    config_path: PathBuf,
    args: ReceiveArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    if args.duration_ms == 0 {
        return Err(CliError::InvalidReceiveDuration);
    }

    let storage = open_storage(config_path)?;
    let local = load_local_identity(&args.secret_key)?;
    let peer = load_peer_identity(&storage, &args.peer_fingerprint)?;
    let previous_hash = parse_hash(&args.previous_hash)?;
    let mut service = ChatMessageService::start(args.listen, local, peer, previous_hash).await?;

    writeln!(
        writer,
        "receive: listening on {} for {} ms",
        service.local_addr(),
        args.duration_ms
    )?;
    let received = tokio::time::timeout(
        Duration::from_millis(args.duration_ms),
        service.recv(),
    )
    .await
    .map_err(|_| CliError::ReceiveTimedOut {
        duration_ms: args.duration_ms,
    })?
    .ok_or(CliError::ReceiveTimedOut {
        duration_ms: args.duration_ms,
    })?;

    storage
        .insert_accepted_chat_message(AcceptedChatMessageInsert {
            conversation_uuid: received.conversation_uuid,
            message_uuid: received.uuid,
            previous_hash: received.previous_hash,
            message_hash: received.message_hash,
            sender: received.source,
            sent_at: i64::from(received.timestamp),
            headers: received.headers,
            encrypted_payload: received.encrypted_payload,
            decrypted_payload: received.plaintext,
            reply_to: None,
        })
        .map_err(CliError::PersistMessage)?;

    writeln!(
        writer,
        "receive: accepted message_uuid={} message_hash={}",
        uuid_hex(&received.uuid),
        fingerprint_hex(&received.message_hash)
    )?;
    Ok(())
}

pub(super) async fn run_send<W: Write>(
    config_path: PathBuf,
    args: SendArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let storage = open_storage(config_path)?;
    let local = load_local_identity(&args.secret_key)?;
    let peer = load_peer_identity(&storage, &args.peer_fingerprint)?;
    let conversation_uuid = match args.conversation {
        Some(value) => parse_uuid(&value)?,
        None => new_uuid_v4(),
    };
    let previous_hash = parse_hash(&args.previous_hash)?;
    let plaintext = args.message.into_bytes();

    let (message, ack) = message_transport::send_chat_message_and_record_ack(
        args.peer,
        &local,
        &peer,
        OutgoingChatMessage {
            conversation_uuid,
            previous_hash,
            headers: b"Content-Type: text/plain".to_vec(),
            plaintext: plaintext.clone(),
        },
        &storage,
    )
    .await?;
    storage
        .insert_accepted_chat_message(AcceptedChatMessageInsert {
            conversation_uuid: message.conv_uuid,
            message_uuid: message.uuid,
            previous_hash: message.prev_hash,
            message_hash: ack.message_hash,
            sender: message.source,
            sent_at: i64::from(message.timestamp),
            headers: message.headers,
            encrypted_payload: message.data,
            decrypted_payload: plaintext,
            reply_to: None,
        })
        .map_err(CliError::PersistMessage)?;

    writeln!(
        writer,
        "send: delivered message_uuid={} acked_by={}",
        uuid_hex(&ack.message_uuid),
        fingerprint_hex(&ack.acknowledger)
    )?;
    Ok(())
}

pub(super) async fn run_chat<W: Write>(
    config_path: PathBuf,
    args: ChatArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    if args.duration_ms == 0 {
        return Err(CliError::InvalidChatDuration);
    }

    let conversation_uuid = parse_uuid(&args.conversation)?;
    let storage = open_storage(config_path)?;
    let local = load_local_identity(&args.secret_key)?;
    let contact = find_contact(&storage, &args.contact)?;
    require_trusted_contact(&contact)?;
    let peer = load_peer_identity_from_fingerprint(&storage, contact.fingerprint)?;
    storage
        .ensure_conversation(conversation_uuid)
        .map_err(CliError::PersistMessage)?;

    let mut history = chat_history(&storage, conversation_uuid)?;
    writeln!(
        writer,
        "chat: conversation_uuid={} contact={} fingerprint={} messages={}",
        uuid_hex(&conversation_uuid),
        contact.alias,
        fingerprint_hex(&contact.fingerprint),
        history.len()
    )?;
    writeln!(
        writer,
        "message_uuid\tsender_fingerprint\ttimestamp\tdelivery_state\treply_state\tpayload"
    )?;
    for message in &history {
        write_history_message(writer, message)?;
    }

    let mut latest_hash = history
        .last()
        .map(|message| message.message_hash)
        .unwrap_or([0; 32]);
    let mut service =
        ChatMessageService::start(args.listen, local.clone(), peer.clone(), latest_hash).await?;
    writeln!(
        writer,
        "chat: listening on {} for {} ms",
        service.local_addr(),
        args.duration_ms
    )?;
    writeln!(writer, "chat: enter one plaintext message per stdin line")?;

    let deadline = tokio::time::sleep(Duration::from_millis(args.duration_ms));
    pin!(deadline);
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();
    let mut stdin_done = false;
    let mut sent = 0_u64;
    let mut received_count = 0_u64;

    loop {
        tokio::select! {
            _ = &mut deadline => {
                break;
            }
            maybe_line = lines.next_line(), if !stdin_done => {
                let maybe_line = maybe_line.map_err(CliError::ReadStdin)?;
                let Some(line) = maybe_line else {
                    stdin_done = true;
                    continue;
                };
                if line.is_empty() {
                    continue;
                }

                let (message, ack) = message_transport::send_chat_message_and_record_ack(
                    args.peer,
                    &local,
                    &peer,
                    OutgoingChatMessage {
                        conversation_uuid,
                        previous_hash: latest_hash,
                        headers: b"Content-Type: text/plain".to_vec(),
                        plaintext: line.as_bytes().to_vec(),
                    },
                    &storage,
                )
                .await?;
                storage
                    .insert_accepted_chat_message(AcceptedChatMessageInsert {
                        conversation_uuid: message.conv_uuid,
                        message_uuid: message.uuid,
                        previous_hash: message.prev_hash,
                        message_hash: ack.message_hash,
                        sender: message.source,
                        sent_at: i64::from(message.timestamp),
                        headers: message.headers,
                        encrypted_payload: message.data,
                        decrypted_payload: line.into_bytes(),
                        reply_to: None,
                    })
                    .map_err(CliError::PersistMessage)?;
                latest_hash = ack.message_hash;
                sent += 1;
                writeln!(
                    writer,
                    "chat: delivered message_uuid={} acked_by={}",
                    uuid_hex(&ack.message_uuid),
                    fingerprint_hex(&ack.acknowledger)
                )?;
            }
            received = service.recv() => {
                let Some(received) = received else {
                    break;
                };
                storage
                    .insert_accepted_chat_message(AcceptedChatMessageInsert {
                        conversation_uuid: received.conversation_uuid,
                        message_uuid: received.uuid,
                        previous_hash: received.previous_hash,
                        message_hash: received.message_hash,
                        sender: received.source,
                        sent_at: i64::from(received.timestamp),
                        headers: received.headers,
                        encrypted_payload: received.encrypted_payload,
                        decrypted_payload: received.plaintext,
                        reply_to: None,
                    })
                    .map_err(CliError::PersistMessage)?;
                latest_hash = received.message_hash;
                received_count += 1;
                writeln!(
                    writer,
                    "chat: received message_uuid={} message_hash={}",
                    uuid_hex(&received.uuid),
                    fingerprint_hex(&received.message_hash)
                )?;
            }
        }
    }

    history = chat_history(&storage, conversation_uuid)?;
    writeln!(
        writer,
        "chat: stopped sent={} received={} messages={}",
        sent,
        received_count,
        history.len()
    )?;
    Ok(())
}

pub(super) fn run_conversations<W: Write>(config_path: PathBuf, writer: &mut W) -> Result<(), CliError> {
    let storage = open_storage(config_path)?;
    let engine = ConversationEngine::new(&storage);
    let conversations = engine
        .list_conversations()
        .map_err(CliError::ReadConversation)?;

    writeln!(writer, "conversations: {}", conversations.len())?;
    writeln!(writer, "conversation_uuid\tcreated_at\tupdated_at")?;
    for conversation in conversations {
        writeln!(
            writer,
            "{}\t{}\t{}",
            uuid_hex(&conversation.conversation_uuid),
            conversation.created_at,
            conversation.updated_at
        )?;
    }
    Ok(())
}

pub(super) fn run_history<W: Write>(
    config_path: PathBuf,
    args: HistoryArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let conversation_uuid = parse_uuid(&args.conversation)?;
    let storage = open_storage(config_path)?;
    let engine = ConversationEngine::new(&storage);
    let history = engine
        .message_history(conversation_uuid)
        .map_err(|error| conversation_error(error, conversation_uuid))?;

    writeln!(
        writer,
        "history: conversation_uuid={} messages={}",
        uuid_hex(&conversation_uuid),
        history.len()
    )?;
    writeln!(
        writer,
        "message_uuid\tsender_fingerprint\ttimestamp\tdelivery_state\treply_state\tpayload"
    )?;
    for message in history {
        write_history_message(writer, &message)?;
    }
    Ok(())
}

pub(super) fn run_contact<W: Write>(
    config_path: PathBuf,
    args: ContactArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    match args.command {
        ContactCommand::Add(args) => run_contact_add(config_path, args, writer),
        ContactCommand::List => run_contact_list(config_path, writer),
        ContactCommand::Show(args) => run_contact_show(config_path, args, writer),
        ContactCommand::Trust(args) => run_contact_trust(config_path, args, writer),
    }
}

pub(super) fn run_contact_add<W: Write>(
    config_path: PathBuf,
    args: ContactAddArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let alias = validate_cli_contact_alias(args.alias)?;
    let fingerprint = parse_fingerprint(&args.fingerprint)?;
    let storage = open_storage(config_path)?;
    let contact = storage
        .upsert_contact(ContactUpsert { alias, fingerprint })
        .map_err(CliError::PersistContact)?;

    writeln!(
        writer,
        "contact: stored alias={} fingerprint={}",
        contact.alias,
        fingerprint_hex(&contact.fingerprint)
    )?;
    write_contact_header(writer)?;
    write_contact(writer, &contact)?;
    Ok(())
}

pub(super) fn run_contact_list<W: Write>(config_path: PathBuf, writer: &mut W) -> Result<(), CliError> {
    let storage = open_storage(config_path)?;
    let contacts = storage.list_contacts().map_err(CliError::ReadContacts)?;

    writeln!(writer, "contacts: {}", contacts.len())?;
    write_contact_header(writer)?;
    for contact in contacts {
        write_contact(writer, &contact)?;
    }
    Ok(())
}

pub(super) fn run_contact_show<W: Write>(
    config_path: PathBuf,
    args: ContactLookupArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let storage = open_storage(config_path)?;
    let contact = find_contact(&storage, &args.query)?;

    writeln!(
        writer,
        "contact: alias={} fingerprint={}",
        contact.alias,
        fingerprint_hex(&contact.fingerprint)
    )?;
    write_contact_header(writer)?;
    write_contact(writer, &contact)?;
    Ok(())
}

pub(super) fn run_contact_trust<W: Write>(
    config_path: PathBuf,
    args: ContactLookupArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let storage = open_storage(config_path)?;
    let contact = find_contact(&storage, &args.query)?;
    let trusted = storage
        .trust_contact(contact.fingerprint)
        .map_err(CliError::PersistContact)?
        .ok_or_else(|| CliError::MissingContact { query: args.query })?;

    writeln!(
        writer,
        "contact: trusted alias={} fingerprint={}",
        trusted.alias,
        fingerprint_hex(&trusted.fingerprint)
    )?;
    write_contact_header(writer)?;
    write_contact(writer, &trusted)?;
    Ok(())
}

fn find_contact(storage: &Storage, query: &str) -> Result<ContactRecord, CliError> {
    if query.len() == 64 {
        if let Ok(fingerprint) = parse_fingerprint(query) {
            return storage
                .get_contact_by_fingerprint(fingerprint)
                .map_err(CliError::ReadContacts)?
                .ok_or_else(|| CliError::MissingContact {
                    query: query.to_owned(),
                });
        }
    }

    validate_cli_contact_alias(query.to_owned())?;
    storage
        .get_contact_by_alias(query)
        .map_err(CliError::ReadContacts)?
        .ok_or_else(|| CliError::MissingContact {
            query: query.to_owned(),
        })
}

fn require_trusted_contact(contact: &ContactRecord) -> Result<(), CliError> {
    if contact.trust_state != ContactTrustState::Trusted {
        return Err(CliError::ContactNotTrusted {
            alias: contact.alias.clone(),
        });
    }
    if !contact.public_key_present {
        return Err(CliError::ContactMissingPublicKey {
            alias: contact.alias.clone(),
        });
    }
    Ok(())
}

fn chat_history(
    storage: &Storage,
    conversation_uuid: [u8; 16],
) -> Result<Vec<ConversationMessage>, CliError> {
    let engine = ConversationEngine::new(storage);
    engine
        .message_history(conversation_uuid)
        .map_err(|error| conversation_error(error, conversation_uuid))
}
fn conversation_error(
    error: ConversationEngineError,
    requested_uuid: [u8; 16],
) -> CliError {
    match error {
        ConversationEngineError::MissingConversation { .. } => CliError::MissingConversation {
            conversation_uuid: uuid_hex(&requested_uuid),
        },
        ConversationEngineError::BrokenChain { .. } => CliError::BrokenConversationChain {
            conversation_uuid: uuid_hex(&requested_uuid),
        },
        error => CliError::ReadConversation(error),
    }
}
