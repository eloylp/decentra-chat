use crate::codec;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::{net::UdpSocket, sync::broadcast, task::JoinHandle};

/// DecentraChat peer identity fingerprint.
pub type Fingerprint = [u8; 32];

const DEFAULT_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(5);
const MAX_DISCOVERY_DATAGRAM_LEN: usize = 512;
const WIRE_DISCOVERY_VERSION: u8 = 1;

/// Runtime networking settings for UDP multicast discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverySettings {
    /// IPv4 multicast group used for discovery announcements.
    pub multicast_group: Ipv4Addr,
    /// UDP port shared by all discovery receivers.
    pub discovery_port: u16,
    /// Address advertised to peers for subsequent direct connections.
    pub listen_addr: Ipv4Addr,
    /// Local interface used when joining and sending to the multicast group.
    pub multicast_interface: Ipv4Addr,
    /// Period between type-1 discovery datagrams.
    pub announce_interval: Duration,
}

impl DiscoverySettings {
    /// Build settings with the protocol default 5 second announcement interval.
    pub fn new(multicast_group: Ipv4Addr, discovery_port: u16, listen_addr: Ipv4Addr) -> Self {
        Self {
            multicast_group,
            discovery_port,
            listen_addr,
            multicast_interface: Ipv4Addr::UNSPECIFIED,
            announce_interval: DEFAULT_ANNOUNCE_INTERVAL,
        }
    }

    /// Select the local interface used for multicast traffic.
    pub fn with_multicast_interface(mut self, interface: Ipv4Addr) -> Self {
        self.multicast_interface = interface;
        self
    }

    /// Override the announcement interval, primarily for tests and short-lived demos.
    pub fn with_announce_interval(mut self, interval: Duration) -> Self {
        self.announce_interval = interval;
        self
    }
}

/// Local identity material advertised by the discovery sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalNode {
    /// User-visible nickname encoded by the message codec.
    pub nick: Vec<u8>,
    /// Port advertised to peers for follow-up direct connections.
    pub listen_port: u16,
    /// Opaque SHA-256 public-key fingerprint supplied by the caller.
    pub fingerprint: Fingerprint,
    /// Optional local public-key bytes retained for future registry integration.
    pub public_key_blob: Option<Vec<u8>>,
}

/// Decoded type-1 discovery announcement used by the networking layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryAnnouncement {
    /// IPv4 address advertised by the sending peer.
    pub address: Ipv4Addr,
    /// Port advertised by the sending peer.
    pub port: u16,
    /// Nickname bytes, kept opaque so the codec owns wire validation rules.
    pub nick: Vec<u8>,
    /// Opaque key fingerprint from the wire message.
    pub key_fingerprint: Fingerprint,
}

/// Current in-memory view of a discovered peer.
#[derive(Debug, Clone)]
pub struct PeerEntry {
    /// Lossy UTF-8 rendering of the peer nickname for display and diagnostics.
    pub nick: String,
    /// Address and port advertised by the peer.
    pub listen_addr: SocketAddr,
    /// Stable key fingerprint used as the registry key.
    pub fingerprint: Fingerprint,
    /// Public key bytes learned by a higher-level key exchange phase, if known.
    pub public_key_blob: Option<Vec<u8>>,
    /// Last time this peer was observed through discovery.
    pub last_seen: Instant,
}

/// Event emitted when known public-key bytes change for an existing fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRekeyed {
    /// Fingerprint whose associated public key changed.
    pub fingerprint: Fingerprint,
    /// Previous public key bytes.
    pub old_public_key_blob: Vec<u8>,
    /// Replacement public key bytes.
    pub new_public_key_blob: Vec<u8>,
}

/// Errors returned while validating settings or creating discovery sockets.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("discovery port must be between 1 and 65535")]
    InvalidPort,
    #[error("multicast group must be an IPv4 multicast address, got {0}")]
    InvalidMulticastGroup(Ipv4Addr),
    #[error("announcement interval must be greater than zero")]
    InvalidAnnouncementInterval,
    #[error("socket error while {operation}: {source}")]
    Socket {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to encode discovery announcement: {0}")]
    Encode(String),
    #[error("failed to decode discovery announcement: {0}")]
    Decode(String),
}

/// Production adapter between UDP discovery and the DecentraChat wire codec.
#[derive(Debug, Clone, Copy, Default)]
pub struct WireAnnouncementCodec;

/// Errors returned by the production discovery announcement codec adapter.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireAnnouncementCodecError {
    #[error("nickname is too long for a discovery announcement: {len} bytes, max 255")]
    NickTooLong { len: usize },
    #[error("wire codec error: {0}")]
    Codec(#[from] codec::CodecError),
}

/// Binary codec boundary for type-1 discovery announcements.
pub trait AnnouncementCodec: Clone + Send + Sync + 'static {
    type Error: std::fmt::Display + Send + Sync + 'static;

    /// Encode an announcement into one UDP datagram payload.
    fn encode(&self, announcement: &DiscoveryAnnouncement) -> Result<Vec<u8>, Self::Error>;
    /// Decode one UDP datagram payload into an announcement.
    fn decode(&self, bytes: &[u8]) -> Result<DiscoveryAnnouncement, Self::Error>;
}

impl AnnouncementCodec for WireAnnouncementCodec {
    type Error = WireAnnouncementCodecError;

    fn encode(&self, announcement: &DiscoveryAnnouncement) -> Result<Vec<u8>, Self::Error> {
        if announcement.nick.len() > u8::MAX as usize {
            return Err(WireAnnouncementCodecError::NickTooLong {
                len: announcement.nick.len(),
            });
        }

        Ok(codec::DiscoveryAnnounce {
            version: WIRE_DISCOVERY_VERSION,
            address: announcement.address.octets(),
            port: announcement.port,
            nick: announcement.nick.clone(),
            key_fingerprint: announcement.key_fingerprint,
        }
        .into())
    }

    fn decode(&self, bytes: &[u8]) -> Result<DiscoveryAnnouncement, Self::Error> {
        let message = codec::DiscoveryAnnounce::try_from(bytes)?;
        Ok(DiscoveryAnnouncement {
            address: Ipv4Addr::from(message.address),
            port: message.port,
            nick: message.nick,
            key_fingerprint: message.key_fingerprint,
        })
    }
}

/// Running discovery service with owned sender and receiver tasks.
pub struct Discovery<C: AnnouncementCodec = WireAnnouncementCodec> {
    registry: Arc<Mutex<HashMap<Fingerprint, PeerEntry>>>,
    rekey_tx: broadcast::Sender<PeerRekeyed>,
    receiver_task: JoinHandle<()>,
    sender_task: JoinHandle<()>,
    codec: C,
}

impl Discovery<WireAnnouncementCodec> {
    /// Join the multicast group and start discovery using the production wire codec.
    pub async fn start(
        settings: DiscoverySettings,
        local_node: LocalNode,
    ) -> Result<Self, DiscoveryError> {
        Self::start_with_codec(settings, local_node, WireAnnouncementCodec).await
    }
}

impl<C: AnnouncementCodec> Discovery<C> {
    /// Join the multicast group and start the periodic sender plus receiver.
    pub async fn start_with_codec(
        settings: DiscoverySettings,
        local_node: LocalNode,
        codec: C,
    ) -> Result<Self, DiscoveryError> {
        validate_settings(&settings)?;

        let registry = Arc::new(Mutex::new(HashMap::new()));
        let (rekey_tx, _) = broadcast::channel(16);

        let receiver_socket = multicast_receiver_socket(&settings)?;
        let sender_socket = multicast_sender_socket(&settings)?;
        let receiver_registry = Arc::clone(&registry);
        let receiver_rekey_tx = rekey_tx.clone();
        let receiver_codec = codec.clone();

        let receiver_task = tokio::spawn(async move {
            receiver_loop(
                receiver_socket,
                receiver_registry,
                receiver_rekey_tx,
                receiver_codec,
            )
            .await;
        });

        let sender_settings = settings.clone();
        let sender_codec = codec.clone();
        let sender_task = tokio::spawn(async move {
            sender_loop(sender_socket, sender_settings, local_node, sender_codec).await;
        });

        Ok(Self {
            registry,
            rekey_tx,
            receiver_task,
            sender_task,
            codec,
        })
    }

    /// Return a cloned point-in-time view of the peer registry.
    pub fn registry_snapshot(&self) -> HashMap<Fingerprint, PeerEntry> {
        self.registry
            .lock()
            .expect("peer registry mutex poisoned")
            .clone()
    }

    /// Subscribe to peer re-key events.
    pub fn subscribe_rekey(&self) -> broadcast::Receiver<PeerRekeyed> {
        self.rekey_tx.subscribe()
    }

    /// Attach or replace public-key bytes for a known peer.
    ///
    /// Type-1 discovery currently carries only the fingerprint, so the key bytes
    /// are recorded by later key-exchange code. A change emits `PeerRekeyed`.
    pub fn record_public_key(
        &self,
        fingerprint: Fingerprint,
        public_key_blob: Vec<u8>,
    ) -> Option<PeerRekeyed> {
        record_public_key(&self.registry, &self.rekey_tx, fingerprint, public_key_blob)
    }

    /// Return the codec used by this discovery instance.
    pub fn codec(&self) -> &C {
        &self.codec
    }
}

impl<C: AnnouncementCodec> Drop for Discovery<C> {
    fn drop(&mut self) {
        self.receiver_task.abort();
        self.sender_task.abort();
    }
}

fn validate_settings(settings: &DiscoverySettings) -> Result<(), DiscoveryError> {
    if settings.discovery_port == 0 {
        return Err(DiscoveryError::InvalidPort);
    }

    if !settings.multicast_group.is_multicast() {
        return Err(DiscoveryError::InvalidMulticastGroup(
            settings.multicast_group,
        ));
    }

    if settings.announce_interval.is_zero() {
        return Err(DiscoveryError::InvalidAnnouncementInterval);
    }

    Ok(())
}

fn multicast_receiver_socket(settings: &DiscoverySettings) -> Result<UdpSocket, DiscoveryError> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).map_err(|source| {
        DiscoveryError::Socket {
            operation: "creating receiver socket",
            source,
        }
    })?;
    socket.set_reuse_address(true).map_err(|source| {
        DiscoveryError::Socket {
            operation: "enabling receiver address reuse",
            source,
        }
    })?;
    socket.set_nonblocking(true).map_err(|source| {
        DiscoveryError::Socket {
            operation: "setting receiver nonblocking mode",
            source,
        }
    })?;

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), settings.discovery_port);
    socket.bind(&bind_addr.into()).map_err(|source| DiscoveryError::Socket {
        operation: "binding receiver socket",
        source,
    })?;
    socket
        .join_multicast_v4(&settings.multicast_group, &settings.multicast_interface)
        .map_err(|source| DiscoveryError::Socket {
            operation: "joining multicast group",
            source,
        })?;
    socket
        .set_multicast_loop_v4(true)
        .map_err(|source| DiscoveryError::Socket {
            operation: "enabling multicast loopback on receiver",
            source,
        })?;

    UdpSocket::from_std(socket.into()).map_err(|source| DiscoveryError::Socket {
        operation: "wrapping receiver socket for tokio",
        source,
    })
}

fn multicast_sender_socket(settings: &DiscoverySettings) -> Result<UdpSocket, DiscoveryError> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).map_err(|source| {
        DiscoveryError::Socket {
            operation: "creating sender socket",
            source,
        }
    })?;
    socket.set_nonblocking(true).map_err(|source| {
        DiscoveryError::Socket {
            operation: "setting sender nonblocking mode",
            source,
        }
    })?;
    socket.set_multicast_ttl_v4(1).map_err(|source| {
        DiscoveryError::Socket {
            operation: "setting multicast ttl",
            source,
        }
    })?;
    socket
        .set_multicast_loop_v4(true)
        .map_err(|source| DiscoveryError::Socket {
            operation: "enabling multicast loopback on sender",
            source,
        })?;
    if settings.multicast_interface != Ipv4Addr::UNSPECIFIED {
        socket
            .set_multicast_if_v4(&settings.multicast_interface)
            .map_err(|source| DiscoveryError::Socket {
                operation: "selecting multicast interface",
                source,
            })?;
    }

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    socket.bind(&bind_addr.into()).map_err(|source| DiscoveryError::Socket {
        operation: "binding sender socket",
        source,
    })?;

    UdpSocket::from_std(socket.into()).map_err(|source| DiscoveryError::Socket {
        operation: "wrapping sender socket for tokio",
        source,
    })
}

async fn sender_loop<C: AnnouncementCodec>(
    socket: UdpSocket,
    settings: DiscoverySettings,
    local_node: LocalNode,
    codec: C,
) {
    let target = SocketAddr::new(
        IpAddr::V4(settings.multicast_group),
        settings.discovery_port,
    );
    let mut interval = tokio::time::interval(settings.announce_interval);

    loop {
        interval.tick().await;

        let announcement = DiscoveryAnnouncement {
            address: settings.listen_addr,
            port: local_node.listen_port,
            nick: local_node.nick.clone(),
            key_fingerprint: local_node.fingerprint,
        };
        let Ok(bytes) = codec.encode(&announcement) else {
            continue;
        };
        if bytes.len() > MAX_DISCOVERY_DATAGRAM_LEN {
            continue;
        }

        let _ = socket.send_to(&bytes, target).await;
    }
}

async fn receiver_loop<C: AnnouncementCodec>(
    socket: UdpSocket,
    registry: Arc<Mutex<HashMap<Fingerprint, PeerEntry>>>,
    rekey_tx: broadcast::Sender<PeerRekeyed>,
    codec: C,
) {
    let mut buffer = [0_u8; MAX_DISCOVERY_DATAGRAM_LEN];

    loop {
        let Ok((len, _from_addr)) = socket.recv_from(&mut buffer).await else {
            continue;
        };

        let Ok(announcement) = codec.decode(&buffer[..len]) else {
            continue;
        };

        upsert_peer(&registry, &rekey_tx, announcement, None);
    }
}

fn upsert_peer(
    registry: &Arc<Mutex<HashMap<Fingerprint, PeerEntry>>>,
    rekey_tx: &broadcast::Sender<PeerRekeyed>,
    announcement: DiscoveryAnnouncement,
    public_key_blob: Option<Vec<u8>>,
) {
    let now = Instant::now();
    let nick = String::from_utf8_lossy(&announcement.nick).into_owned();
    let listen_addr = SocketAddr::new(IpAddr::V4(announcement.address), announcement.port);
    let mut registry = registry.lock().expect("peer registry mutex poisoned");

    let existing_public_key_blob = registry
        .get(&announcement.key_fingerprint)
        .and_then(|entry| entry.public_key_blob.clone());

    if let (Some(old), Some(new)) = (&existing_public_key_blob, &public_key_blob) {
        if old != new {
            let _ = rekey_tx.send(PeerRekeyed {
                fingerprint: announcement.key_fingerprint,
                old_public_key_blob: old.clone(),
                new_public_key_blob: new.clone(),
            });
        }
    }

    registry.insert(
        announcement.key_fingerprint,
        PeerEntry {
            nick,
            listen_addr,
            fingerprint: announcement.key_fingerprint,
            public_key_blob: public_key_blob.or(existing_public_key_blob),
            last_seen: now,
        },
    );
}

fn record_public_key(
    registry: &Arc<Mutex<HashMap<Fingerprint, PeerEntry>>>,
    rekey_tx: &broadcast::Sender<PeerRekeyed>,
    fingerprint: Fingerprint,
    public_key_blob: Vec<u8>,
) -> Option<PeerRekeyed> {
    let mut registry = registry.lock().expect("peer registry mutex poisoned");
    let entry = registry.get_mut(&fingerprint)?;
    let old_public_key_blob = entry.public_key_blob.replace(public_key_blob.clone());

    match old_public_key_blob {
        Some(old_public_key_blob) if old_public_key_blob != public_key_blob => {
            let event = PeerRekeyed {
                fingerprint,
                old_public_key_blob,
                new_public_key_blob: public_key_blob,
            };
            let _ = rekey_tx.send(event.clone());
            Some(event)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU16, Ordering};
    use tokio::time::{sleep, timeout};

    static NEXT_PORT: AtomicU16 = AtomicU16::new(42091);

    #[derive(Debug, Clone)]
    struct TestCodec;

    impl AnnouncementCodec for TestCodec {
        type Error = &'static str;

        fn encode(&self, announcement: &DiscoveryAnnouncement) -> Result<Vec<u8>, Self::Error> {
            if announcement.nick.len() > u8::MAX as usize {
                return Err("nick too long");
            }

            let mut bytes = Vec::with_capacity(2 + 4 + 2 + 1 + announcement.nick.len() + 32);
            bytes.push(1);
            bytes.push(1);
            bytes.extend(announcement.address.octets());
            bytes.extend(announcement.port.to_be_bytes());
            bytes.push(announcement.nick.len() as u8);
            bytes.extend(&announcement.nick);
            bytes.extend(announcement.key_fingerprint);
            Ok(bytes)
        }

        fn decode(&self, bytes: &[u8]) -> Result<DiscoveryAnnouncement, Self::Error> {
            if bytes.len() < 2 + 4 + 2 + 1 + 32 {
                return Err("truncated");
            }
            if bytes[0] != 1 || bytes[1] != 1 {
                return Err("unsupported type or version");
            }

            let address = Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]);
            let port = u16::from_be_bytes([bytes[6], bytes[7]]);
            let nick_len = bytes[8] as usize;
            let expected_len = 2 + 4 + 2 + 1 + nick_len + 32;
            if bytes.len() != expected_len {
                return Err("invalid length");
            }

            let nick = bytes[9..9 + nick_len].to_vec();
            let mut key_fingerprint = [0_u8; 32];
            key_fingerprint.copy_from_slice(&bytes[9 + nick_len..]);

            Ok(DiscoveryAnnouncement {
                address,
                port,
                nick,
                key_fingerprint,
            })
        }
    }

    #[test]
    fn wire_codec_round_trips_discovery_announcement() {
        let codec = WireAnnouncementCodec;
        let announcement = DiscoveryAnnouncement {
            address: Ipv4Addr::new(192, 168, 1, 10),
            port: 40091,
            nick: b"alice".to_vec(),
            key_fingerprint: [0xaa; 32],
        };

        let encoded = codec.encode(&announcement).expect("encode announcement");
        let decoded = codec.decode(&encoded).expect("decode announcement");

        assert_eq!(decoded, announcement);
    }

    #[test]
    fn wire_codec_rejects_oversized_nick_without_panicking() {
        let codec = WireAnnouncementCodec;
        let announcement = DiscoveryAnnouncement {
            address: Ipv4Addr::LOCALHOST,
            port: 40091,
            nick: vec![b'a'; u8::MAX as usize + 1],
            key_fingerprint: [0xaa; 32],
        };

        assert_eq!(
            codec.encode(&announcement),
            Err(WireAnnouncementCodecError::NickTooLong { len: 256 })
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_nodes_discover_each_other_on_loopback() {
        let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        let settings = DiscoverySettings::new(
            Ipv4Addr::new(239, 255, 40, 91),
            port,
            Ipv4Addr::LOCALHOST,
        )
        .with_multicast_interface(Ipv4Addr::LOCALHOST)
        .with_announce_interval(Duration::from_millis(100));

        let first_fingerprint = [1_u8; 32];
        let second_fingerprint = [2_u8; 32];
        let first = Discovery::start_with_codec(
            settings.clone(),
            LocalNode {
                nick: b"alice".to_vec(),
                listen_port: 51001,
                fingerprint: first_fingerprint,
                public_key_blob: None,
            },
            TestCodec,
        )
        .await
        .expect("first discovery starts");
        let second = Discovery::start_with_codec(
            settings,
            LocalNode {
                nick: b"bob".to_vec(),
                listen_port: 51002,
                fingerprint: second_fingerprint,
                public_key_blob: None,
            },
            TestCodec,
        )
        .await
        .expect("second discovery starts");

        timeout(Duration::from_secs(10), async {
            loop {
                let first_registry = first.registry_snapshot();
                let second_registry = second.registry_snapshot();
                if first_registry.contains_key(&second_fingerprint)
                    && second_registry.contains_key(&first_fingerprint)
                {
                    break;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("both peers should discover each other");
    }

    #[tokio::test]
    async fn public_key_change_emits_rekey_event() {
        let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        let fingerprint = [7_u8; 32];
        let discovery = Discovery::start_with_codec(
            DiscoverySettings::new(Ipv4Addr::new(239, 255, 40, 91), port, Ipv4Addr::LOCALHOST)
                .with_multicast_interface(Ipv4Addr::LOCALHOST)
                .with_announce_interval(Duration::from_secs(60)),
            LocalNode {
                nick: b"local".to_vec(),
                listen_port: 51003,
                fingerprint: [9_u8; 32],
                public_key_blob: None,
            },
            TestCodec,
        )
        .await
        .expect("discovery starts");
        let mut rekey_rx = discovery.subscribe_rekey();

        upsert_peer(
            &discovery.registry,
            &discovery.rekey_tx,
            DiscoveryAnnouncement {
                address: Ipv4Addr::LOCALHOST,
                port: 51004,
                nick: b"remote".to_vec(),
                key_fingerprint: fingerprint,
            },
            Some(vec![1, 2, 3]),
        );

        let event = discovery
            .record_public_key(fingerprint, vec![4, 5, 6])
            .expect("changed key emits event");
        let broadcast = rekey_rx.recv().await.expect("rekey broadcast");

        assert_eq!(event, broadcast);
        assert_eq!(event.old_public_key_blob, vec![1, 2, 3]);
        assert_eq!(event.new_public_key_blob, vec![4, 5, 6]);
    }

    #[test]
    fn rejects_invalid_settings() {
        let error = validate_settings(&DiscoverySettings::new(
            Ipv4Addr::LOCALHOST,
            40091,
            Ipv4Addr::LOCALHOST,
        ))
        .expect_err("loopback is not multicast");

        assert!(matches!(
            error,
            DiscoveryError::InvalidMulticastGroup(Ipv4Addr::LOCALHOST)
        ));
    }
}
