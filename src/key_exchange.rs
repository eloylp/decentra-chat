use crate::{
    codec::{self, KeyExchangeReq, KeyExchangeResp, Message},
    crypto,
    discovery::Fingerprint,
    storage::{PeerKeyRecord, PeerKeyUpsert, Storage, StorageError},
};
use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
};

const WIRE_KEY_EXCHANGE_VERSION: u8 = 1;
const MAX_KEY_EXCHANGE_FRAME_LEN: usize = 1 + 1 + 2 + u16::MAX as usize;

/// Local key material advertised by the TCP key-exchange responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalKeyMaterial {
    pub public_key: Vec<u8>,
}

impl LocalKeyMaterial {
    /// Build key material from serialized public-key bytes after validating that
    /// the bytes are parseable by the configured PGP implementation.
    pub fn from_public_key(public_key: Vec<u8>) -> Result<Self, KeyExchangeError> {
        verify_public_key(&public_key)?;
        Ok(Self { public_key })
    }

    pub fn fingerprint(&self) -> Fingerprint {
        crypto::fingerprint(&self.public_key)
    }
}

/// Running TCP key-exchange responder.
pub struct KeyExchangeService {
    local_addr: SocketAddr,
    task: JoinHandle<()>,
}

/// Errors returned by TCP key-exchange listener, connector, and storage paths.
#[derive(Debug, Error)]
pub enum KeyExchangeError {
    #[error("TCP key-exchange listener bind failed at {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("TCP key-exchange local address is unavailable: {0}")]
    LocalAddr(#[source] std::io::Error),
    #[error("TCP key-exchange connection to {addr} failed: {source}")]
    Connect {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("TCP key-exchange I/O failed while {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("TCP key-exchange frame length {len} exceeds max {max}")]
    FrameTooLarge { len: usize, max: usize },
    #[error("TCP key-exchange codec rejected message: {0}")]
    Codec(#[from] codec::CodecError),
    #[error("expected key-exchange response, received {received}")]
    UnexpectedResponse { received: &'static str },
    #[error("expected key-exchange request, received {received}")]
    UnexpectedRequest { received: &'static str },
    #[error("peer key verification failed: {0}")]
    InvalidPeerKey(#[source] crypto::CryptoError),
    #[error("failed to persist peer key: {0}")]
    Storage(#[from] StorageError),
    #[error("system clock is before the Unix epoch")]
    InvalidSystemTime,
}

impl KeyExchangeService {
    /// Bind a TCP listener and start answering type-2 requests with type-3
    /// responses containing the local public key material.
    pub async fn start(
        listen_addr: SocketAddr,
        local_key: LocalKeyMaterial,
    ) -> Result<Self, KeyExchangeError> {
        let listener = TcpListener::bind(listen_addr)
            .await
            .map_err(|source| KeyExchangeError::Bind {
                addr: listen_addr,
                source,
            })?;
        let local_addr = listener
            .local_addr()
            .map_err(KeyExchangeError::LocalAddr)?;

        let task = tokio::spawn(async move {
            listener_loop(listener, local_key).await;
        });

        Ok(Self { local_addr, task })
    }

    /// Return the bound address. This is especially useful when tests bind port 0.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for KeyExchangeService {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Connect to a peer, request its public key, verify it, and persist it by
/// DecentraChat fingerprint.
pub async fn request_peer_key(
    peer_addr: SocketAddr,
    storage: &Storage,
) -> Result<PeerKeyRecord, KeyExchangeError> {
    let mut stream = TcpStream::connect(peer_addr)
        .await
        .map_err(|source| KeyExchangeError::Connect {
            addr: peer_addr,
            source,
        })?;

    write_message(
        &mut stream,
        Message::KeyExchangeReq(KeyExchangeReq {
            version: WIRE_KEY_EXCHANGE_VERSION,
        }),
    )
    .await?;

    let response = read_message(&mut stream).await?;
    let Message::KeyExchangeResp(response) = response else {
        return Err(KeyExchangeError::UnexpectedResponse {
            received: response.name(),
        });
    };

    persist_peer_key(storage, response.key_data)
}

async fn listener_loop(listener: TcpListener, local_key: LocalKeyMaterial) {
    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let Ok((stream, _peer_addr)) = accept_result else {
                    continue;
                };
                let local_key = local_key.clone();
                connections.spawn(async move {
                    let _ = handle_connection(stream, local_key).await;
                });
            }
            Some(_result) = connections.join_next() => {}
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    local_key: LocalKeyMaterial,
) -> Result<(), KeyExchangeError> {
    let request = read_message(&mut stream).await?;
    let Message::KeyExchangeReq(_request) = request else {
        return Err(KeyExchangeError::UnexpectedRequest {
            received: request.name(),
        });
    };

    write_message(
        &mut stream,
        Message::KeyExchangeResp(KeyExchangeResp {
            version: WIRE_KEY_EXCHANGE_VERSION,
            key_data: local_key.public_key,
        }),
    )
    .await
}

fn persist_peer_key(
    storage: &Storage,
    public_key: Vec<u8>,
) -> Result<PeerKeyRecord, KeyExchangeError> {
    verify_public_key(&public_key)?;
    let fingerprint = crypto::fingerprint(&public_key);
    let last_seen = unix_timestamp()?;

    storage
        .upsert_peer_key(PeerKeyUpsert {
            fingerprint,
            nick: None,
            public_key,
            last_seen,
        })
        .map_err(KeyExchangeError::Storage)
}

fn verify_public_key(public_key: &[u8]) -> Result<(), KeyExchangeError> {
    crypto::public_key_from_bytes(public_key)
        .map(|_| ())
        .map_err(KeyExchangeError::InvalidPeerKey)
}

async fn read_message(stream: &mut TcpStream) -> Result<Message, KeyExchangeError> {
    let len = stream
        .read_u32()
        .await
        .map_err(|source| KeyExchangeError::Io {
            operation: "reading frame length",
            source,
        })? as usize;
    if len > MAX_KEY_EXCHANGE_FRAME_LEN {
        return Err(KeyExchangeError::FrameTooLarge {
            len,
            max: MAX_KEY_EXCHANGE_FRAME_LEN,
        });
    }

    let mut bytes = vec![0_u8; len];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|source| KeyExchangeError::Io {
            operation: "reading frame payload",
            source,
        })?;

    Message::try_from(bytes.as_slice()).map_err(KeyExchangeError::Codec)
}

async fn write_message(stream: &mut TcpStream, message: Message) -> Result<(), KeyExchangeError> {
    let bytes: Vec<u8> = message.into();
    if bytes.len() > MAX_KEY_EXCHANGE_FRAME_LEN {
        return Err(KeyExchangeError::FrameTooLarge {
            len: bytes.len(),
            max: MAX_KEY_EXCHANGE_FRAME_LEN,
        });
    }

    stream
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|source| KeyExchangeError::Io {
            operation: "writing frame length",
            source,
        })?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|source| KeyExchangeError::Io {
            operation: "writing frame payload",
            source,
        })?;
    stream.flush().await.map_err(|source| KeyExchangeError::Io {
        operation: "flushing frame",
        source,
    })
}

fn unix_timestamp() -> Result<i64, KeyExchangeError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| KeyExchangeError::InvalidSystemTime)?;
    i64::try_from(duration.as_secs()).map_err(|_| KeyExchangeError::InvalidSystemTime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{public_key_to_bytes, KeyPair};
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::AsyncReadExt;
    use tokio::time::{timeout, Duration};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn requester_stores_responders_verified_key() {
        let responder_keypair = KeyPair::generate().expect("generate responder keypair");
        let responder_public_key =
            public_key_to_bytes(&responder_keypair.public).expect("serialize responder key");
        let responder_fingerprint = crypto::fingerprint(&responder_public_key);
        let local_key =
            LocalKeyMaterial::from_public_key(responder_public_key.clone()).expect("local key");
        let responder = KeyExchangeService::start(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            local_key,
        )
        .await
        .expect("start key-exchange responder");

        let dir = tempfile::tempdir().expect("tempdir");
        let requester_storage =
            Storage::open(dir.path().join("requester.sqlite3")).expect("open storage");

        let record = timeout(
            Duration::from_secs(10),
            request_peer_key(responder.local_addr(), &requester_storage),
        )
        .await
        .expect("key exchange should finish")
        .expect("request peer key");

        assert_eq!(record.fingerprint, responder_fingerprint);
        assert_eq!(record.public_key, responder_public_key);
        assert_eq!(record.nick, None);
        assert_eq!(
            requester_storage
                .get_peer_key(responder_fingerprint)
                .expect("fetch peer key")
                .expect("stored key"),
            record
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn requester_rejects_non_key_exchange_response() {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            read_message(&mut stream).await.expect("read request");
            write_message(
                &mut stream,
                Message::KeyExchangeReq(KeyExchangeReq {
                    version: WIRE_KEY_EXCHANGE_VERSION,
                }),
            )
            .await
            .expect("write wrong response");
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path().join("requester.sqlite3")).expect("open storage");
        let error = request_peer_key(addr, &storage)
            .await
            .expect_err("wrong response is rejected");

        assert!(matches!(
            error,
            KeyExchangeError::UnexpectedResponse {
                received: "key-exchange request"
            }
        ));
        server.await.expect("server task");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_service_cancels_stalled_connection_handlers() {
        let responder_keypair = KeyPair::generate().expect("generate responder keypair");
        let responder_public_key =
            public_key_to_bytes(&responder_keypair.public).expect("serialize responder key");
        let local_key = LocalKeyMaterial::from_public_key(responder_public_key).expect("local key");
        let responder = KeyExchangeService::start(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            local_key,
        )
        .await
        .expect("start key-exchange responder");

        let mut stalled_stream = TcpStream::connect(responder.local_addr())
            .await
            .expect("connect stalled peer");

        drop(responder);

        let mut byte = [0_u8; 1];
        let read_result = timeout(Duration::from_secs(2), stalled_stream.read(&mut byte))
            .await
            .expect("service shutdown should close stalled connection");

        match read_result {
            Ok(0) => {}
            Ok(n) => panic!("expected shutdown to close connection, read {n} byte(s)"),
            Err(error) => {
                assert!(
                    matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ),
                    "unexpected read error after shutdown: {error}"
                );
            }
        }
    }

    #[test]
    fn local_key_material_rejects_invalid_public_key_bytes() {
        let error = LocalKeyMaterial::from_public_key(b"not a pgp key".to_vec())
            .expect_err("invalid key bytes are rejected");

        assert!(matches!(error, KeyExchangeError::InvalidPeerKey(_)));
    }

    #[test]
    fn local_key_material_reports_stable_fingerprint() {
        let keypair = KeyPair::generate().expect("generate keypair");
        let public_key = public_key_to_bytes(&keypair.public).expect("serialize key");
        let local_key = LocalKeyMaterial::from_public_key(public_key.clone()).expect("local key");

        assert_eq!(local_key.fingerprint(), crypto::fingerprint(&public_key));
    }
}
