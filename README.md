# DecentraChat

![](https://img.shields.io/static/v1?label=Status&message=Early+development+%E2%80%94+v0.1+in+progress&color=orange)

DecentraChat is a serverless, peer-to-peer chat application that uses PGP encryption over LAN multicast. There is no central server: peers discover each other on the local network and exchange end-to-end encrypted, cryptographically signed messages. It is designed for privacy-conscious users, air-gapped networks, and settings like conferences or events where participants share a local network.

## Prerequisites

- Rust stable toolchain — install via [rustup.rs](https://rustup.rs)

## Build

```sh
cargo build
```

## Test

```sh
cargo test
```

## Quickstart

Inspect the non-secret node configuration and initialize the local SQLite storage:

```sh
cargo run -- status
```

Use a specific config file:

```sh
cargo run -- --config ./config.toml status
```

Show the current command surface:

```sh
cargo run -- --help
```

Run a bounded local peer discovery session and print the visible peers:

```sh
cargo run -- discover --duration-ms 5000 --announce-interval-ms 1000 --nick local --fingerprint 0000000000000000000000000000000000000000000000000000000000000000
```

When testing multicast loopback on one machine, bind discovery to loopback explicitly:

```sh
cargo run -- --config ./config.toml discover --multicast-interface 127.0.0.1 --listen-port 51001 --duration-ms 3000
```

Generate two local identities:

```sh
cargo run -- keygen --secret-key ./alice.secret --public-key ./alice.public
cargo run -- keygen --secret-key ./bob.secret --public-key ./bob.public
```

Create separate local configs and SQLite stores for the loopback example:

```sh
cat > alice.toml <<'EOF'
multicast_group = "239.255.40.91"
discovery_port = 40091
listen_addr = "127.0.0.1"
storage_path = "./alice.sqlite3"
EOF
cat > bob.toml <<'EOF'
multicast_group = "239.255.40.91"
discovery_port = 40091
listen_addr = "127.0.0.1"
storage_path = "./bob.sqlite3"
EOF
```

In terminal 1, serve Bob's public key:

```sh
cargo run -- key-serve --public-key ./bob.public --listen 127.0.0.1:52002 --duration-ms 30000
```

In terminal 2, request and store Bob's key in Alice's configured storage:

```sh
cargo run -- --config ./alice.toml key-request --peer 127.0.0.1:52002
```

Then serve Alice's public key:

```sh
cargo run -- key-serve --public-key ./alice.public --listen 127.0.0.1:52002 --duration-ms 30000
```

And request it into Bob's configured storage:

```sh
cargo run -- --config ./bob.toml key-request --peer 127.0.0.1:52002
```

Use the fingerprint printed by `keygen` or `key-request` as `BOB_FINGERPRINT`.
Use Alice's fingerprint as `ALICE_FINGERPRINT`.

In terminal 1, receive one encrypted message as Bob:

```sh
cargo run -- --config ./bob.toml receive --secret-key ./bob.secret --peer-fingerprint ALICE_FINGERPRINT --listen 127.0.0.1:52003 --duration-ms 30000
```

In terminal 2, send one encrypted signed message as Alice and persist the ACK:

```sh
cargo run -- --config ./alice.toml send --secret-key ./alice.secret --peer-fingerprint BOB_FINGERPRINT --peer 127.0.0.1:52003 --conversation 11111111-1111-4111-8111-111111111111 "hello bob"
```

List conversations stored in Alice's local database:

```sh
cargo run -- --config ./alice.toml conversations
```

Show the ordered message history for a conversation, including delivery and reply-validation state:

```sh
cargo run -- --config ./alice.toml history --conversation 11111111-1111-4111-8111-111111111111
```

## Protocol and architecture

The full protocol design — peer discovery, key exchange, message format, acknowledgement, and ordering — is documented in [PAPER.md](PAPER.md).

The implemented v0.3 conversation read model is documented in [docs/CONVERSATION_ENGINE.md](docs/CONVERSATION_ENGINE.md).

## Contributing

A contributor guide is still in progress. For now, use the build and test commands above.
