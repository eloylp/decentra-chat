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

Peer discovery and message sending are planned for later v1.0 work.

## Protocol and architecture

The full protocol design — peer discovery, key exchange, message format, acknowledgement, and ordering — is documented in [PAPER.md](PAPER.md).

The implemented v0.3 conversation read model is documented in [docs/CONVERSATION_ENGINE.md](docs/CONVERSATION_ENGINE.md).

## Contributing

A contributor guide is still in progress. For now, use the build and test commands above.
