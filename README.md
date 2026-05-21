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
RUST_MIN_STACK=16777216 cargo test
```

## Quickstart

Start by checking the effective configuration and initializing the local SQLite
store:

```sh
cargo run -- status
```

Use `--config` when you want an isolated node profile:

```sh
cargo run -- --config ./config.toml status
```

For a complete loopback walkthrough with two local identities, key exchange,
message send/receive, delivery state, and conversation history, follow the
[CLI user guide](docs/CLI_GUIDE.md).

Show the command surface at any time:

```sh
cargo run -- --help
```

## Protocol and architecture

The full protocol design — peer discovery, key exchange, message format, acknowledgement, and ordering — is documented in [PAPER.md](PAPER.md).

The implemented v0.3 conversation read model is documented in [docs/CONVERSATION_ENGINE.md](docs/CONVERSATION_ENGINE.md).

The implemented CLI workflows are documented in [docs/CLI_GUIDE.md](docs/CLI_GUIDE.md).

## Contributing

A contributor guide is still in progress. For now, use the build and test commands above.
