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

> TODO: coming in v0.1 — run two instances on the same LAN and they will discover each other automatically via IP multicast.

## Protocol specification

The full protocol design — peer discovery, key exchange, message format, acknowledgement, and ordering — is documented in [PAPER.md](PAPER.md).

## Contributing

A contributor guide is in progress. See [CONTRIBUTING.md](CONTRIBUTING.md) once it lands.
