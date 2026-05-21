# DecentraChat

> **Status:** Early development — v0.1 in progress.

DecentraChat is a serverless, peer-to-peer chat application for local networks. Peers discover each other via UDP multicast, authenticate with PGP keys, and exchange end-to-end encrypted messages — no servers, no accounts, no phone numbers required. It is designed for privacy-conscious users, air-gapped environments, and network-restricted situations such as conferences or disaster relief operations.

## Prerequisites

- Rust stable toolchain — install via [rustup.rs](https://rustup.rs)

No additional system dependencies are required.

## Build

```bash
cargo build
```

## Test

```bash
cargo test
```

## Quickstart

> **Coming in v0.1.** Once peer discovery lands, this section will show how to run two instances on the same LAN so they discover each other automatically.

## Protocol specification

The wire format, message types, cryptographic design, and full rationale are documented in [PAPER.md](PAPER.md).

## Contributing

A contributor guide covering prerequisites, architecture orientation, and module layout is coming in v0.1. See [CONTRIBUTING.md](CONTRIBUTING.md) *(not yet written)*.
