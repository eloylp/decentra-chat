# CLI User Guide

The DecentraChat CLI is the current user-facing client. It can inspect local
configuration, initialize storage, manage local contacts, run bounded LAN
discovery, exchange public keys, send and receive one encrypted message, and
read conversation history from SQLite.

The commands below describe what is implemented in `src/cli.rs` today. There is
no TUI or long-running chat daemon yet.

## Setup

Install the Rust stable toolchain, then build from the repository root:

```sh
cargo build
```

Run the full test suite with the stack size used by the current CLI and
conversation-engine work:

```sh
RUST_MIN_STACK=16777216 cargo test
```

Print the command surface:

```sh
cargo run -- --help
```

## Configuration and Storage

`decentra-chat` loads configuration from `DC_CONFIG` when that environment
variable is set. Otherwise it uses the platform config directory and appends
`decentra-chat/config.toml`.

When the config file does not exist, the CLI uses these defaults:

| Field | Default |
|-------|---------|
| `multicast_group` | `239.255.40.91` |
| `discovery_port` | `40091` |
| `listen_addr` | `0.0.0.0` |
| `storage_path` | platform config directory plus `decentra-chat/decentra-chat.sqlite3` |

Run `status` to print the non-secret settings and create the SQLite database if
needed:

```sh
cargo run -- status
```

Use an explicit config for local testing:

```sh
cat > ./decentra-chat.toml <<'EOF'
multicast_group = "239.255.40.91"
discovery_port = 40091
listen_addr = "127.0.0.1"
storage_path = "./decentra-chat.sqlite3"
EOF

cargo run -- --config ./decentra-chat.toml status
```

## Local Peer Discovery

Discovery is bounded. The command announces the local node for a fixed duration,
prints progress once per second, then prints the peer table visible from the
local registry.

```sh
cargo run -- --config ./decentra-chat.toml discover \
  --nick local \
  --fingerprint 0000000000000000000000000000000000000000000000000000000000000000 \
  --listen-port 51001 \
  --multicast-interface 127.0.0.1 \
  --duration-ms 3000 \
  --announce-interval-ms 1000
```

Use a real key fingerprint after generating an identity. The all-zero
fingerprint is only useful for checking that the discovery command starts and
prints the expected table.

## Loopback Chat Quickstart

This script creates two local node profiles, exchanges public keys over the TCP
key-exchange command, sends one encrypted signed message from Alice to Bob, then
prints the conversation list and history from Alice's storage.

```sh
set -eu

REPO_DIR="$(pwd)"
DEMO_DIR="$(mktemp -d)"
cd "$DEMO_DIR"

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

cargo run --manifest-path "$REPO_DIR/Cargo.toml" -- \
  keygen --secret-key ./alice.secret --public-key ./alice.public \
  | tee alice-keygen.txt
cargo run --manifest-path "$REPO_DIR/Cargo.toml" -- \
  keygen --secret-key ./bob.secret --public-key ./bob.public \
  | tee bob-keygen.txt

ALICE_FINGERPRINT="$(awk -F= '/fingerprint=/{print $2}' alice-keygen.txt)"
BOB_FINGERPRINT="$(awk -F= '/fingerprint=/{print $2}' bob-keygen.txt)"

cargo run --manifest-path "$REPO_DIR/Cargo.toml" -- \
  key-serve --public-key ./bob.public --listen 127.0.0.1:52002 --duration-ms 30000 \
  > bob-key-serve.log 2>&1 &
BOB_KEY_SERVE_PID="$!"
sleep 1
cargo run --manifest-path "$REPO_DIR/Cargo.toml" -- \
  --config ./alice.toml key-request --peer 127.0.0.1:52002
kill "$BOB_KEY_SERVE_PID" 2>/dev/null || true
wait "$BOB_KEY_SERVE_PID" 2>/dev/null || true

cargo run --manifest-path "$REPO_DIR/Cargo.toml" -- \
  key-serve --public-key ./alice.public --listen 127.0.0.1:52002 --duration-ms 30000 \
  > alice-key-serve.log 2>&1 &
ALICE_KEY_SERVE_PID="$!"
sleep 1
cargo run --manifest-path "$REPO_DIR/Cargo.toml" -- \
  --config ./bob.toml key-request --peer 127.0.0.1:52002
kill "$ALICE_KEY_SERVE_PID" 2>/dev/null || true
wait "$ALICE_KEY_SERVE_PID" 2>/dev/null || true

CONVERSATION_ID="11111111-1111-4111-8111-111111111111"

cargo run --manifest-path "$REPO_DIR/Cargo.toml" -- \
  --config ./bob.toml receive \
  --secret-key ./bob.secret \
  --peer-fingerprint "$ALICE_FINGERPRINT" \
  --listen 127.0.0.1:52003 \
  --duration-ms 30000 \
  > bob-receive.log 2>&1 &
BOB_RECEIVE_PID="$!"
sleep 1

cargo run --manifest-path "$REPO_DIR/Cargo.toml" -- \
  --config ./alice.toml send \
  --secret-key ./alice.secret \
  --peer-fingerprint "$BOB_FINGERPRINT" \
  --peer 127.0.0.1:52003 \
  --conversation "$CONVERSATION_ID" \
  "hello bob"

wait "$BOB_RECEIVE_PID"
cat bob-receive.log

cargo run --manifest-path "$REPO_DIR/Cargo.toml" -- \
  --config ./alice.toml conversations
cargo run --manifest-path "$REPO_DIR/Cargo.toml" -- \
  --config ./alice.toml history --conversation "$CONVERSATION_ID"
```

Run the script from the repository root. It stores demo keys, config files, and
SQLite databases in a temporary directory.

## Key Exchange

Generate a local PGP identity:

```sh
cargo run -- keygen --secret-key ./alice.secret --public-key ./alice.public
```

The command writes both key files and prints the DecentraChat fingerprint. The
secret key is used for signing and decrypting local messages. The public key is
served to peers.

Serve a public key for a bounded window:

```sh
cargo run -- key-serve --public-key ./alice.public --listen 127.0.0.1:52002 --duration-ms 30000
```

Request a peer public key and persist it in the configured SQLite store:

```sh
cargo run -- --config ./bob.toml key-request --peer 127.0.0.1:52002
```

`send` and `receive` require the peer fingerprint to exist in local storage.
When it is missing, the CLI exits with an error that points back to
`key-request`.

## Contact Book and Trust

Contacts are local aliases pinned to peer fingerprints in the configured SQLite
store. They do not replace raw fingerprint workflows yet; `key-request`, `send`,
`receive`, `conversations`, and `history` still accept the same fingerprint
arguments as before.

Add or update an alias for a fingerprint:

```sh
cargo run -- --config ./alice.toml contact add \
  --alias bob \
  --fingerprint "$BOB_FINGERPRINT"
```

List contacts:

```sh
cargo run -- --config ./alice.toml contact list
```

Show one contact by alias or fingerprint:

```sh
cargo run -- --config ./alice.toml contact show bob
cargo run -- --config ./alice.toml contact show "$BOB_FINGERPRINT"
```

Mark a contact as explicitly trusted/pinned after verifying the fingerprint:

```sh
cargo run -- --config ./alice.toml contact trust bob
```

Contact output is tab-separated:

```text
alias	fingerprint	public_key_present	trust_state	created_at	updated_at
```

Aliases are case-insensitive for lookup and uniqueness. The CLI rejects empty
aliases, aliases with leading or trailing spaces, control characters, tabs, or
newlines, and aliases longer than 64 bytes. Reusing an alias for a different
fingerprint fails with an actionable conflict error.

## Sending and Receiving

`receive` waits for one encrypted signed message from a known peer, persists the
accepted message, then exits:

```sh
cargo run -- --config ./bob.toml receive \
  --secret-key ./bob.secret \
  --peer-fingerprint "$ALICE_FINGERPRINT" \
  --listen 127.0.0.1:52003 \
  --duration-ms 30000
```

`send` encrypts and signs one plaintext message for a known peer, waits for the
ACK, persists the sent message and ACK state locally, then exits:

```sh
cargo run -- --config ./alice.toml send \
  --secret-key ./alice.secret \
  --peer-fingerprint "$BOB_FINGERPRINT" \
  --peer 127.0.0.1:52003 \
  --conversation 11111111-1111-4111-8111-111111111111 \
  "hello bob"
```

When `--conversation` is omitted, `send` creates a new UUID v4. Use
`--previous-hash` when appending to an existing message chain. The default
previous hash is the zero hash, which starts a chain segment.

## Delivery State and History

List locally known conversations:

```sh
cargo run -- --config ./alice.toml conversations
```

Show ordered history for one conversation:

```sh
cargo run -- --config ./alice.toml history \
  --conversation 11111111-1111-4111-8111-111111111111
```

History output is tab-separated:

```text
message_uuid	sender_fingerprint	timestamp	delivery_state	reply_state	payload
```

`delivery_state` is `unknown` until a matching ACK is stored. Sent messages that
receive an ACK are printed as `acknowledged:<unix_timestamp>`.

`reply_state` is one of `none`, `valid:<uuid>:<hash>`,
`unresolved:<uuid>:<hash>`, or `invalid:<uuid>:<hash>`. These states come from
the conversation engine's validation of persisted reply metadata.

## Troubleshooting

`error: failed to load config from ... invalid config field`

Check the named field in your TOML file. Unknown fields are rejected, IP fields
must parse as IP addresses, `discovery_port` must be non-zero, and
`storage_path` must not be empty.

`error: failed to initialize SQLite storage at ...`

Check that the parent directory is writable. `status` opens storage and applies
migrations, so it is the quickest way to verify a profile before running network
commands.

`error: peer key ... is not in storage`

Run `key-request --peer <ADDR>` against the peer's `key-serve` command, using
the same `--config` file you will use for `send` or `receive`.

`error: receive timed out after ... ms without an accepted message`

Start `receive` before `send`, verify both commands use each other's
fingerprints, and confirm that the `--listen` address on `receive` matches the
`--peer` address on `send`.

Discovery prints no peers

Use an IPv4 `listen_addr`, bind `--multicast-interface` to the interface you are
testing, and make sure peers share the same `multicast_group` and
`discovery_port`. Local loopback multicast behavior varies by operating system,
so test on the target LAN when possible.

## Current Limits

- Commands are intentionally bounded and exit after one operation or a fixed
  duration.
- There is no TUI, background daemon, contact book, or automatic retry loop yet.
- Discovery is local-network multicast. It does not cross routers without
  network support.
- Conversation history is local storage state. It does not fetch missing
  predecessors or resolve message-chain forks across peers.
