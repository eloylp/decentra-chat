# CLI User Guide

The DecentraChat CLI is the current user-facing client. It can inspect local
configuration, initialize storage, manage local contacts, run bounded LAN
discovery, onboard discovered peers, exchange public keys, send and receive
encrypted messages, run a bounded stdin-driven chat session, and read
conversation history from SQLite.

The preferred path is contact-first: create a local identity, onboard a peer
into the contact book, trust the pinned fingerprint, then use `chat`. The lower
level `key-request`, `send`, and `receive` commands are still useful for testing
and debugging one part of the stack at a time.

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

## First Local Chat

This loopback script creates two isolated node profiles, generates two PGP
identities, onboards each peer as a trusted contact, sends two chat lines from
Alice to Bob, then prints Alice's conversation history.

```sh
set -eu

REPO_DIR="$(pwd)"
DEMO_DIR="$REPO_DIR/target/cli-guide-demo-$$"
mkdir -p "$DEMO_DIR"
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
  --config ./alice.toml onboard \
  --alias bob \
  --fingerprint "$BOB_FINGERPRINT" \
  --peer 127.0.0.1:52002 \
  --trust
kill "$BOB_KEY_SERVE_PID" 2>/dev/null || true
wait "$BOB_KEY_SERVE_PID" 2>/dev/null || true

cargo run --manifest-path "$REPO_DIR/Cargo.toml" -- \
  key-serve --public-key ./alice.public --listen 127.0.0.1:52002 --duration-ms 30000 \
  > alice-key-serve.log 2>&1 &
ALICE_KEY_SERVE_PID="$!"
sleep 1
cargo run --manifest-path "$REPO_DIR/Cargo.toml" -- \
  --config ./bob.toml onboard \
  --alias alice \
  --fingerprint "$ALICE_FINGERPRINT" \
  --peer 127.0.0.1:52002 \
  --trust
kill "$ALICE_KEY_SERVE_PID" 2>/dev/null || true
wait "$ALICE_KEY_SERVE_PID" 2>/dev/null || true

CONVERSATION_ID="11111111-1111-4111-8111-111111111111"

printf '' | cargo run --manifest-path "$REPO_DIR/Cargo.toml" -- \
  --config ./bob.toml chat \
  --secret-key ./bob.secret \
  --contact alice \
  --peer 127.0.0.1:52003 \
  --listen 127.0.0.1:52004 \
  --conversation "$CONVERSATION_ID" \
  --duration-ms 3000 \
  > bob-chat.log 2>&1 &
BOB_CHAT_PID="$!"
sleep 1

printf 'first message\nsecond message\n' | cargo run --manifest-path "$REPO_DIR/Cargo.toml" -- \
  --config ./alice.toml chat \
  --secret-key ./alice.secret \
  --contact bob \
  --peer 127.0.0.1:52004 \
  --listen 127.0.0.1:52003 \
  --conversation "$CONVERSATION_ID" \
  --duration-ms 500

wait "$BOB_CHAT_PID"
cat bob-chat.log

cargo run --manifest-path "$REPO_DIR/Cargo.toml" -- \
  --config ./alice.toml conversations
cargo run --manifest-path "$REPO_DIR/Cargo.toml" -- \
  --config ./alice.toml history --conversation "$CONVERSATION_ID"
```

Run the script from the repository root. It stores demo keys, config files, and
SQLite databases in a temporary directory. The `chat` sessions are bounded, so
they exit after `--duration-ms` even when no more messages arrive.

## Onboard a Peer

`onboard` is the shortest path from a discovery row to a trusted local contact.
Pass the advertised peer address, advertised fingerprint, and the alias you want
to use locally. The command runs the TCP key-exchange protocol, verifies that
the fetched public key matches the advertised fingerprint, stores the peer key,
and creates or updates the contact record.

```sh
cargo run -- --config ./alice.toml onboard \
  --alias bob \
  --fingerprint "$BOB_FINGERPRINT" \
  --peer 127.0.0.1:52002 \
  --trust
```

`--trust` is the explicit non-interactive trust decision. Use it only after you
have verified the fingerprint through discovery or another channel. Omit it to
fetch and store the key as an untrusted contact, then run `contact trust bob`
after verifying the fingerprint out of band.

If an alias already belongs to a different fingerprint, onboarding fails before
requesting a new key. That refusal is the fingerprint-change warning: the CLI
will not silently replace a pinned alias with a different peer identity.

If the peer returns a public key with a different fingerprint than the one you
passed, onboarding fails and prints both fingerprints. Re-run discovery or
verify the peer manually before trusting the new value.

## Contact Book and Trust

Contacts are local aliases pinned to peer fingerprints in the configured SQLite
store. `chat` requires a trusted contact with a stored public key. The lower
level `key-request`, `send`, `receive`, `conversations`, and `history` commands
still accept the same fingerprint arguments as before.

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

## Bounded Chat Session

`chat` opens one conversation with one trusted contact. It prints the current
conversation history, listens for inbound messages until `--duration-ms`
expires, and sends each non-empty stdin line through the same encrypted TCP path
used by `send`. Sent messages are persisted with their ACK state, and received
messages are persisted for later history reads.

```sh
printf 'first message\nsecond message\n' | cargo run -- --config ./alice.toml chat \
  --secret-key ./alice.secret \
  --contact bob \
  --peer 127.0.0.1:52003 \
  --listen 127.0.0.1:52004 \
  --conversation 11111111-1111-4111-8111-111111111111 \
  --duration-ms 30000
```

Start the peer's `chat` command first with the opposite `--peer` and `--listen`
addresses. Close stdin on a receive-only session; it will continue polling
inbound messages until the bounded duration expires.

`chat` refuses untrusted contacts and contacts without stored public keys. Use
`onboard --trust` for the usual setup, or combine `key-request`, `contact add`,
and `contact trust` when you need to test each step separately.

## Local Peer Discovery

Discovery is bounded. The command announces the local node for a fixed duration,
prints progress once per second, then prints the peer table visible from the
local registry.

```sh
cargo run -- --config ./decentra-chat.toml discover \
  --nick local \
  --fingerprint "$ALICE_FINGERPRINT" \
  --listen-port 51001 \
  --multicast-interface 127.0.0.1 \
  --duration-ms 3000 \
  --announce-interval-ms 1000
```

Use the fingerprint printed by `keygen`. The advertised `--listen-port` should
be the TCP port where the peer can serve follow-up commands such as
`key-serve`.

## Key Exchange Reference

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

`key-request` only stores the peer key. It does not create an alias or mark the
peer trusted; use `onboard` for the usual user-facing path.

## One-Message Send and Receive

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

`error: contact 'bob' is not trusted`

Run `contact show bob` and verify the fingerprint. If it is the peer you expect,
run `contact trust bob`. For the normal setup flow, use `onboard --trust` after
verifying the advertised fingerprint.

`error: contact 'bob' has no stored public key`

Run `onboard --alias bob --fingerprint <HEX> --peer <ADDR> --trust` while the
peer is serving its public key, or run `key-request --peer <ADDR>` against the
peer's `key-serve` command when testing the lower-level flow.

`error: contact alias 'bob' is already pinned to fingerprint ...`

The alias already points at a different fingerprint. Do not overwrite it until
you have verified whether the peer re-keyed, you selected the wrong alias, or a
different node is advertising the same name.

`error: peer at ... returned fingerprint ..., but discovery advertised ...`

The key served over TCP does not match the fingerprint you passed to `onboard`.
Re-run discovery or verify the peer through another channel before trusting it.

`error: peer key ... is not in storage`

Run `key-request --peer <ADDR>` against the peer's `key-serve` command, using
the same `--config` file you will use for `send` or `receive`. The contact-first
alternative is `onboard`, which stores the key and creates the alias together.

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
- There is no TUI, background daemon, or automatic retry loop yet.
- Discovery is local-network multicast. It does not cross routers without
  network support.
- Conversation history is local storage state. It does not fetch missing
  predecessors or resolve message-chain forks across peers.
