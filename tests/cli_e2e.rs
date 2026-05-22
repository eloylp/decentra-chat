use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const CLI_TIMEOUT: Duration = Duration::from_secs(60);
const BACKGROUND_READY_TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn status_bootstraps_configured_storage_without_home_state() {
    let fixture = TestFixture::new("status-bootstrap");
    let storage_path = fixture.path("state/chat.sqlite3");
    let config_path = fixture.write_config("alice.toml", 45101, &storage_path);

    let output = fixture.cli(["--config", path_arg(&config_path), "status"], "status");

    assert_success(&output, "status");
    let stdout = stdout(&output);
    assert!(storage_path.exists(), "status should create configured storage");
    assert!(stdout.contains("DecentraChat status"), "{stdout}");
    assert!(stdout.contains("listen_addr: 127.0.0.1"), "{stdout}");
    assert!(
        stdout.contains(&format!("storage_path: {}", storage_path.display())),
        "{stdout}"
    );
    assert!(stdout.contains("storage: ready"), "{stdout}");
}

#[test]
fn discover_runs_with_bounded_loopback_runtime_and_exits_cleanly() {
    let fixture = TestFixture::new("bounded-discovery");
    let discovery_port = fixture.unique_udp_port();
    let storage_path = fixture.path("state/discovery.sqlite3");
    let config_path = fixture.write_config("discovery.toml", discovery_port, &storage_path);
    let fingerprint = "1111111111111111111111111111111111111111111111111111111111111111";

    let output = fixture.cli(
        [
            "--config",
            path_arg(&config_path),
            "discover",
            "--nick",
            "alice",
            "--fingerprint",
            fingerprint,
            "--listen-port",
            "55101",
            "--multicast-interface",
            "127.0.0.1",
            "--duration-ms",
            "250",
            "--announce-interval-ms",
            "50",
        ],
        "bounded discover",
    );

    assert_success(&output, "discover");
    let stdout = stdout(&output);
    assert!(stdout.contains("discovery: running for 250 ms"), "{stdout}");
    assert!(stdout.contains("discovery: elapsed_ms="), "{stdout}");
    assert!(stdout.contains("peers:"), "{stdout}");
    assert!(
        stdout.contains("nick\tfingerprint\taddress\tlast_seen_ms_ago"),
        "{stdout}"
    );
}

#[test]
fn contact_book_add_list_show_and_trust_work_through_public_cli() {
    let fixture = TestFixture::new("contact-book");
    let storage_path = fixture.path("state/contacts.sqlite3");
    let config_path = fixture.write_config("contacts.toml", 45102, &storage_path);
    let fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    let add = fixture.cli(
        [
            "--config",
            path_arg(&config_path),
            "contact",
            "add",
            "--alias",
            "alice",
            "--fingerprint",
            fingerprint,
        ],
        "contact add alice",
    );
    assert_success(&add, "contact add alice");
    let add_stdout = stdout(&add);
    assert!(add_stdout.contains("contact: stored alias=alice"), "{add_stdout}");
    assert!(
        add_stdout.contains(&format!("alice\t{fingerprint}\tfalse\tuntrusted")),
        "{add_stdout}"
    );

    let trust = fixture.cli(
        [
            "--config",
            path_arg(&config_path),
            "contact",
            "trust",
            "alice",
        ],
        "contact trust alice",
    );
    assert_success(&trust, "contact trust alice");
    let trust_stdout = stdout(&trust);
    assert!(trust_stdout.contains("contact: trusted alias=alice"), "{trust_stdout}");
    assert!(
        trust_stdout.contains(&format!("alice\t{fingerprint}\tfalse\ttrusted")),
        "{trust_stdout}"
    );

    let list = fixture.cli(
        ["--config", path_arg(&config_path), "contact", "list"],
        "contact list",
    );
    assert_success(&list, "contact list");
    let list_stdout = stdout(&list);
    assert!(list_stdout.contains("contacts: 1"), "{list_stdout}");
    assert!(
        list_stdout.contains("alias\tfingerprint\tpublic_key_present\ttrust_state"),
        "{list_stdout}"
    );
    assert!(
        list_stdout.contains(&format!("alice\t{fingerprint}\tfalse\ttrusted")),
        "{list_stdout}"
    );

    let show = fixture.cli(
        [
            "--config",
            path_arg(&config_path),
            "contact",
            "show",
            fingerprint,
        ],
        "contact show alice by fingerprint",
    );
    assert_success(&show, "contact show alice by fingerprint");
    let show_stdout = stdout(&show);
    assert!(show_stdout.contains("contact: alias=alice"), "{show_stdout}");
    assert!(
        show_stdout.contains(&format!("alice\t{fingerprint}\tfalse\ttrusted")),
        "{show_stdout}"
    );
}

#[test]
fn key_exchange_send_ack_and_history_work_through_public_cli() {
    let fixture = TestFixture::new("chat-roundtrip");
    let alice_storage = fixture.path("alice.sqlite3");
    let bob_storage = fixture.path("bob.sqlite3");
    let alice_config =
        fixture.write_config("alice.toml", fixture.unique_udp_port(), &alice_storage);
    let bob_config = fixture.write_config("bob.toml", fixture.unique_udp_port(), &bob_storage);
    let alice_secret = fixture.path("alice.secret");
    let alice_public = fixture.path("alice.public");
    let bob_secret = fixture.path("bob.secret");
    let bob_public = fixture.path("bob.public");

    let alice_keygen = fixture.cli(
        [
            "keygen",
            "--secret-key",
            path_arg(&alice_secret),
            "--public-key",
            path_arg(&alice_public),
        ],
        "alice keygen",
    );
    assert_success(&alice_keygen, "alice keygen");
    let bob_keygen = fixture.cli(
        [
            "keygen",
            "--secret-key",
            path_arg(&bob_secret),
            "--public-key",
            path_arg(&bob_public),
        ],
        "bob keygen",
    );
    assert_success(&bob_keygen, "bob keygen");
    let alice_fingerprint = fingerprint_from_keygen(&stdout(&alice_keygen));
    let bob_fingerprint = fingerprint_from_keygen(&stdout(&bob_keygen));

    let key_port = free_tcp_port();
    let bob_key_addr = format!("127.0.0.1:{key_port}");
    let mut bob_key_server = fixture.spawn_cli(
        [
            "key-serve",
            "--public-key",
            path_arg(&bob_public),
            "--listen",
            bob_key_addr.as_str(),
            "--duration-ms",
            "10000",
        ],
        "bob key-serve",
    );
    let alice_request = fixture.eventually_cli(
        [
            "--config",
            path_arg(&alice_config),
            "key-request",
            "--peer",
            bob_key_addr.as_str(),
        ],
        "alice key-request bob",
    );
    assert_success(&alice_request, "alice key-request bob");
    bob_key_server.kill_and_wait();

    let alice_key_addr = format!("127.0.0.1:{key_port}");
    let mut alice_key_server = fixture.spawn_cli(
        [
            "key-serve",
            "--public-key",
            path_arg(&alice_public),
            "--listen",
            alice_key_addr.as_str(),
            "--duration-ms",
            "10000",
        ],
        "alice key-serve",
    );
    let bob_request = fixture.eventually_cli(
        [
            "--config",
            path_arg(&bob_config),
            "key-request",
            "--peer",
            alice_key_addr.as_str(),
        ],
        "bob key-request alice",
    );
    assert_success(&bob_request, "bob key-request alice");
    alice_key_server.kill_and_wait();

    let chat_addr = format!("127.0.0.1:{}", free_tcp_port());
    let conversation = "11111111-1111-4111-8111-111111111111";
    let mut bob_receiver = fixture.spawn_cli(
        [
            "--config",
            path_arg(&bob_config),
            "receive",
            "--secret-key",
            path_arg(&bob_secret),
            "--peer-fingerprint",
            alice_fingerprint.as_str(),
            "--listen",
            chat_addr.as_str(),
            "--duration-ms",
            "10000",
        ],
        "bob receive",
    );
    let send_output = fixture.eventually_cli(
        [
            "--config",
            path_arg(&alice_config),
            "send",
            "--secret-key",
            path_arg(&alice_secret),
            "--peer-fingerprint",
            bob_fingerprint.as_str(),
            "--peer",
            chat_addr.as_str(),
            "--conversation",
            conversation,
            "hello bob from the cli",
        ],
        "alice send bob",
    );
    assert_success(&send_output, "alice send bob");
    let receive_output = bob_receiver.wait_with_timeout(CLI_TIMEOUT);
    assert_success(&receive_output, "bob receive");

    let conversations = fixture.cli(
        ["--config", path_arg(&alice_config), "conversations"],
        "alice conversations",
    );
    assert_success(&conversations, "alice conversations");
    let conversations_stdout = stdout(&conversations);
    assert!(
        conversations_stdout.contains("conversations: 1"),
        "{conversations_stdout}"
    );
    assert!(
        conversations_stdout.contains("11111111111141118111111111111111"),
        "{conversations_stdout}"
    );

    let history = fixture.cli(
        [
            "--config",
            path_arg(&alice_config),
            "history",
            "--conversation",
            conversation,
        ],
        "alice history",
    );
    assert_success(&history, "alice history");
    let send_stdout = stdout(&send_output);
    let receive_stdout = stdout(&receive_output);
    let history_stdout = stdout(&history);
    assert!(send_stdout.contains("send: delivered"), "{send_stdout}");
    assert!(
        receive_stdout.contains("receive: accepted"),
        "{receive_stdout}"
    );
    assert!(history_stdout.contains("messages=1"), "{history_stdout}");
    assert!(history_stdout.contains("acknowledged:"), "{history_stdout}");
    assert!(history_stdout.contains("\tnone\thello bob from the cli"), "{history_stdout}");
}

struct TestFixture {
    root: tempfile::TempDir,
}

impl TestFixture {
    fn new(name: &str) -> Self {
        let root = tempfile::Builder::new()
            .prefix(name)
            .tempdir()
            .expect("create tempdir");
        Self { root }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.path().join(relative)
    }

    fn write_config(&self, name: &str, discovery_port: u16, storage_path: &Path) -> PathBuf {
        let config_path = self.path(name);
        fs::write(
            &config_path,
            format!(
                r#"
multicast_group = "239.255.40.91"
discovery_port = {discovery_port}
listen_addr = "127.0.0.1"
storage_path = "{}"
"#,
                storage_path.display()
            ),
        )
        .expect("write config");
        config_path
    }

    fn unique_udp_port(&self) -> u16 {
        free_tcp_port()
    }

    fn cli<const N: usize>(&self, args: [&str; N], description: &str) -> Output {
        run_cli(args, CLI_TIMEOUT, description)
    }

    fn eventually_cli<const N: usize>(&self, args: [&str; N], description: &str) -> Output {
        let deadline = Instant::now() + BACKGROUND_READY_TIMEOUT;
        let mut last_output = None;
        while Instant::now() < deadline {
            let output = run_cli(args, CLI_TIMEOUT, description);
            if output.status.success() {
                return output;
            }
            last_output = Some(output);
            thread::sleep(Duration::from_millis(100));
        }

        let output = last_output.expect("command was attempted at least once");
        panic!(
            "{description} did not succeed before timeout\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            stdout(&output),
            stderr(&output)
        );
    }

    fn spawn_cli<const N: usize>(
        &self,
        args: [&str; N],
        description: &'static str,
    ) -> ChildGuard {
        let child = Command::new(cli_bin())
            .args(args)
            .current_dir(self.root.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn CLI process");
        ChildGuard {
            child: Some(child),
            description,
            args: args.map(str::to_owned).to_vec(),
        }
    }
}

struct ChildGuard {
    child: Option<Child>,
    description: &'static str,
    args: Vec<String>,
}

impl ChildGuard {
    fn wait_with_timeout(&mut self, timeout: Duration) -> Output {
        let mut child = self.child.take().expect("child is still running");
        let deadline = Instant::now() + timeout;
        loop {
            if child.try_wait().expect("poll child").is_some() {
                return child.wait_with_output().expect("collect child output");
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let output = child.wait_with_output().expect("collect timed-out child output");
                panic!(
                    "{} timed out after {timeout:?}\ncommand: {}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
                    self.description,
                    format_cli_command(&self.args),
                    output.status,
                    stdout(&output),
                    stderr(&output)
                );
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn kill_and_wait(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if child.try_wait().expect("poll child").is_none() {
            let _ = child.kill();
        }
        let _ = child.wait_with_output();
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            if child.try_wait().expect("poll child").is_none() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

fn run_cli<const N: usize>(args: [&str; N], timeout: Duration, description: &str) -> Output {
    let mut child = Command::new(cli_bin())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn CLI command");
    let deadline = Instant::now() + timeout;

    loop {
        if child.try_wait().expect("poll CLI command").is_some() {
            return child.wait_with_output().expect("collect CLI output");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child
                .wait_with_output()
                .expect("collect timed-out CLI output");
            panic!(
                "{description} timed out after {timeout:?}\ncommand: {}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
                format_cli_command(&args),
                output.status,
                stdout(&output),
                stderr(&output)
            );
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn assert_success(output: &Output, description: &str) {
    assert!(
        output.status.success(),
        "{description} failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout(output),
        stderr(output)
    );
}

fn fingerprint_from_keygen(output: &str) -> String {
    output
        .lines()
        .find_map(|line| line.strip_prefix("keygen: fingerprint="))
        .expect("keygen output includes fingerprint")
        .to_owned()
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("read local addr")
        .port()
}

fn cli_bin() -> &'static str {
    env!("CARGO_BIN_EXE_decentra-chat")
}

fn format_cli_command(args: &[impl AsRef<str>]) -> String {
    std::iter::once(cli_bin().to_owned())
        .chain(args.iter().map(|arg| arg.as_ref().to_owned()))
        .collect::<Vec<_>>()
        .join(" ")
}

fn path_arg(path: &Path) -> &str {
    path.to_str().expect("test paths are valid UTF-8")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
