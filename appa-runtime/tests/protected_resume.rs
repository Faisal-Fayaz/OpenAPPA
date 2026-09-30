#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const FIRST: &str = "11111111-1111-4111-8111-111111111111";
const LAST: &str = "22222222-2222-4222-8222-222222222222";

fn appa() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_appa"))
}

struct Fixture {
    root: tempfile::TempDir,
    bin: PathBuf,
    data: PathBuf,
    ready: PathBuf,
    forwarded: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        let data = root.path().join("data");
        let ready = root.path().join("ready");
        let forwarded = root.path().join("forwarded");
        fs::create_dir(&bin).unwrap();
        let claude = bin.join("claude");
        fs::write(
            &claude,
            format!(
                r#"#!/bin/sh
record() {{
  printf '%s' "$1" | "$APPA_TEST_BINARY" record-launch --data-dir "$APPA_TEST_DATA" "$2"
}}
start='{{"hook_event_name":"SessionStart","session_id":"{FIRST}"}}'
first='{{"hook_event_name":"SessionEnd","session_id":"{FIRST}","transcript_path":"'$APPA_TEST_DATA'/first.jsonl"}}'
last='{{"hook_event_name":"SessionEnd","session_id":"{LAST}","transcript_path":"'$APPA_TEST_DATA'/last.jsonl"}}'
case "$APPA_TEST_MODE" in
  normal)
    : > "$APPA_TEST_DATA/last.jsonl"
    record "$last" end
    printf 'Resume this session with:\nclaude --resume {LAST}\n'
    ;;
  empty)
    rm -f "$APPA_TEST_DATA/last.jsonl"
    record "$last" end
    ;;
  clear)
    : > "$APPA_TEST_DATA/first.jsonl"
    : > "$APPA_TEST_DATA/last.jsonl"
    record "$first" end
    record "$start" start
    record "$last" end
    printf 'Resume this session with:\nclaude --resume {LAST}\n'
    ;;
  crash)
    : > "$APPA_TEST_DATA/first.jsonl"
    record "$first" end
    record "$start" start
    ;;
  argv)
    if [ "$3" = --messaging-socket-path ]; then : > "$4"; fi
    printf '%s\n' "$@" > "$APPA_TEST_DATA/argv"
    printf '%s' "${{APPA_PEER_ADDRESS-unset}}" > "$APPA_TEST_DATA/peer"
    ;;
  signal)
    kill -TERM $$
    ;;
  wait)
    trap 'printf forwarded > "$APPA_TEST_FORWARDED"; exit 42' TERM HUP
    : > "$APPA_TEST_READY"
    while :; do sleep 1; done
    ;;
esac
exit "${{APPA_TEST_EXIT:-0}}"
"#
            ),
        )
        .unwrap();
        fs::set_permissions(&claude, fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            root,
            bin,
            data,
            ready,
            forwarded,
        }
    }

    fn command(&self, mode: &str) -> Command {
        let mut command = Command::new(appa());
        command
            .args(["protected-launch", "--settings"])
            .arg(self.data.join("settings.json"))
            .arg("--data-dir")
            .arg(&self.data)
            .arg("--")
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
            .env("APPA_TEST_BINARY", appa())
            .env("APPA_TEST_DATA", &self.data)
            .env("APPA_TEST_MODE", mode)
            .env("APPA_TEST_READY", &self.ready)
            .env("APPA_TEST_FORWARDED", &self.forwarded);
        command
    }

    fn terminal_output(&self, mode: &str) -> Output {
        let command = format!(
            "{} protected-launch --settings {} --data-dir {} --",
            shell(appa()),
            shell(&self.data.join("settings.json")),
            shell(&self.data),
        );
        Command::new("script")
            .args(["-qefc", &command, "/dev/null"])
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
            .env("APPA_TEST_BINARY", appa())
            .env("APPA_TEST_DATA", &self.data)
            .env("APPA_TEST_MODE", mode)
            .output()
            .unwrap()
    }
}

/// Launch the fake Claude with `XDG_RUNTIME_DIR` inside the fixture, and return
/// the argv it saw and its `APPA_PEER_ADDRESS` ("unset" when absent).
fn launch_recording(fixture: &Fixture, runtime: &Path, arguments: &[&str]) -> (Vec<String>, String) {
    let status = fixture
        .command("argv")
        .args(arguments)
        .env("XDG_RUNTIME_DIR", runtime)
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let argv = fs::read_to_string(fixture.data.join("argv")).unwrap();
    let peer = fs::read_to_string(fixture.data.join("peer")).unwrap();
    (argv.lines().map(str::to_owned).collect(), peer)
}

fn shell(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

#[test]
fn terminal_output_appends_only_the_last_resumable_protected_session() {
    let fixture = Fixture::new();
    for mode in ["normal", "clear"] {
        let output = fixture.terminal_output(mode);
        assert!(output.status.success());
        let text = String::from_utf8_lossy(&output.stdout).replace('\r', "");
        assert_eq!(
            text,
            format!(
                "Resume this session with:\nclaude --resume {LAST}\n\nResume with OpenAPPA protection:\nclappa --resume {LAST}\n"
            ),
            "mode {mode}"
        );
    }

    for mode in ["empty", "crash"] {
        let output = fixture.terminal_output(mode);
        assert!(output.status.success());
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("OpenAPPA protection"),
            "mode {mode}"
        );
    }
}

#[test]
fn child_exit_status_and_signal_death_are_preserved() {
    let fixture = Fixture::new();
    let status = fixture.command("empty").env("APPA_TEST_EXIT", "37").status().unwrap();
    assert_eq!(status.code(), Some(37));

    let status = fixture.command("signal").status().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGTERM));
}

#[test]
fn term_and_hup_are_forwarded_to_the_foreground_claude_process() {
    for signal in [libc::SIGTERM, libc::SIGHUP] {
        let fixture = Fixture::new();
        let mut child = fixture
            .command("wait")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !fixture.ready.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(fixture.ready.exists(), "fake Claude reached its wait loop");
        assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(42));
        assert_eq!(fs::read_to_string(&fixture.forwarded).unwrap(), "forwarded");
    }
}

#[test]
fn each_claude_gets_a_private_messaging_socket_and_its_peer_address() {
    let fixture = Fixture::new();
    let runtime = fixture.root.path().join("runtime");
    fs::create_dir(&runtime).unwrap();
    let (argv, peer) = launch_recording(&fixture, &runtime, &["--resume", "x"]);

    let settings = fixture.data.join("settings.json");
    assert_eq!(argv.len(), 6, "{argv:?}");
    let socket = PathBuf::from(&argv[3]);
    assert_eq!(
        argv[..],
        [
            "--settings",
            settings.to_str().unwrap(),
            "--messaging-socket-path",
            &argv[3],
            "--resume",
            "x"
        ]
    );
    assert_eq!(peer, format!("uds:{}", socket.display()));
    assert!(socket.as_os_str().len() < 104, "{}", socket.display());
    assert_eq!(socket.parent().unwrap(), runtime.join("appa"));
    let name = socket.file_name().unwrap().to_str().unwrap();
    let stem = name.strip_suffix(".sock").expect("the socket is a .sock file");
    assert!(
        stem.len() == 12 && stem.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{name}"
    );
    let mode = fs::metadata(runtime.join("appa")).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    assert!(!socket.exists(), "the socket is removed when Claude exits");
}

#[test]
fn a_user_messaging_socket_suppresses_clappa_s_own() {
    let fixture = Fixture::new();
    let runtime = fixture.root.path().join("runtime");
    fs::create_dir(&runtime).unwrap();
    let own = fixture.root.path().join("own.sock");
    let (argv, peer) = launch_recording(&fixture, &runtime, &["--messaging-socket-path", own.to_str().unwrap()]);

    let settings = fixture.data.join("settings.json");
    assert_eq!(
        argv[..],
        [
            "--settings",
            settings.to_str().unwrap(),
            "--messaging-socket-path",
            own.to_str().unwrap()
        ]
    );
    assert_eq!(peer, "unset");
    assert!(own.exists(), "clappa leaves the user's socket alone");
}

#[test]
fn a_shared_socket_directory_is_refused_and_claude_starts_without_an_address() {
    let fixture = Fixture::new();
    let runtime = fixture.root.path().join("runtime");
    fs::create_dir_all(runtime.join("appa")).unwrap();
    fs::set_permissions(runtime.join("appa"), fs::Permissions::from_mode(0o777)).unwrap();
    let (argv, peer) = launch_recording(&fixture, &runtime, &[]);

    let settings = fixture.data.join("settings.json");
    assert_eq!(argv[..], ["--settings", settings.to_str().unwrap()]);
    assert_eq!(peer, "unset");
}
