//! Process-level tests for the daemon behaviours mobile launchers depend on:
//! exit codes, readiness file, single-instance lock, parent-death handling, and
//! never stalling when stdout is not drained.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_synapse-core");

static NEXT_PORT: AtomicU16 = AtomicU16::new(0);

fn free_port_pair() -> (u16, u16) {
    let base = 30000 + (std::process::id() % 10000) as u16;
    let n = NEXT_PORT.fetch_add(2, Ordering::SeqCst);
    (base + n, base + n + 1)
}

fn temp_home(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("synapse_daemon_{tag}_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn daemon(home: &Path) -> Command {
    daemon_on(home, 0)
}

fn daemon_on(home: &Path, api_port: u16) -> Command {
    let (p2p, disc) = free_port_pair();
    let mut cmd = Command::new(BIN);
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg("--home")
        .arg(home)
        .args(["--port", &api_port.to_string()])
        .args(["--p2p-port", &p2p.to_string()])
        .args(["--discovery-port", &disc.to_string()]);
    cmd
}

fn wait_for<T>(timeout: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(v) = f() {
            return Some(v);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn read_runtime(home: &Path) -> Option<serde_json::Value> {
    let bytes = std::fs::read(home.join("runtime.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn wait_ready(home: &Path) -> serde_json::Value {
    wait_for(Duration::from_secs(15), || read_runtime(home)).expect("daemon never became ready")
}

fn http_get(addr: &str, path: &str) -> Option<String> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    Some(out)
}

fn wait_exit(child: &mut Child, timeout: Duration) -> Option<i32> {
    wait_for(timeout, || child.try_wait().ok().flatten()).map(|s| s.code().unwrap_or(-1))
}

fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn missing_home_exits_with_config_error() {
    // Mirrors Android: no HOME, no SYNAPSE_HOME, cwd may be read-only.
    let out = Command::new(BIN)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir("/")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--home"), "{stderr}");
}

#[test]
fn ready_file_reports_ephemeral_port_and_sigterm_cleans_up() {
    let home = temp_home("ready");
    let mut child = daemon(&home).stdout(Stdio::null()).spawn().unwrap();
    let rt = wait_ready(&home);

    assert_eq!(rt["pid"].as_u64(), Some(child.id() as u64));
    let addr = rt["api_addr"].as_str().unwrap().to_string();
    assert!(
        !addr.ends_with(":0"),
        "ephemeral port must be resolved: {addr}"
    );
    let resp = http_get(&addr, "/api/v1/system/ping").expect("API unreachable");
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");

    unsafe { libc_kill(child.id() as i32, 15) };
    assert_eq!(wait_exit(&mut child, Duration::from_secs(10)), Some(0));
    assert!(
        !home.join("runtime.json").exists(),
        "runtime.json must be removed on exit"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn second_instance_on_same_home_is_refused() {
    let home = temp_home("lock");
    let mut first = daemon(&home).stdout(Stdio::null()).spawn().unwrap();
    wait_ready(&home);

    let out = daemon(&home).output().unwrap();
    assert_eq!(out.status.code(), Some(4), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("already"));

    kill(&mut first);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn busy_api_port_exits_with_bind_error() {
    let home = temp_home("bind");
    let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = blocker.local_addr().unwrap().port();
    let out = daemon_on(&home, port).output().unwrap();
    assert_eq!(out.status.code(), Some(5), "{out:?}");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn exits_when_stdin_closes() {
    let home = temp_home("stdin");
    let mut child = daemon(&home)
        .arg("--exit-on-stdin-close")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    wait_ready(&home);
    drop(child.stdin.take());
    assert_eq!(wait_exit(&mut child, Duration::from_secs(10)), Some(0));
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn exits_when_parent_dies() {
    let home = temp_home("parent");
    let (p2p, disc) = free_port_pair();
    // `sh` is the parent; it backgrounds the daemon, prints its PID, then exits.
    let script = format!(
        "'{BIN}' --home '{}' --port 0 --p2p-port {p2p} --discovery-port {disc} \
         --exit-with-parent --quiet </dev/null >/dev/null 2>&1 & echo $!; sleep 3",
        home.display()
    );
    let mut sh = Command::new("sh")
        .args(["-c", &script])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut pid = String::new();
    {
        let stdout = sh.stdout.as_mut().unwrap();
        let mut byte = [0u8; 1];
        while stdout.read(&mut byte).unwrap_or(0) == 1 && byte[0] != b'\n' {
            pid.push(byte[0] as char);
        }
    }
    let pid: i32 = pid.trim().parse().unwrap();
    wait_ready(&home);
    let _ = sh.wait();

    let gone = wait_for(Duration::from_secs(10), || {
        (unsafe { libc_kill(pid, 0) } != 0).then_some(())
    });
    if gone.is_none() {
        unsafe { libc_kill(pid, 9) };
        panic!("daemon {pid} outlived its parent");
    }
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn undrained_stdout_never_stalls_the_engine() {
    // Android apps commonly spawn the daemon and never read its output. Once the pipe
    // buffer fills, a synchronous logger would block worker threads and freeze the API.
    let home = temp_home("pipe");
    let mut child = daemon(&home)
        .env("RUST_LOG", "trace")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let rt = wait_ready(&home);
    let addr = rt["api_addr"].as_str().unwrap().to_string();

    // Generate far more than 64 KiB of trace output without ever reading the pipe.
    let start = Instant::now();
    for _ in 0..1000 {
        let resp = http_get(&addr, "/api/v1/system/ping").expect("API stalled");
        assert!(resp.starts_with("HTTP/1.1 200"));
    }
    assert!(start.elapsed() < Duration::from_secs(60));

    kill(&mut child);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn log_dir_receives_rotated_logs() {
    let home = temp_home("logs");
    let logs = home.join("logs");
    let mut child = daemon(&home)
        .arg("--quiet")
        .arg("--log-dir")
        .arg(&logs)
        .spawn()
        .unwrap();
    wait_ready(&home);
    let found = wait_for(Duration::from_secs(5), || {
        std::fs::read_dir(&logs)
            .ok()?
            .filter_map(Result::ok)
            .find(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.starts_with("synapse.") && name.ends_with(".log")
            })
            .and_then(|e| std::fs::read_to_string(e.path()).ok())
            .filter(|s| s.contains("ready at"))
    });
    kill(&mut child);
    assert!(
        found.is_some(),
        "no log file with readiness line in {}",
        logs.display()
    );
    let _ = std::fs::remove_dir_all(&home);
}

fn http_post(addr: &str, path: &str) -> Option<String> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    Some(out)
}

fn json_body(resp: &str) -> serde_json::Value {
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
    serde_json::from_str(body).unwrap_or(serde_json::Value::Null)
}

#[test]
fn restart_starts_a_fresh_generation_on_the_same_address() {
    let home = temp_home("restart");
    let mut child = daemon(&home).stdout(Stdio::null()).spawn().unwrap();
    let rt = wait_ready(&home);
    let addr = rt["api_addr"].as_str().unwrap().to_string();
    let started = rt["started_at"].as_i64().unwrap();

    let status = json_body(&http_get(&addr, "/api/v1/system/status").unwrap());
    assert_eq!(status["lifecycle"], "ready");

    let resp = http_post(&addr, "/api/v1/system/restart").expect("restart call");
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert_eq!(json_body(&resp)["lifecycle"], "restarting");

    // The new generation republishes runtime.json on the same address, same PID.
    let rt2 = wait_for(Duration::from_secs(15), || {
        read_runtime(&home).filter(|r| r["started_at"].as_i64() != Some(started))
    })
    .expect("engine did not come back after restart");
    assert_eq!(rt2["api_addr"].as_str(), Some(addr.as_str()));
    assert_eq!(rt2["pid"].as_u64(), Some(child.id() as u64));
    let status = json_body(&http_get(&addr, "/api/v1/system/status").unwrap());
    assert_eq!(status["lifecycle"], "ready");

    // And it still shuts down cleanly afterwards.
    let resp = http_post(&addr, "/api/v1/system/shutdown").unwrap();
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert_eq!(wait_exit(&mut child, Duration::from_secs(10)), Some(0));
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn version_includes_target() {
    let out = Command::new(BIN).arg("--version").output().unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains(env!("CARGO_PKG_VERSION")), "{s}");
}

unsafe fn libc_kill(pid: i32, sig: i32) -> i32 {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    kill(pid, sig)
}
