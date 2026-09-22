//! IPC integration: spin a TCP reflex core on an ephemeral port and round-trip.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

use nexus0::client::call;
use nexus0::config::Config;
use nexus0::schema::{
    Opcode, Request, RouteAction, FLAG_APPLY_REDACT, FLAG_RETURN_SPANS, RESPONSE_HEADER_LEN,
    STATUS_ERROR,
};

fn start_core() -> (String, std::path::PathBuf) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let bind = addr.to_string();
    let port = addr.port();
    let quarantine = std::env::temp_dir().join(format!("nexus0-test-q-{port}"));
    let quarantine_thread = quarantine.clone();
    let bind_thread = bind.clone();
    thread::spawn(move || {
        let cfg = Config {
            bind: bind_thread,
            stats_path: std::env::temp_dir().join(format!("nexus0-test-{port}.stats")),
            events_path: std::env::temp_dir().join(format!("nexus0-test-{port}.events")),
            quarantine_dir: quarantine_thread,
            ..Config::default()
        };
        let _ = nexus0::ipc::run(cfg);
    });
    (bind, quarantine)
}

fn wait_connect(bind: &str) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match TcpStream::connect(bind) {
            Ok(s) => return s,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("core did not accept connections: {e}"),
        }
    }
}

#[test]
fn framed_reflex_roundtrip() {
    let (bind, _) = start_core();
    let payload = b"ping ada@nexus.dev";
    let req = Request {
        opcode: Opcode::Reflex,
        flags: FLAG_RETURN_SPANS | FLAG_APPLY_REDACT,
        seq: 9,
        payload: payload.to_vec(),
    };

    let deadline = Instant::now() + Duration::from_secs(3);
    let resp = loop {
        match call(&bind, &req) {
            Ok(r) => break r,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("core did not accept connections: {e}"),
        }
    };

    assert_eq!(resp.seq, 9);
    assert_eq!(resp.route, RouteAction::Accept);
    assert!(resp
        .spans
        .iter()
        .any(|s| s.kind == nexus0::schema::EntityKind::Email));
    let redacted = resp.payload.expect("redacted echo");
    assert!(redacted.contains(&b'*'));
}

#[test]
fn oversized_declared_length_is_rejected() {
    let (bind, _) = start_core();
    let mut stream = wait_connect(&bind);
    let mut header = [0u8; 20];
    header[0..4].copy_from_slice(&nexus0::MAGIC);
    header[4] = nexus0::PROTOCOL_VERSION;
    header[5] = Opcode::Reflex as u8;
    header[16..20].copy_from_slice(&2_000_000u32.to_le_bytes());
    stream.write_all(&header).unwrap();
    let mut resp = [0u8; RESPONSE_HEADER_LEN];
    stream.read_exact(&mut resp).expect("error frame");
    assert_eq!(&resp[0..4], b"NX0R");
    assert_eq!(resp[4], STATUS_ERROR);
}

#[test]
fn bad_magic_closes_without_nx0r_frame() {
    let (bind, _) = start_core();
    let mut stream = wait_connect(&bind);
    stream.write_all(&[0u8; 20]).unwrap();
    let mut buf = [0u8; 4];
    match stream.read_exact(&mut buf) {
        Err(_) => {}
        Ok(()) => assert_ne!(
            &buf, b"NX0R",
            "garbage header must not parse as a reflex response"
        ),
    }
}

#[test]
fn quarantine_file_masks_email() {
    let (bind, dir) = start_core();
    let payload = b"mail ada@nexus.dev <script src=x>";
    let req = Request {
        opcode: Opcode::Route,
        flags: 0,
        seq: 3,
        payload: payload.to_vec(),
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    let resp = loop {
        match call(&bind, &req) {
            Ok(r) => break r,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("core did not accept connections: {e}"),
        }
    };
    assert_eq!(resp.route, RouteAction::Quarantine);
    let stored = std::fs::read_dir(&dir)
        .expect("quarantine dir")
        .next()
        .expect("quarantine file")
        .expect("dir entry")
        .path();
    let bytes = std::fs::read(&stored).expect("quarantine bytes");
    assert!(
        !bytes
            .windows(b"ada@nexus.dev".len())
            .any(|w| w == b"ada@nexus.dev"),
        "quarantine file kept the email"
    );
    assert!(bytes.contains(&b'*'));
}
