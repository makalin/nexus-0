//! Cross-check the Rust frame encoder against ui/protocol.py.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use nexus0::schema::{
    encode_request, encode_response, EntityKind, Opcode, Request, Response, RouteAction, Span,
    FLAG_APPLY_REDACT, FLAG_RETURN_SPANS, STATUS_OK,
};

#[test]
fn python_encoder_matches_rust() {
    let req = Request {
        opcode: Opcode::Reflex,
        flags: FLAG_RETURN_SPANS | FLAG_APPLY_REDACT,
        seq: 42,
        payload: b"hello".to_vec(),
    };
    let mut request = Vec::new();
    encode_request(&req, &mut request);

    let resp = Response {
        status: STATUS_OK,
        opcode: Opcode::Extract,
        seq: 7,
        latency_ns: 1234,
        malicious: 0.5,
        pii: 0.25,
        entropy: 4.0,
        ai_marker: 0.5,
        route: RouteAction::Accept,
        spans: vec![Span {
            start: 2,
            end: 10,
            kind: EntityKind::Email,
        }],
        payload: Some(b"abc".to_vec()),
        tools: None,
    };
    let mut response = Vec::new();
    encode_response(&resp, &mut response);

    let dir = std::env::temp_dir().join(format!("nexus0-golden-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let request_path = dir.join("request.bin");
    let response_path = dir.join("response.bin");
    fs::write(&request_path, &request).unwrap();
    fs::write(&response_path, &response).unwrap();

    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ui/test_protocol.py");
    let status = python()
        .arg(&script)
        .arg(&request_path)
        .arg(&response_path)
        .status()
        .expect("python is required to cross-check ui/protocol.py");
    assert!(status.success(), "python golden check failed");
    let _ = fs::remove_dir_all(&dir);
}

fn python() -> Command {
    if Command::new("python")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
    {
        return Command::new("python");
    }
    let mut cmd = Command::new("py");
    cmd.arg("-3");
    cmd
}
