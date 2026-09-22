//! IPC client example. Talks the framed NX0 protocol to a running core.
//!
//! Start the engine first:
//!   cargo run --release
//!
//! Then:
//!   cargo run --example client
//!
//! On Windows the default bind is `127.0.0.1:9800`. On Unix it is
//! `{temp}/nexus0-{uid}/nexus0.sock`. Override with NEXUS0_BIND.

use nexus0::client::call;
use nexus0::config::client_bind;
use nexus0::schema::{
    Opcode, Request, FLAG_APPLY_REDACT, FLAG_DROP_IF_MALICIOUS, FLAG_RETURN_SPANS, FLAG_TOOLS,
};

fn main() {
    let bind = client_bind();
    println!("connecting to {bind}");

    let samples: &[(&str, Opcode, &[u8])] = &[
        (
            "benign routing request",
            Opcode::Reflex,
            b"ROUTING_REQ: User access token validation needed.",
        ),
        (
            "extract PII spans",
            Opcode::Extract,
            b"notify ada@nexus.dev from 10.0.0.8",
        ),
        (
            "redact card + email",
            Opcode::Redact,
            b"charge 4111111111111111 and mail jane.doe@example.com",
        ),
        (
            "route stacked threat markers",
            Opcode::Route,
            b"admin' OR 1=1-- union select ../etc/passwd",
        ),
        (
            "entropy / AI-marker check",
            Opcode::Entropy,
            b"The system will now proceed to evaluate the incoming payload in a consistent manner.",
        ),
    ];

    for (label, opcode, payload) in samples {
        let req = Request {
            opcode: *opcode,
            flags: FLAG_RETURN_SPANS | FLAG_APPLY_REDACT | FLAG_DROP_IF_MALICIOUS | FLAG_TOOLS,
            seq: 0,
            payload: payload.to_vec(),
        };
        match call(&bind, &req) {
            Ok(resp) => {
                println!("--- {label} ---");
                println!(
                    "  status={} route={:?} latency={}us mal={:.3} pii={:.3} H={:.2} ai={:.3}",
                    resp.status,
                    resp.route,
                    resp.latency_ns / 1000,
                    resp.malicious,
                    resp.pii,
                    resp.entropy,
                    resp.ai_marker
                );
                for span in &resp.spans {
                    let text = span
                        .as_bytes(payload)
                        .and_then(|b| std::str::from_utf8(b).ok())
                        .unwrap_or("");
                    println!(
                        "  span {}..{} {} {:?}",
                        span.start,
                        span.end,
                        span.kind.as_str(),
                        text
                    );
                }
                if let Some(t) = resp.tools {
                    println!(
                        "  tools fp={:016x} fmt={} replay={} pri={}",
                        t.fingerprint,
                        t.format.as_str(),
                        t.replay,
                        t.priority
                    );
                }
                if let Some(p) = &resp.payload {
                    if let Ok(s) = std::str::from_utf8(p) {
                        println!("  payload: {s}");
                    }
                }
            }
            Err(e) => {
                eprintln!("failed ({label}): {e}");
                eprintln!("is the core running?  cargo run --release");
                std::process::exit(1);
            }
        }
    }
}
