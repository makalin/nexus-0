//! Zero-copy extract: print start/end pointers, never clone the entity text
//! except for display.

use nexus0::engine::ReflexEngine;
use nexus0::schema::{Opcode, FLAG_RETURN_SPANS};

fn main() {
    let payloads: [&[u8]; 4] = [
        b"From: Ada Lovelace <ada@analytical.engine>",
        b"peer 192.168.10.42 session",
        b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc",
        b"ssn 078-05-1120 phone +1 415-555-0100",
    ];

    let engine = ReflexEngine::default();
    for payload in payloads {
        let d = engine.evaluate(Opcode::Extract, FLAG_RETURN_SPANS, payload);
        println!("{}", String::from_utf8_lossy(payload));
        if d.spans.is_empty() {
            println!("  (no entities)");
        }
        for span in d.spans {
            println!(
                "  ptr {:>3}..{:>3}  kind={:<12} bytes={}",
                span.start,
                span.end,
                span.kind.as_str(),
                span.len()
            );
        }
        println!();
    }
}
