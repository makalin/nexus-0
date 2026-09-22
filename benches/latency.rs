//! Sample reflex latency. Run with `cargo bench`.
//!
//! Prints the median of five warmed calls at 64 B, 4 KiB, and 1 MiB.
//! `cargo test` asserts looser bounds on the same sizes.

use std::time::Instant;

use nexus0::engine::ReflexEngine;
use nexus0::schema::{Opcode, FLAG_TOOLS};

fn median_ns(buf: &[u8]) -> u64 {
    let engine = ReflexEngine::default();
    let _ = engine.evaluate(Opcode::Kit, FLAG_TOOLS, buf);
    let mut samples = [0u64; 5];
    for sample in &mut samples {
        let started = Instant::now();
        let _ = engine.evaluate(Opcode::Kit, FLAG_TOOLS, buf);
        *sample = started.elapsed().as_nanos() as u64;
    }
    samples.sort_unstable();
    samples[2]
}

fn main() {
    let small = [b'a'; 64];
    let mid = vec![b'b'; 4096];
    let big = vec![b'c'; 1_048_576];
    for (label, buf) in [
        ("64B", small.as_slice()),
        ("4KiB", mid.as_slice()),
        ("1MiB", big.as_slice()),
    ] {
        let ns = median_ns(buf);
        println!(
            "{label:>5}  median {ns:>10} ns  ({:.1} us)",
            ns as f64 / 1000.0
        );
    }
}
