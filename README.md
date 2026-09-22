<p align="center">
  <img src="nexus_logo.png" alt="NEXUS-0" width="280">
</p>

# NEXUS-0

NEXUS-0 is a zero-dependency Rust reflex router. One pass over a raw byte payload returns entity spans, an optional in-place mask, a route, and entropy. It does not generate tokens.

The decision head is a fixed 8-wide byte embedding and a 12-unit ReLU layer blended with pattern hits. Scores are a heuristic, not a trained transformer and not a security boundary. There is no candle, ONNX, or rkyv dependency. The wire format is a packed little-endian frame in `src/schema.rs`.

## What a request does

| Opcode | Result |
| --- | --- |
| `extract` | Byte offsets of emails, cards, tokens, and similar spans |
| `redact` | Those spans overwritten with `*` |
| `route` | Accept, quarantine, or drop from the malicious score |
| `entropy` | Sketch entropy and head scores, without entity or threat scans |
| `kit` | Route plus fingerprint, format, HTTP split, and replay |

Default thresholds are **0.80 quarantine** and **0.95 drop**. Drop at 0.95 happens only when the request sets `FLAG_DROP_IF_MALICIOUS` (`0x0004`). Otherwise that score is quarantined. `FLAG_DROP_REPLAY` (`0x0020`) drops a payload whose fingerprint is already in the engine's seen cache.

Quarantine writes a masked copy under the quarantine directory (mode `0600` on Unix). The original bytes are not stored. Replay state lives on the `ReflexEngine` you keep. `kit` and `evaluate` take that engine so repeated calls share it.

The seen cache is 8192 buckets of four fingerprints. A second distinct key in the same bucket does not evict the first.

## Layout

```
src/            Reflex core (engine, schema, IPC, telemetry)
examples/       Offline library, extract, redact, kit, framed IPC client
ui/             PyGame monitor and the shared Python wire helpers
benches/        Latency samples for 64 B, 4 KiB, and 1 MiB
tests/          Framed IPC integration test
```

## Build

```bash
cargo build --release
cargo test
cargo run --release
```

On Unix the core listens on `{temp}/nexus0-{uid}/nexus0.sock` (directory `0700`, socket `0600`). On Windows it listens on `127.0.0.1:9800`. Override with `--bind` or `NEXUS0_BIND`. A TCP address that is not loopback is refused unless you pass `--allow-remote`. Command-line flags win over environment variables.

```bash
cargo run --example offline
cargo run --example extract
cargo run --example redact
cargo run --example kit
cargo run --example client
```

`examples/client.rs` speaks the framed protocol. A raw write of ASCII is not a request. The header is 20 bytes: magic `NX0\0`, version, opcode, flags, sequence, payload length, then the payload bytes.

Library:

```rust
use nexus0::engine::{kit, ReflexEngine};

fn main() {
    let engine = ReflexEngine::default();
    let decision = kit(&engine, b"notify ada@nexus.dev");
    println!("{}  {:.3}", decision.route.as_str(), decision.malicious);
}
```

Telemetry is a 256-byte block written beside the socket (`nexus0.stats`) plus an event ticker (`nexus0.events`). Request threads update memory only. A background task publishes the block by writing a temp file and renaming it. `last_latency_ns` is engine time. `last_publish_ns` at offset 224 is the publish time.

```bash
pip install -r ui/requirements.txt
python ui/monitor.py
```

The monitor polls those files. It is not on the request path.

```bash
python examples/client.py
```

## Limits

Pattern hits for SQL, markup, and paths are easy to bypass. Use the route as a hint. The release profile unwinds panics so one session can return an error frame instead of aborting the process. Sessions are capped (default 64). Ctrl-C stops accept, drains in-flight work, and flushes telemetry.

Latency checks in `cargo test` cover 64-byte, 4 KiB, and 1 MiB payloads. `cargo bench` prints the same sizes.

## Author and license

Developed by **Mehmet T. AKALIN**

[Digital Vision](https://dv.com.tr)

MIT. See `LICENSE`.
