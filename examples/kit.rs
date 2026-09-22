//! Unique OS tool plane: one fused pass → fingerprint, format, HTTP split, replay.

use nexus0::const_eq;
use nexus0::engine::{kit, ReflexEngine};
use nexus0::schema::{Opcode, FLAG_DROP_REPLAY, FLAG_TOOLS};
use nexus0::tools::{http_body, near_dup, utf8_prefix};

fn main() {
    let engine = ReflexEngine::default();
    let json = br#"{"dept":"billing","n":2}"#;
    let d = kit(&engine, json);
    let t = d.tools.expect("kit always returns tools");
    println!("NEXUS-0 tool kit  ({} us)", d.latency_ns / 1000);
    println!("  format       {}", t.format.as_str());
    println!("  fingerprint  {:016x}", t.fingerprint);
    println!("  simhash      {:016x}", t.simhash);
    println!("  content_id   {:016x}", t.content_id);
    println!("  utf8_ok      {}  errors={}", t.utf8_ok, t.utf8_errors);
    println!("  json keys    {}  depth={}", t.json_keys, t.json_depth);
    println!("  token budget {}", t.token_budget);
    println!("  priority     {}", t.priority);
    println!("  replay       {}", t.replay);

    let http = b"POST /ingest HTTP/1.1\r\nHost: core\r\n\r\n{\"ok\":true}";
    let h = engine.evaluate(Opcode::Format, FLAG_TOOLS, http);
    let ht = h.tools.unwrap();
    println!(
        "\nHTTP split  format={} body={:?}",
        ht.format.as_str(),
        String::from_utf8_lossy(http_body(http, ht.http_body_off))
    );

    let a = engine.evaluate(Opcode::Fingerprint, FLAG_TOOLS, b"dup");
    let b = engine.evaluate(Opcode::Seen, FLAG_TOOLS | FLAG_DROP_REPLAY, b"dup");
    println!(
        "replay gate  first={} second={} route={}",
        a.tools.unwrap().replay,
        b.tools.unwrap().replay,
        b.route.as_str()
    );

    let near = near_dup(
        a.tools.unwrap().simhash,
        engine
            .evaluate(Opcode::Fingerprint, FLAG_TOOLS, b"dup!")
            .tools
            .unwrap()
            .simhash,
        16,
    );
    println!("near-dup(dup, dup!) within hamming 16: {near}");

    let cut = utf8_prefix("néxus-0".as_bytes(), 4);
    println!("utf8_prefix(4) = {cut} bytes");
    println!("const_eq secret compare: {}", const_eq(b"nx0", b"nx0"));

    let batch = engine.evaluate_batch(&[
        (b"alpha", Opcode::Kit, FLAG_TOOLS),
        (b"beta", Opcode::Kit, FLAG_TOOLS),
        (b"alpha", Opcode::Kit, FLAG_TOOLS),
    ]);
    println!(
        "batch 3  replay flags {:?}/{:?}/{:?}",
        batch[0].tools.unwrap().replay,
        batch[1].tools.unwrap().replay,
        batch[2].tools.unwrap().replay
    );
}
