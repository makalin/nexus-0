//! Library-only demo: no socket, no server. Runs the reflex engine in-process.

use nexus0::engine::{evaluate, evaluate_in_place, ReflexEngine};
use nexus0::schema::Opcode;

fn main() {
    let engine = ReflexEngine::default();
    let payload = b"notify ada@nexus.dev cc=4111111111111111";
    let decision = evaluate(&engine, payload);

    println!("NEXUS-0 offline reflex");
    println!(
        "  latency     {} ns ({} us)",
        decision.latency_ns,
        decision.latency_ns / 1000
    );
    println!("  malicious   {:.4}", decision.malicious);
    println!("  pii         {:.4}", decision.pii);
    println!("  entropy     {:.4} bits", decision.entropy);
    println!("  ai_marker   {:.4}", decision.ai_marker);
    println!("  route       {}", decision.route.as_str());
    println!("  spans       {}", decision.spans.len());
    for span in &decision.spans {
        let slice = &payload[span.start as usize..span.end as usize];
        println!(
            "    [{:>3}..{:>3}] {:<12} {}",
            span.start,
            span.end,
            span.kind.as_str(),
            String::from_utf8_lossy(slice)
        );
    }
    if let Some(t) = decision.tools {
        println!(
            "  tools       {} fp={:016x} replay={}",
            t.format.as_str(),
            t.fingerprint,
            t.replay
        );
    }
    if let Some(redacted) = &decision.redacted {
        println!("  redacted    {}", String::from_utf8_lossy(redacted));
    }

    let mut owned = payload.to_vec();
    let (_d, spans) = evaluate_in_place(&engine, &mut owned);
    println!(
        "  in-place    {} ({} spans masked)",
        String::from_utf8_lossy(&owned),
        spans.len()
    );

    let routed = engine.evaluate(Opcode::Route, 0, b"hello from the reflex layer");
    println!("  benign route {}", routed.route.as_str());
}
