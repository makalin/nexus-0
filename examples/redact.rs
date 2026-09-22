//! Hardware-style in-place mask: overwrite PII bytes, keep length and offsets.

use nexus0::engine::redact_in_place;
use nexus0::patterns::scan_entities;

fn main() {
    let original = b"invoice 4111111111111111 for jane.doe@example.com from 10.1.2.3";
    let mut buf = original.to_vec();
    let spans = scan_entities(&buf);
    println!("before  {}", String::from_utf8_lossy(original));
    redact_in_place(&mut buf, &spans, b'*');
    println!("after   {}", String::from_utf8_lossy(&buf));
    println!("spans   {}", spans.len());
    for span in spans {
        println!(
            "  {} bytes {}..{} masked",
            span.kind.as_str(),
            span.start,
            span.end
        );
    }
}
