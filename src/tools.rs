//! OS-native tool plane: hashes, format, HTTP split, replay, batch.
//!
//! These are the operations Jev/Laya cannot do — they return JSON answers,
//! not memory-level sketches of a raw buffer.

use crate::schema::{RouteAction, ToolReport};
#[cfg(test)]
use crate::sketch::sketch;
use crate::sketch::{redact_fingerprint, Sketch};

pub use crate::sketch::{const_eq, hamming, utf8_prefix};

pub fn token_budget(sk: &Sketch) -> u32 {
    // ~4 bytes per token for ASCII; fall back to token_count.
    let by_bytes = (sk.len as u32 / 4).max(1);
    if sk.token_count == 0 {
        by_bytes
    } else {
        sk.token_count.max(by_bytes / 4)
    }
}

pub fn content_id(sk: &Sketch) -> u64 {
    sk.fingerprint.wrapping_mul(0x9E3779B97F4A7C15)
        ^ sk.simhash.rotate_left(17)
        ^ (sk.len as u64).wrapping_shl(1)
}

pub fn priority(route: RouteAction, pii: f32, replay: bool) -> u8 {
    if route == RouteAction::Drop {
        3
    } else if route == RouteAction::Quarantine || replay {
        2
    } else if pii >= 0.5 {
        1
    } else {
        0
    }
}

#[allow(clippy::too_many_arguments)]
pub fn report_from_sketch(
    sk: &Sketch,
    spans: &[crate::schema::Span],
    payload: &[u8],
    mask: u8,
    route: RouteAction,
    pii: f32,
    replay: bool,
    seen_count: u32,
) -> ToolReport {
    let redact_hash = if spans.is_empty() {
        sk.fingerprint
    } else {
        redact_fingerprint(payload, spans, mask)
    };
    ToolReport {
        format: sk.format,
        utf8_ok: sk.utf8_ok,
        utf8_errors: sk.utf8_errors,
        fingerprint: sk.fingerprint,
        simhash: sk.simhash,
        content_id: content_id(sk),
        redact_hash,
        json_depth: sk.json_depth,
        json_keys: sk.json_keys,
        http_body_off: sk.http_body_off,
        token_budget: token_budget(sk),
        priority: priority(route, pii, replay),
        replay,
        triggers: sk.triggers,
        seen_count,
    }
}

/// Zero-copy HTTP body (or full payload if not HTTP).
pub fn http_body(payload: &[u8], body_off: u32) -> &[u8] {
    let off = body_off as usize;
    if off == 0 || off > payload.len() {
        payload
    } else {
        &payload[off..]
    }
}

/// Zero-copy HTTP header block.
pub fn http_headers(payload: &[u8], body_off: u32) -> &[u8] {
    let off = body_off as usize;
    if off == 0 || off > payload.len() {
        &[]
    } else {
        &payload[..off]
    }
}

pub fn near_dup(a: u64, b: u64, max_distance: u32) -> bool {
    hamming(a, b) <= max_distance
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Span;

    #[test]
    fn kit_json_report() {
        let payload = br#"{"email":"ada@nexus.dev"}"#;
        let sk = sketch(payload);
        let r = report_from_sketch(
            &sk,
            &[] as &[Span],
            payload,
            b'*',
            RouteAction::Accept,
            0.0,
            false,
            1,
        );
        assert_eq!(r.format.as_str(), "json");
        assert!(r.fingerprint != 0);
        assert!(r.token_budget >= 1);
    }

    #[test]
    fn http_split_zero_copy() {
        let p = b"GET / HTTP/1.1\r\n\r\nxyz";
        let sk = sketch(p);
        assert_eq!(http_body(p, sk.http_body_off), b"xyz");
        assert!(http_headers(p, sk.http_body_off)
            .windows(3)
            .any(|w| w == b"GET"));
    }
}
