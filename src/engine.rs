//! Orchestrates one fused sketch pass, then gated scanners + optional FFN.

use std::sync::Arc;
use std::time::Instant;

use crate::config::Config;
use crate::features::{ai_marker_score, features_from_sketch, sigmoid};
use crate::model::ReflexHead;
use crate::patterns::{scan_entities_gated, scan_threats_gated};
use crate::schema::{
    Opcode, RouteAction, Span, ToolReport, FLAG_APPLY_REDACT, FLAG_DROP_IF_MALICIOUS,
    FLAG_DROP_REPLAY, FLAG_ECHO_PAYLOAD, FLAG_RETURN_SPANS, FLAG_TOOLS,
};
use crate::seen::SeenRing;
use crate::sketch::{sketch, PII_TRIGGERS, THREAT_TRIGGERS};
use crate::tools::report_from_sketch;

#[derive(Clone, Debug)]
pub struct Decision {
    pub opcode: Opcode,
    pub malicious: f32,
    pub pii: f32,
    pub entropy: f32,
    pub ai_marker: f32,
    pub route: RouteAction,
    pub spans: Vec<Span>,
    pub latency_ns: u64,
    pub redacted: Option<Vec<u8>>,
    pub tools: Option<ToolReport>,
}

#[derive(Clone)]
pub struct ReflexEngine {
    head: ReflexHead,
    drop_threshold: f32,
    quarantine_threshold: f32,
    mask: u8,
    seen: Arc<SeenRing>,
}

impl Default for ReflexEngine {
    fn default() -> Self {
        Self::from_config(&Config::default())
    }
}

impl ReflexEngine {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            head: ReflexHead::new(),
            drop_threshold: cfg.drop_threshold,
            quarantine_threshold: cfg.quarantine_threshold,
            mask: b'*',
            seen: Arc::new(SeenRing::new()),
        }
    }

    pub fn mask_byte(&self) -> u8 {
        self.mask
    }

    pub fn seen(&self) -> &SeenRing {
        &self.seen
    }

    pub fn evaluate(&self, opcode: Opcode, flags: u16, payload: &[u8]) -> Decision {
        let t0 = Instant::now();
        let sk = sketch(payload);

        // Fingerprint / format / seen skip the head. Entropy still scores, but
        // it does not run the PII or threat scanners.
        let skip_head = opcode.skip_scanners();
        let skip_scan = skip_head || opcode == Opcode::Entropy;
        let spans = if skip_scan || sk.triggers & PII_TRIGGERS == 0 {
            Vec::new()
        } else {
            scan_entities_gated(payload, sk.triggers)
        };
        let threats = if skip_scan || sk.triggers & THREAT_TRIGGERS == 0 {
            crate::patterns::ThreatHits::default()
        } else {
            scan_threats_gated(payload, sk.triggers)
        };

        let feat = features_from_sketch(&sk, &spans, threats);
        let (malicious, pii, ai_marker, mut route) = if skip_head {
            (0.0, 0.0, 0.0, RouteAction::Accept)
        } else {
            let head = self.head.forward(payload, &feat.values);
            self.classify(&feat, head, flags)
        };

        let replay = self.seen.check_and_insert(sk.fingerprint);
        if flags & FLAG_DROP_REPLAY != 0 && replay {
            route = RouteAction::Drop;
        }

        let return_spans = matches!(
            opcode,
            Opcode::Extract | Opcode::Reflex | Opcode::Redact | Opcode::Kit
        ) || flags & FLAG_RETURN_SPANS != 0;
        let apply_redact = opcode == Opcode::Redact
            || (matches!(opcode, Opcode::Reflex | Opcode::Kit) && flags & FLAG_APPLY_REDACT != 0);

        let echo = flags & FLAG_ECHO_PAYLOAD != 0 || apply_redact;
        let redacted = if echo {
            let mut copy = payload.to_vec();
            if apply_redact {
                redact_in_place(&mut copy, &spans, self.mask);
            }
            Some(copy)
        } else {
            None
        };

        let emit_tools = opcode.wants_tools() || flags & FLAG_TOOLS != 0;
        let tools = if emit_tools {
            Some(report_from_sketch(
                &sk,
                &spans,
                payload,
                self.mask,
                route,
                pii,
                replay,
                self.seen.count(),
            ))
        } else {
            None
        };
        let out_spans = if return_spans { spans } else { Vec::new() };

        let latency_ns = t0.elapsed().as_nanos() as u64;
        Decision {
            opcode,
            malicious,
            pii,
            entropy: feat.entropy,
            ai_marker,
            route,
            spans: out_spans,
            latency_ns,
            redacted,
            tools,
        }
    }

    /// Evaluate many payloads with one engine; fingerprints share the seen ring.
    pub fn evaluate_batch(&self, items: &[(&[u8], Opcode, u16)]) -> Vec<Decision> {
        items
            .iter()
            .map(|(p, op, flags)| self.evaluate(*op, *flags, p))
            .collect()
    }

    pub fn redact_buffer(&self, buf: &mut [u8]) -> Vec<Span> {
        let sk = sketch(buf);
        let spans = scan_entities_gated(buf, sk.triggers);
        redact_in_place(buf, &spans, self.mask);
        spans
    }

    fn classify(
        &self,
        feat: &crate::features::FeatureVec,
        head: crate::model::HeadScores,
        flags: u16,
    ) -> (f32, f32, f32, RouteAction) {
        let threat = feat.threats.sqli + feat.threats.xss + feat.threats.path;
        let heuristic_malicious = sigmoid(2.4 * threat as f32 + 1.8 * feat.values[6] - 0.8);
        let mut malicious = (0.45 * head.malicious + 0.55 * heuristic_malicious).clamp(0.0, 1.0);
        if threat >= 1 {
            malicious = malicious.max(0.82);
        }
        if threat >= 2 {
            malicious = malicious.max(0.96);
        }

        let heuristic_pii =
            sigmoid(3.0 * feat.values[7] + 2.4 * feat.values[8] + 2.6 * feat.values[9] - 0.4);
        let pii = (0.4 * head.pii + 0.6 * heuristic_pii).clamp(0.0, 1.0);
        let ai_marker = (0.5 * head.ai_marker + 0.5 * ai_marker_score(feat)).clamp(0.0, 1.0);

        // Scores are a heuristic. Quarantine starts at quarantine_threshold.
        // Drop at drop_threshold only when the caller set FLAG_DROP_IF_MALICIOUS.
        let route = if malicious >= self.drop_threshold && flags & FLAG_DROP_IF_MALICIOUS != 0 {
            RouteAction::Drop
        } else if malicious >= self.quarantine_threshold {
            RouteAction::Quarantine
        } else {
            RouteAction::Accept
        };
        (malicious, pii, ai_marker, route)
    }
}

/// Kit pass on `engine`. Replay detection uses that engine's seen ring.
pub fn evaluate(engine: &ReflexEngine, payload: &[u8]) -> Decision {
    engine.evaluate(
        Opcode::Kit,
        FLAG_RETURN_SPANS | FLAG_APPLY_REDACT | FLAG_TOOLS,
        payload,
    )
}

/// In-place PII mask. Does not allocate a second redacted copy.
pub fn evaluate_in_place(engine: &ReflexEngine, buf: &mut [u8]) -> (Decision, Vec<Span>) {
    let decision = engine.evaluate(Opcode::Redact, FLAG_RETURN_SPANS, buf);
    let spans = decision.spans.clone();
    redact_in_place(buf, &spans, engine.mask_byte());
    (decision, spans)
}

/// Full tool kit in-process (fingerprint, format, replay, HTTP split, …).
pub fn kit(engine: &ReflexEngine, payload: &[u8]) -> Decision {
    evaluate(engine, payload)
}

pub fn redact_in_place(buf: &mut [u8], spans: &[Span], mask: u8) {
    for span in spans {
        let start = span.start as usize;
        let end = (span.end as usize).min(buf.len());
        if start < end {
            for b in &mut buf[start..end] {
                *b = mask;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{EntityKind, FormatKind};

    #[test]
    fn extract_email_offsets() {
        let payload = b"user=ada@nexus.dev token=none";
        let d = ReflexEngine::default().evaluate(Opcode::Extract, FLAG_RETURN_SPANS, payload);
        let email = d
            .spans
            .iter()
            .find(|s| s.kind == EntityKind::Email)
            .expect("email span");
        assert_eq!(
            &payload[email.start as usize..email.end as usize],
            b"ada@nexus.dev"
        );
        assert!(
            d.latency_ns < 33_000_000,
            "reflex should stay under 33ms, got {}",
            d.latency_ns
        );
    }

    #[test]
    fn redact_masks_pii_in_place() {
        let mut buf = b"cc=4111111111111111".to_vec();
        let (_d, spans) = evaluate_in_place(&ReflexEngine::default(), &mut buf);
        assert!(spans.iter().any(|s| s.kind == EntityKind::CreditCard));
        assert!(buf.windows(4).any(|w| w == b"****") || buf.contains(&b'*'));
        assert!(!buf.windows(4).any(|w| w == b"4111"));
    }

    #[test]
    fn route_drops_stacked_threat_markers() {
        let payload = b"admin' OR 1=1-- union select ../etc/passwd <script";
        let d = ReflexEngine::default().evaluate(Opcode::Route, FLAG_DROP_IF_MALICIOUS, payload);
        assert_eq!(d.route, RouteAction::Drop);
        assert!(d.malicious >= 0.95);
    }

    #[test]
    fn benign_is_accepted() {
        let d = evaluate(
            &ReflexEngine::default(),
            b"ROUTING_REQ: User access token validation needed.",
        );
        assert_eq!(d.route, RouteAction::Accept);
        assert!(d.malicious < 0.5);
    }

    #[test]
    fn drop_requires_flag() {
        let payload = b"admin' OR 1=1-- union select ../etc/passwd <script";
        let engine = ReflexEngine::default();
        let held = engine.evaluate(Opcode::Route, 0, payload);
        assert!(held.malicious >= 0.95, "mal={}", held.malicious);
        assert_eq!(held.route, RouteAction::Quarantine);
        let dropped = engine.evaluate(Opcode::Route, FLAG_DROP_IF_MALICIOUS, payload);
        assert_eq!(dropped.route, RouteAction::Drop);
    }

    #[test]
    fn entropy_skips_entity_scan() {
        let d = ReflexEngine::default().evaluate(
            Opcode::Entropy,
            FLAG_RETURN_SPANS,
            b"user=ada@nexus.dev token=none",
        );
        assert!(d.spans.is_empty());
        assert!(d.entropy > 0.0);
    }

    #[test]
    fn kit_shares_seen_ring() {
        let engine = ReflexEngine::default();
        let a = kit(&engine, b"same-bytes");
        let b = kit(&engine, b"same-bytes");
        assert!(!a.tools.unwrap().replay);
        assert!(b.tools.unwrap().replay);
    }

    #[test]
    fn latency_median_stays_bounded() {
        let small = [b'a'; 64];
        let mid = vec![b'b'; 4096];
        let big = vec![b'c'; 1_048_576];
        let cases: [(&[u8], u64); 3] =
            [(&small, 5_000_000), (&mid, 10_000_000), (&big, 33_000_000)];
        for (buf, limit_ns) in cases {
            let ns = median_latency(buf);
            assert!(
                ns < limit_ns,
                "len {} median {} ns, limit {} ns",
                buf.len(),
                ns,
                limit_ns
            );
        }
    }

    fn median_latency(buf: &[u8]) -> u64 {
        let engine = ReflexEngine::default();
        let _ = engine.evaluate(Opcode::Kit, FLAG_TOOLS, buf);
        let mut samples = [0u64; 5];
        for sample in &mut samples {
            *sample = engine.evaluate(Opcode::Kit, FLAG_TOOLS, buf).latency_ns;
        }
        samples.sort_unstable();
        samples[2]
    }

    #[test]
    fn single_xss_marker_quarantines_not_drops() {
        let d = ReflexEngine::default().evaluate(Opcode::Route, 0, b"click <script src=probe>");
        assert!(
            d.malicious >= 0.80 && d.malicious < 0.95,
            "mal={}",
            d.malicious
        );
        assert_eq!(d.route, RouteAction::Quarantine);
    }

    #[test]
    fn kit_emits_fingerprint_and_json_format() {
        let d = kit(&ReflexEngine::default(), br#"{"dept":"billing"}"#);
        let t = d.tools.expect("tools");
        assert_eq!(t.format, FormatKind::Json);
        assert!(t.fingerprint != 0);
        assert!(t.utf8_ok);
        assert!(d.latency_ns < 33_000_000);
    }

    #[test]
    fn replay_sets_flag_and_can_drop() {
        let engine = ReflexEngine::default();
        let payload = b"same payload twice";
        let a = engine.evaluate(Opcode::Kit, FLAG_TOOLS, payload);
        let b = engine.evaluate(Opcode::Kit, FLAG_TOOLS | FLAG_DROP_REPLAY, payload);
        assert!(!a.tools.unwrap().replay);
        assert!(b.tools.unwrap().replay);
        assert_eq!(b.route, RouteAction::Drop);
    }

    #[test]
    fn batch_shares_seen_ring() {
        let engine = ReflexEngine::default();
        let items: [(&[u8], Opcode, u16); 3] = [
            (b"one", Opcode::Kit, FLAG_TOOLS),
            (b"two", Opcode::Kit, FLAG_TOOLS),
            (b"one", Opcode::Kit, FLAG_TOOLS),
        ];
        let out = engine.evaluate_batch(&items);
        assert!(!out[0].tools.unwrap().replay);
        assert!(out[2].tools.unwrap().replay);
    }
}
