//! Statistical features derived from the fused sketch (no second byte scan).

use crate::patterns::ThreatHits;
use crate::schema::{EntityKind, Span};
use crate::sketch::Sketch;

pub const FEATURE_DIM: usize = 16;

#[derive(Clone, Debug)]
pub struct FeatureVec {
    pub values: [f32; FEATURE_DIM],
    pub entropy: f32,
    pub threats: ThreatHits,
    pub pii_bytes: usize,
}

pub fn extract_features(payload: &[u8], spans: &[Span]) -> FeatureVec {
    let sk = crate::sketch::sketch(payload);
    let threats = crate::patterns::scan_threats_gated(payload, sk.triggers);
    features_from_sketch(&sk, spans, threats)
}

pub fn features_from_sketch(sk: &Sketch, spans: &[Span], threats: ThreatHits) -> FeatureVec {
    let n = sk.len.max(1) as f32;
    let pii_bytes: usize = spans.iter().map(|s| s.len() as usize).sum();
    let email_n = spans.iter().filter(|s| s.kind == EntityKind::Email).count();
    let key_n = spans
        .iter()
        .filter(|s| {
            matches!(
                s.kind,
                EntityKind::ApiKey | EntityKind::Jwt | EntityKind::Bearer
            )
        })
        .count();

    let mut values = [0.0f32; FEATURE_DIM];
    values[0] = (sk.entropy / 8.0).clamp(0.0, 1.0);
    values[1] = sk.printable as f32 / n;
    values[2] = sk.digits as f32 / n;
    values[3] = sk.alpha as f32 / n;
    values[4] = sk.space as f32 / n;
    values[5] = sk.punct as f32 / n;
    values[6] = sk.control as f32 / n;
    values[7] = (pii_bytes as f32 / n).clamp(0.0, 1.0);
    values[8] = ((email_n as f32) / 4.0).clamp(0.0, 1.0);
    values[9] = ((key_n as f32) / 3.0).clamp(0.0, 1.0);
    values[10] = ((threats.sqli as f32) / 3.0).clamp(0.0, 1.0);
    values[11] = ((threats.xss as f32) / 2.0).clamp(0.0, 1.0);
    values[12] = ((threats.path as f32) / 2.0).clamp(0.0, 1.0);
    values[13] = sk.repeats as f32 / n;
    values[14] = (sk.token_mean / 16.0).clamp(0.0, 1.0);
    values[15] = sk.token_smooth;

    FeatureVec {
        values,
        entropy: sk.entropy,
        threats,
        pii_bytes,
    }
}

/// Independent structural-entropy / AI-marker estimate used alongside the FFN.
pub fn ai_marker_score(feat: &FeatureVec) -> f32 {
    let entropy_mid = 1.0 - (feat.values[0] - 0.55).abs() * 2.0;
    let s = 1.6 * feat.values[15] + 0.8 * feat.values[1] + 0.6 * entropy_mid.clamp(0.0, 1.0)
        - 0.7 * feat.values[13]
        - 0.4 * feat.values[6];
    sigmoid(s - 0.9)
}

pub fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero_entropy() {
        let f = extract_features(b"", &[]);
        assert_eq!(f.entropy, 0.0);
    }

    #[test]
    fn repeated_bytes_low_entropy() {
        let f = extract_features(&[b'a'; 64], &[]);
        assert!(f.entropy < 0.5);
    }

    #[test]
    fn mixed_text_mid_entropy() {
        let f = extract_features(b"The quick brown fox jumps over 13 lazy dogs.", &[]);
        assert!(f.entropy > 3.0 && f.entropy < 6.0);
    }
}
