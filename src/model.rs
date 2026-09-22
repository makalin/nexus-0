//! Tiny non-autoregressive decision head: mean-pooled byte embeddings + FFN.
//!
//! One matrix multiply stack, no sequential decoding. Weights are hand-set so
//! the built-in threat / PII / regularity axes are linearly separable. This is
//! not a trained transformer. A later model can replace this module without
//! touching IPC.

use crate::features::{sigmoid, FEATURE_DIM};

pub const EMBED_DIM: usize = 8;
pub const HIDDEN_DIM: usize = 12;
pub const OUT_DIM: usize = 3;
pub const IN_DIM: usize = FEATURE_DIM + EMBED_DIM;
pub const EMBED_SAMPLE_CAP: usize = 8192;

#[derive(Clone, Debug)]
pub struct ReflexHead {
    embed: [[f32; EMBED_DIM]; 256],
    w1: [[f32; IN_DIM]; HIDDEN_DIM],
    b1: [f32; HIDDEN_DIM],
    w2: [[f32; HIDDEN_DIM]; OUT_DIM],
    b2: [f32; OUT_DIM],
}

#[derive(Clone, Copy, Debug)]
pub struct HeadScores {
    pub malicious: f32,
    pub pii: f32,
    pub ai_marker: f32,
}

impl Default for ReflexHead {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::needless_range_loop)]
impl ReflexHead {
    pub fn new() -> Self {
        let mut embed = [[0.0f32; EMBED_DIM]; 256];
        for b in 0..256u16 {
            let byte = b as u8;
            let mut v = [0.0f32; EMBED_DIM];
            v[0] = 0.05;
            if byte.is_ascii_digit() {
                v[1] = 1.0;
            }
            if byte.is_ascii_alphabetic() {
                v[2] = 1.0;
            }
            if matches!(byte, b'\'' | b'"' | b';' | b'-' | b'#' | b'=') {
                v[3] = 1.2; // SQL-ish punctuation
            }
            if matches!(byte, b'<' | b'>' | b'/') {
                v[4] = 1.0; // markup / path
            }
            if byte == b'@' || byte == b'.' {
                v[5] = 1.0; // email-ish
            }
            if byte < 0x20 && byte != b'\t' && byte != b'\n' && byte != b'\r' {
                v[6] = 1.5;
            }
            if byte > 0x7e {
                v[7] = 1.0;
            }
            embed[b as usize] = v;
        }

        let mut w1 = [[0.0f32; IN_DIM]; HIDDEN_DIM];
        let mut b1 = [0.0f32; HIDDEN_DIM];
        // Hidden units specialized to feature axes (features occupy 0..16, embed 16..24).
        // 0: threat mix, 1: pii mix, 2: smoothness/AI, 3: control/binary
        for j in 0..IN_DIM {
            w1[0][j] = 0.02;
            w1[1][j] = 0.02;
            w1[2][j] = 0.02;
        }
        w1[0][10] = 2.8; // sqli
        w1[0][11] = 2.6; // xss
        w1[0][12] = 2.4; // path
        w1[0][6] = 1.4; // control
        w1[0][IN_DIM - 5] = 1.1; // embed threat punct
        b1[0] = -0.6;

        w1[1][7] = 2.5; // pii density
        w1[1][8] = 2.2; // email
        w1[1][9] = 2.4; // keys
        w1[1][2] = 0.4; // digits
        w1[1][IN_DIM - 3] = 0.8; // embed @/.
        b1[1] = -0.5;

        w1[2][15] = 2.0; // smoothness
        w1[2][1] = 0.8; // printable
        w1[2][0] = 0.6; // entropy
        w1[2][13] = -1.2; // repeats (encrypted/low)
        b1[2] = -0.4;

        w1[3][6] = 2.0;
        w1[3][IN_DIM - 2] = 1.5;
        b1[3] = -0.3;

        for h in 4..HIDDEN_DIM {
            for j in 0..IN_DIM {
                w1[h][j] = 0.04 * ((h + j) % 5) as f32 - 0.08;
            }
            b1[h] = -0.1;
        }

        let mut w2 = [[0.0f32; HIDDEN_DIM]; OUT_DIM];
        let mut b2 = [0.0f32; OUT_DIM];
        w2[0][0] = 2.4;
        w2[0][3] = 0.8;
        b2[0] = -0.2;
        w2[1][1] = 2.6;
        b2[1] = -0.15;
        w2[2][2] = 2.2;
        b2[2] = -0.2;

        Self {
            embed,
            w1,
            b1,
            w2,
            b2,
        }
    }

    pub fn forward(&self, payload: &[u8], features: &[f32; FEATURE_DIM]) -> HeadScores {
        self.forward_capped(payload, features, EMBED_SAMPLE_CAP)
    }

    /// Mean-pool at most `cap` bytes (strided) so a 1 MiB payload stays sub-ms.
    pub fn forward_capped(
        &self,
        payload: &[u8],
        features: &[f32; FEATURE_DIM],
        cap: usize,
    ) -> HeadScores {
        let mut pooled = [0.0f32; EMBED_DIM];
        if !payload.is_empty() {
            let stride = if payload.len() <= cap {
                1
            } else {
                (payload.len() + cap - 1) / cap
            };
            let mut n = 0u32;
            let mut i = 0;
            while i < payload.len() {
                let e = &self.embed[payload[i] as usize];
                for k in 0..EMBED_DIM {
                    pooled[k] += e[k];
                }
                n += 1;
                i += stride;
            }
            let inv = 1.0 / n.max(1) as f32;
            for k in 0..EMBED_DIM {
                pooled[k] *= inv;
            }
        }

        let mut x = [0.0f32; IN_DIM];
        x[..FEATURE_DIM].copy_from_slice(features);
        x[FEATURE_DIM..].copy_from_slice(&pooled);

        let mut h = [0.0f32; HIDDEN_DIM];
        for i in 0..HIDDEN_DIM {
            let mut s = self.b1[i];
            for j in 0..IN_DIM {
                s += self.w1[i][j] * x[j];
            }
            h[i] = s.max(0.0); // ReLU
        }

        let mut y = [0.0f32; OUT_DIM];
        for i in 0..OUT_DIM {
            let mut s = self.b2[i];
            for j in 0..HIDDEN_DIM {
                s += self.w2[i][j] * h[j];
            }
            y[i] = sigmoid(s);
        }

        HeadScores {
            malicious: y[0],
            pii: y[1],
            ai_marker: y[2],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::extract_features;
    use crate::patterns::scan_entities;

    #[test]
    fn sql_payload_scores_higher_than_hello() {
        let head = ReflexHead::new();
        let benign = b"hello world, how are you today?";
        let hostile = b"admin' OR 1=1-- union select";
        let sb = scan_entities(benign);
        let sh = scan_entities(hostile);
        let fb = extract_features(benign, &sb);
        let fh = extract_features(hostile, &sh);
        let yb = head.forward(benign, &fb.values);
        let yh = head.forward(hostile, &fh.values);
        assert!(yh.malicious > yb.malicious);
    }
}
