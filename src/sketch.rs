//! One-pass payload sketch: histogram, hash, format, utf8, triggers.
//!
//! This is the hot path. Entity scanners and the FFN run *after* this, and
//! only if trigger bits say they can fire.

use crate::schema::FormatKind;

pub const T_AT: u32 = 1 << 0;
pub const T_DIGIT: u32 = 1 << 1;
pub const T_DOT: u32 = 1 << 2;
pub const T_LT: u32 = 1 << 3;
pub const T_QUOTE: u32 = 1 << 4;
pub const T_DASH: u32 = 1 << 5;
pub const T_SLASH: u32 = 1 << 6;
pub const T_COLON: u32 = 1 << 7;
pub const T_EQ: u32 = 1 << 8;
pub const T_PERCENT: u32 = 1 << 9;
pub const T_UNDERSCORE: u32 = 1 << 10;
pub const T_CR: u32 = 1 << 11;

pub const PII_TRIGGERS: u32 = T_AT | T_DIGIT | T_DOT | T_DASH | T_UNDERSCORE | T_COLON;
pub const THREAT_TRIGGERS: u32 = T_LT | T_QUOTE | T_SLASH | T_PERCENT | T_EQ | T_DASH | T_DOT;

const FNV_OFF: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

#[derive(Clone, Debug)]
pub struct Sketch {
    pub len: usize,
    pub hist: [u32; 256],
    pub printable: u32,
    pub digits: u32,
    pub alpha: u32,
    pub space: u32,
    pub punct: u32,
    pub control: u32,
    pub repeats: u32,
    pub entropy: f32,
    pub token_mean: f32,
    pub token_smooth: f32,
    pub token_count: u32,
    pub triggers: u32,
    pub fingerprint: u64,
    pub simhash: u64,
    pub utf8_errors: u16,
    pub utf8_ok: bool,
    pub format: FormatKind,
    pub json_depth: u16,
    pub json_keys: u16,
    pub http_body_off: u32,
}

pub fn sketch(payload: &[u8]) -> Sketch {
    let n = payload.len();
    let mut hist = [0u32; 256];
    let mut printable = 0u32;
    let mut digits = 0u32;
    let mut alpha = 0u32;
    let mut space = 0u32;
    let mut punct = 0u32;
    let mut control = 0u32;
    let mut repeats = 0u32;
    let mut prev = 0u8;
    let mut have_prev = false;
    let mut triggers = 0u32;
    let mut hash = FNV_OFF ^ n as u64;
    let mut utf8 = Utf8::new();
    let mut json = JsonWalk::new();
    let mut http = HttpWalk::new();
    let mut tokens = Welford::new();
    let mut run = 0u32;
    let mut sh = [0i16; 64];

    let sim_hi = n.saturating_sub(256);

    for (i, &b) in payload.iter().enumerate() {
        hist[b as usize] += 1;
        hash = hash.wrapping_mul(FNV_PRIME) ^ b as u64;
        utf8.push(b);
        json.push(b);
        http.push(b, i);

        if i < 4096 || i >= sim_hi {
            let mix = (b as u64).wrapping_mul(0x9E3779B97F4A7C15) ^ (i as u64);
            for k in 0..8 {
                let lane = ((mix as usize) + k * 13) & 63;
                if (b >> k) & 1 == 1 {
                    sh[lane] = sh[lane].saturating_add(1);
                } else {
                    sh[lane] = sh[lane].saturating_sub(1);
                }
            }
        }

        match b {
            b'@' => triggers |= T_AT,
            b'0'..=b'9' => triggers |= T_DIGIT,
            b'.' => triggers |= T_DOT,
            b'<' => triggers |= T_LT,
            b'\'' | b'"' => triggers |= T_QUOTE,
            b'-' => triggers |= T_DASH,
            b'/' | b'\\' => triggers |= T_SLASH,
            b':' => triggers |= T_COLON,
            b'=' => triggers |= T_EQ,
            b'%' => triggers |= T_PERCENT,
            b'_' => triggers |= T_UNDERSCORE,
            b'\r' => triggers |= T_CR,
            _ => {}
        }

        match b {
            0x20 | 0x09 | 0x0a | 0x0d => {
                space += 1;
                tokens.flush(&mut run);
            }
            b'0'..=b'9' => {
                digits += 1;
                printable += 1;
                run += 1;
            }
            b'A'..=b'Z' | b'a'..=b'z' => {
                alpha += 1;
                printable += 1;
                run += 1;
            }
            0x21..=0x2f | 0x3a..=0x40 | 0x5b..=0x60 | 0x7b..=0x7e => {
                punct += 1;
                printable += 1;
                tokens.flush(&mut run);
            }
            _ => {
                control += 1;
                tokens.flush(&mut run);
            }
        }
        if have_prev && b == prev {
            repeats += 1;
        }
        prev = b;
        have_prev = true;
    }
    tokens.flush(&mut run);

    let mut simhash = 0u64;
    for (k, v) in sh.iter().enumerate() {
        if *v >= 0 {
            simhash |= 1u64 << k;
        }
    }

    let entropy = shannon(&hist, n);
    let (token_mean, token_smooth) = tokens.finish();
    let utf8_ok = utf8.errors == 0 && utf8.pending == 0;
    let format = classify_format(payload, &json, &http, utf8_ok, control, n);

    Sketch {
        len: n,
        hist,
        printable,
        digits,
        alpha,
        space,
        punct,
        control,
        repeats,
        entropy,
        token_mean,
        token_smooth,
        token_count: tokens.n,
        triggers,
        fingerprint: hash,
        simhash,
        utf8_errors: utf8.errors.min(u16::MAX as u32) as u16,
        utf8_ok,
        format,
        json_depth: json.max_depth,
        json_keys: json.keys,
        http_body_off: http.body_off,
    }
}

fn classify_format(
    payload: &[u8],
    json: &JsonWalk,
    http: &HttpWalk,
    utf8_ok: bool,
    control: u32,
    n: usize,
) -> FormatKind {
    if n == 0 {
        return FormatKind::Empty;
    }
    if http.body_off > 0 {
        return FormatKind::Http;
    }
    let start = skip_ws(payload);
    if start < n && (payload[start] == b'{' || payload[start] == b'[') && json.max_depth > 0 {
        return FormatKind::Json;
    }
    if start < n && payload[start] == b'<' {
        return FormatKind::Xml;
    }
    if starts_http(payload) {
        return FormatKind::Http;
    }
    let ctrl_ratio = control as f32 / n as f32;
    if ctrl_ratio > 0.08 || !utf8_ok {
        FormatKind::Binary
    } else {
        FormatKind::Utf8Text
    }
}

fn skip_ws(buf: &[u8]) -> usize {
    let mut i = 0;
    while i < buf.len() && matches!(buf[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

fn starts_http(buf: &[u8]) -> bool {
    const METH: [&[u8]; 8] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"PATCH ",
        b"HEAD ",
        b"DELETE ",
        b"OPTIONS ",
        b"HTTP/",
    ];
    METH.iter()
        .any(|m| buf.len() >= m.len() && buf.starts_with(m))
}

fn shannon(hist: &[u32; 256], n: usize) -> f32 {
    if n == 0 {
        return 0.0;
    }
    let inv = 1.0 / n as f64;
    let mut h = 0.0f64;
    for &c in hist {
        if c == 0 {
            continue;
        }
        let p = c as f64 * inv;
        h -= p * p.log2();
    }
    h as f32
}

struct Welford {
    n: u32,
    mean: f64,
    m2: f64,
}

impl Welford {
    fn new() -> Self {
        Self {
            n: 0,
            mean: 0.0,
            m2: 0.0,
        }
    }
    fn flush(&mut self, run: &mut u32) {
        if *run == 0 {
            return;
        }
        let x = *run as f64;
        self.n += 1;
        let d = x - self.mean;
        self.mean += d / self.n as f64;
        self.m2 += d * (x - self.mean);
        *run = 0;
    }
    fn finish(&self) -> (f32, f32) {
        if self.n == 0 {
            return (0.0, 0.5);
        }
        let std = (self.m2 / self.n as f64).sqrt();
        let burst = if self.mean > 0.0 {
            ((std / self.mean) as f32).clamp(0.0, 2.0) / 2.0
        } else {
            0.5
        };
        (self.mean as f32, 1.0 - burst)
    }
}

struct Utf8 {
    pending: u8,
    errors: u32,
}

impl Utf8 {
    fn new() -> Self {
        Self {
            pending: 0,
            errors: 0,
        }
    }
    fn push(&mut self, b: u8) {
        if self.pending == 0 {
            if b < 0x80 {
                return;
            }
            self.pending = if b & 0xE0 == 0xC0 {
                1
            } else if b & 0xF0 == 0xE0 {
                2
            } else if b & 0xF8 == 0xF0 {
                3
            } else {
                self.errors += 1;
                0
            };
        } else if b & 0xC0 == 0x80 {
            self.pending -= 1;
        } else {
            self.errors += 1;
            self.pending = 0;
        }
    }
}

struct JsonWalk {
    depth: u16,
    max_depth: u16,
    keys: u16,
    in_str: bool,
    escape: bool,
    expect_key: bool,
}

impl JsonWalk {
    fn new() -> Self {
        Self {
            depth: 0,
            max_depth: 0,
            keys: 0,
            in_str: false,
            escape: false,
            expect_key: true,
        }
    }
    fn push(&mut self, b: u8) {
        if self.in_str {
            if self.escape {
                self.escape = false;
            } else if b == b'\\' {
                self.escape = true;
            } else if b == b'"' {
                self.in_str = false;
            }
            return;
        }
        match b {
            b'"' => {
                self.in_str = true;
                if self.expect_key && self.depth > 0 {
                    self.keys = self.keys.saturating_add(1);
                }
            }
            b'{' | b'[' => {
                self.depth = self.depth.saturating_add(1);
                self.max_depth = self.max_depth.max(self.depth);
                self.expect_key = b == b'{';
            }
            b'}' | b']' => {
                self.depth = self.depth.saturating_sub(1);
                self.expect_key = true;
            }
            b':' => self.expect_key = false,
            b',' => self.expect_key = true,
            _ => {}
        }
    }
}

struct HttpWalk {
    crlf: u8,
    body_off: u32,
}

impl HttpWalk {
    fn new() -> Self {
        Self {
            crlf: 0,
            body_off: 0,
        }
    }
    fn push(&mut self, b: u8, i: usize) {
        if self.body_off != 0 {
            return;
        }
        match (self.crlf, b) {
            (0, b'\r') => self.crlf = 1,
            (1, b'\n') => self.crlf = 2,
            (2, b'\r') => self.crlf = 3,
            (3, b'\n') => {
                self.body_off = (i + 1) as u32;
                self.crlf = 0;
            }
            _ => self.crlf = if b == b'\r' { 1 } else { 0 },
        }
    }
}

/// Hash the payload as-if PII spans were already masked, without allocating.
pub fn redact_fingerprint(payload: &[u8], spans: &[crate::schema::Span], mask: u8) -> u64 {
    let mut h = FNV_OFF ^ payload.len() as u64;
    let mut pos = 0usize;
    for span in spans {
        let s = (span.start as usize).min(payload.len());
        let e = (span.end as usize).min(payload.len());
        if s > pos {
            for &b in &payload[pos..s] {
                h = h.wrapping_mul(FNV_PRIME) ^ b as u64;
            }
        }
        for _ in s..e {
            h = h.wrapping_mul(FNV_PRIME) ^ mask as u64;
        }
        pos = e.max(pos);
    }
    if pos < payload.len() {
        for &b in &payload[pos..] {
            h = h.wrapping_mul(FNV_PRIME) ^ b as u64;
        }
    }
    h
}

pub fn hamming(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

/// Longest valid UTF-8 prefix not exceeding `max` bytes.
pub fn utf8_prefix(buf: &[u8], max: usize) -> usize {
    let max = max.min(buf.len());
    let mut i = 0;
    while i < max {
        let b = buf[i];
        let need = if b < 0x80 {
            1
        } else if b & 0xE0 == 0xC0 {
            2
        } else if b & 0xF0 == 0xE0 {
            3
        } else if b & 0xF8 == 0xF0 {
            4
        } else {
            break;
        };
        if i + need > max {
            break;
        }
        if !(1..need).all(|k| buf[i + k] & 0xC0 == 0x80) {
            break;
        }
        i += need;
    }
    i
}

pub fn const_eq(a: &[u8], b: &[u8]) -> bool {
    let n = a.len().min(b.len());
    let mut acc = u8::from(a.len() != b.len());
    for i in 0..n {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_and_http_format() {
        let j = sketch(br#"{"dept":"billing","n":2}"#);
        assert_eq!(j.format, FormatKind::Json);
        assert!(j.json_keys >= 1);
        assert!(j.utf8_ok);

        let raw = b"POST /v1 HTTP/1.1\r\nHost: x\r\n\r\nbody";
        let h = sketch(raw);
        assert_eq!(h.format, FormatKind::Http);
        assert!(h.http_body_off as usize > 0);
        assert_eq!(&raw[h.http_body_off as usize..], b"body");
    }

    #[test]
    fn fingerprint_stable_and_sensitive() {
        let a = sketch(b"hello");
        let b = sketch(b"hello");
        let c = sketch(b"hello!");
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_ne!(a.fingerprint, c.fingerprint);
    }

    #[test]
    fn utf8_prefix_does_not_split_char() {
        let s = "néxus".as_bytes();
        let cut = utf8_prefix(s, 2);
        assert!(std::str::from_utf8(&s[..cut]).is_ok());
    }

    #[test]
    fn const_eq_rejects_length() {
        assert!(!const_eq(b"ab", b"abc"));
        assert!(const_eq(b"ab", b"ab"));
    }
}
