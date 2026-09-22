//! Defensive span scanners: PII entities and high-signal threat markers.
//!
//! Returns start/end byte offsets into the original buffer. Callers never
//! receive newly allocated strings for the matched text.

use crate::schema::{EntityKind, Span};

pub fn scan_entities(buf: &[u8]) -> Vec<Span> {
    scan_entities_gated(buf, u32::MAX)
}

/// Skip scanners that cannot fire given trigger bits from the sketch pass.
pub fn scan_entities_gated(buf: &[u8], trig: u32) -> Vec<Span> {
    use crate::sketch::{T_AT, T_DASH, T_DIGIT, T_DOT};
    if buf.is_empty() || trig == 0 {
        return Vec::new();
    }
    let mut spans = Vec::new();
    if trig & T_AT != 0 {
        scan_emails(buf, &mut spans);
    }
    if trig & T_DOT != 0 && trig & T_DIGIT != 0 {
        scan_ipv4(buf, &mut spans);
    }
    if trig & T_DIGIT != 0 {
        scan_phones(buf, &mut spans);
        scan_credit_cards(buf, &mut spans);
    }
    if trig & T_DASH != 0 && trig & T_DIGIT != 0 {
        scan_ssn(buf, &mut spans);
    }
    if trig & T_DOT != 0 {
        scan_jwts(buf, &mut spans);
    }
    scan_api_keys(buf, &mut spans);
    scan_bearer(buf, &mut spans);
    spans.sort_by_key(|s| (s.start, s.end));
    merge_overlaps(spans)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ThreatHits {
    pub sqli: u32,
    pub xss: u32,
    pub path: u32,
}

pub fn scan_threats(buf: &[u8]) -> ThreatHits {
    scan_threats_gated(buf, u32::MAX)
}

pub fn scan_threats_gated(buf: &[u8], trig: u32) -> ThreatHits {
    use crate::sketch::{T_DASH, T_DOT, T_EQ, T_LT, T_PERCENT, T_QUOTE, T_SLASH};
    let mut hits = ThreatHits::default();
    if buf.is_empty() {
        return hits;
    }
    if trig & (T_QUOTE | T_DASH | T_EQ) != 0 {
        for pat in SQLI_MARKERS {
            hits.sqli += count_slice_ci(buf, pat) as u32;
        }
    }
    if trig & T_LT != 0 {
        for pat in XSS_MARKERS {
            hits.xss += count_slice_ci(buf, pat) as u32;
        }
    }
    if trig & (T_DOT | T_SLASH | T_PERCENT) != 0 {
        for pat in PATH_MARKERS {
            hits.path += count_slice_ci(buf, pat) as u32;
        }
    }
    hits
}

const SQLI_MARKERS: &[&[u8]] = &[
    b"' or ",
    b"\" or ",
    b"' or'",
    b" or 1=1",
    b" or 1=1--",
    b"union select",
    b"';--",
    b"') --",
    b"drop table",
    b"insert into",
    b"xp_cmdshell",
];

const XSS_MARKERS: &[&[u8]] = &[
    b"<script",
    b"javascript:",
    b"onerror=",
    b"onload=",
    b"<img src=",
];

const PATH_MARKERS: &[&[u8]] = &[b"../", b"..\\", b"%2e%2e", b"/etc/passwd"];

fn count_slice_ci(hay: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || hay.len() < needle.len() {
        return 0;
    }
    hay.windows(needle.len())
        .filter(|w| {
            w.iter()
                .zip(needle.iter())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
        })
        .count()
}

fn merge_overlaps(spans: Vec<Span>) -> Vec<Span> {
    let mut out: Vec<Span> = Vec::with_capacity(spans.len());
    for span in spans {
        if let Some(last) = out.last_mut() {
            if span.start < last.end && span.kind == last.kind {
                last.end = last.end.max(span.end);
                continue;
            }
        }
        out.push(span);
    }
    out
}

fn scan_emails(buf: &[u8], out: &mut Vec<Span>) {
    let n = buf.len();
    let mut i = 0;
    while i < n {
        if buf[i] == b'@' && i > 0 {
            let mut a = i;
            while a > 0 && is_email_local(buf[a - 1]) {
                a -= 1;
            }
            let mut b = i + 1;
            let mut dots = 0;
            while b < n && is_email_domain(buf[b]) {
                if buf[b] == b'.' {
                    dots += 1;
                }
                b += 1;
            }
            if a < i && b > i + 1 && dots >= 1 && b - a >= 6 {
                out.push(Span {
                    start: a as u32,
                    end: b as u32,
                    kind: EntityKind::Email,
                });
                i = b;
                continue;
            }
        }
        i += 1;
    }
}

fn is_email_local(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_email_domain(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

fn scan_ipv4(buf: &[u8], out: &mut Vec<Span>) {
    let n = buf.len();
    let mut i = 0;
    while i < n {
        if buf[i].is_ascii_digit() {
            if let Some(end) = match_ipv4(buf, i) {
                out.push(Span {
                    start: i as u32,
                    end: end as u32,
                    kind: EntityKind::Ipv4,
                });
                i = end;
                continue;
            }
        }
        i += 1;
    }
}

fn match_ipv4(buf: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    for part in 0..4 {
        if pos >= buf.len() || !buf[pos].is_ascii_digit() {
            return None;
        }
        let mut val = 0u32;
        let mut digits = 0;
        while pos < buf.len() && buf[pos].is_ascii_digit() && digits < 3 {
            val = val * 10 + (buf[pos] - b'0') as u32;
            pos += 1;
            digits += 1;
        }
        if digits == 0 || val > 255 {
            return None;
        }
        if part < 3 {
            if pos >= buf.len() || buf[pos] != b'.' {
                return None;
            }
            pos += 1;
        }
    }
    if start > 0 && buf[start - 1].is_ascii_digit() {
        return None;
    }
    if pos < buf.len() && buf[pos].is_ascii_digit() {
        return None;
    }
    Some(pos)
}

fn scan_phones(buf: &[u8], out: &mut Vec<Span>) {
    let n = buf.len();
    let mut i = 0;
    while i < n {
        if buf[i] == b'+' || buf[i].is_ascii_digit() {
            let mut j = i;
            let mut digits = 0u32;
            if buf[j] == b'+' {
                j += 1;
            }
            let mut k = j;
            while k < n && (buf[k].is_ascii_digit() || matches!(buf[k], b'-' | b' ' | b'(' | b')'))
            {
                if buf[k].is_ascii_digit() {
                    digits += 1;
                }
                k += 1;
            }
            if (10..=15).contains(&digits) && k - i >= 10 {
                out.push(Span {
                    start: i as u32,
                    end: k as u32,
                    kind: EntityKind::Phone,
                });
                i = k;
                continue;
            }
        }
        i += 1;
    }
}

fn scan_ssn(buf: &[u8], out: &mut Vec<Span>) {
    // ###-##-####
    if buf.len() < 11 {
        return;
    }
    for i in 0..=buf.len() - 11 {
        if buf[i].is_ascii_digit()
            && buf[i + 1].is_ascii_digit()
            && buf[i + 2].is_ascii_digit()
            && buf[i + 3] == b'-'
            && buf[i + 4].is_ascii_digit()
            && buf[i + 5].is_ascii_digit()
            && buf[i + 6] == b'-'
            && buf[i + 7].is_ascii_digit()
            && buf[i + 8].is_ascii_digit()
            && buf[i + 9].is_ascii_digit()
            && buf[i + 10].is_ascii_digit()
        {
            if i > 0 && buf[i - 1].is_ascii_digit() {
                continue;
            }
            if i + 11 < buf.len() && buf[i + 11].is_ascii_digit() {
                continue;
            }
            out.push(Span {
                start: i as u32,
                end: (i + 11) as u32,
                kind: EntityKind::Ssn,
            });
        }
    }
}

fn scan_credit_cards(buf: &[u8], out: &mut Vec<Span>) {
    let n = buf.len();
    let mut i = 0;
    while i < n {
        if buf[i].is_ascii_digit() {
            let mut j = i;
            let mut digits = Vec::with_capacity(16);
            while j < n && digits.len() < 19 {
                if buf[j].is_ascii_digit() {
                    digits.push(buf[j]);
                    j += 1;
                } else if matches!(buf[j], b' ' | b'-') && !digits.is_empty() {
                    j += 1;
                } else {
                    break;
                }
            }
            if (13..=19).contains(&digits.len()) && luhn(&digits) {
                out.push(Span {
                    start: i as u32,
                    end: j as u32,
                    kind: EntityKind::CreditCard,
                });
                i = j;
                continue;
            }
        }
        i += 1;
    }
}

pub fn luhn(digits: &[u8]) -> bool {
    if digits.len() < 13 {
        return false;
    }
    let mut sum = 0u32;
    let mut alt = false;
    for &d in digits.iter().rev() {
        if !d.is_ascii_digit() {
            return false;
        }
        let mut n = (d - b'0') as u32;
        if alt {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        alt = !alt;
    }
    sum % 10 == 0
}

fn is_b64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')
}

fn scan_jwts(buf: &[u8], out: &mut Vec<Span>) {
    let n = buf.len();
    let mut i = 0;
    while i + 20 < n {
        if is_b64url(buf[i]) {
            let mut dots = 0;
            let mut j = i;
            while j < n && (is_b64url(buf[j]) || buf[j] == b'.' || buf[j] == b'=') {
                if buf[j] == b'.' {
                    dots += 1;
                    if dots > 2 {
                        break;
                    }
                }
                j += 1;
            }
            if dots == 2 && j - i >= 20 {
                let slice = &buf[i..j];
                if slice.starts_with(b"eyJ") || slice.windows(4).any(|w| w == b".eyJ") {
                    out.push(Span {
                        start: i as u32,
                        end: j as u32,
                        kind: EntityKind::Jwt,
                    });
                    i = j;
                    continue;
                }
            }
        }
        i += 1;
    }
}

fn scan_api_keys(buf: &[u8], out: &mut Vec<Span>) {
    const PREFIXES: &[&[u8]] = &[
        b"sk_live_",
        b"sk_test_",
        b"ghp_",
        b"gho_",
        b"xoxb-",
        b"xoxp-",
        b"AKIA",
    ];
    for prefix in PREFIXES {
        let mut start = 0;
        while let Some(rel) = find_subsequence(&buf[start..], prefix) {
            let i = start + rel;
            let mut j = i + prefix.len();
            while j < buf.len() && (buf[j].is_ascii_alphanumeric() || matches!(buf[j], b'_' | b'-'))
            {
                j += 1;
            }
            if j - i >= prefix.len() + 8 {
                out.push(Span {
                    start: i as u32,
                    end: j as u32,
                    kind: EntityKind::ApiKey,
                });
            }
            start = i + 1;
        }
    }
}

fn scan_bearer(buf: &[u8], out: &mut Vec<Span>) {
    let mut start = 0;
    while let Some(rel) = find_subsequence_ci(&buf[start..], b"bearer ") {
        let i = start + rel;
        let mut j = i + 7;
        while j < buf.len()
            && (buf[j].is_ascii_alphanumeric() || matches!(buf[j], b'_' | b'-' | b'.'))
        {
            j += 1;
        }
        if j - i > 12 {
            out.push(Span {
                start: i as u32,
                end: j as u32,
                kind: EntityKind::Bearer,
            });
        }
        start = i + 1;
    }
}

fn find_subsequence(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn find_subsequence_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| {
        w.iter()
            .zip(needle.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_span() {
        let buf = b"contact jane.doe@example.com please";
        let spans = scan_entities(buf);
        let email = spans.iter().find(|s| s.kind == EntityKind::Email).unwrap();
        assert_eq!(email.as_bytes(buf).unwrap(), b"jane.doe@example.com");
    }

    #[test]
    fn luhn_test_card() {
        assert!(luhn(b"4111111111111111"));
        assert!(!luhn(b"4111111111111112"));
    }

    #[test]
    fn ipv4_and_ssn() {
        let buf = b"host 10.0.0.8 user 123-45-6789";
        let spans = scan_entities(buf);
        assert!(spans.iter().any(|s| s.kind == EntityKind::Ipv4));
        assert!(spans.iter().any(|s| s.kind == EntityKind::Ssn));
    }

    #[test]
    fn threat_sql_marker() {
        let hits = scan_threats(b"login admin' OR 1=1--");
        assert!(hits.sqli >= 1);
    }

    #[test]
    fn threat_markers_are_case_insensitive_without_copy() {
        let hits = scan_threats(b"UNION SELECT from dual");
        assert!(hits.sqli >= 1);
    }
}
