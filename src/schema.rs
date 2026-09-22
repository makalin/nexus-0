//! Packed little-endian wire schema. No JSON, no serde.

use crate::{MAGIC, PROTOCOL_VERSION};

/// Execution mode bound to a single forward pass.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode {
    Extract = 0x01,
    Redact = 0x02,
    Route = 0x03,
    /// Entropy and decision-head scores. Skips entity and threat scanners.
    Entropy = 0x04,
    /// Combined reflex: extract + redact-plan + route + entropy in one pass.
    Reflex = 0x05,
    /// Reflex plus OS tool trailer (fingerprint, format, replay, …).
    Kit = 0x06,
    Fingerprint = 0x07,
    Format = 0x08,
    Seen = 0x09,
}

impl Opcode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Extract),
            0x02 => Some(Self::Redact),
            0x03 => Some(Self::Route),
            0x04 => Some(Self::Entropy),
            0x05 => Some(Self::Reflex),
            0x06 => Some(Self::Kit),
            0x07 => Some(Self::Fingerprint),
            0x08 => Some(Self::Format),
            0x09 => Some(Self::Seen),
            _ => None,
        }
    }

    pub fn wants_tools(self) -> bool {
        matches!(
            self,
            Self::Kit | Self::Fingerprint | Self::Format | Self::Seen
        )
    }

    pub fn skip_scanners(self) -> bool {
        matches!(self, Self::Fingerprint | Self::Format | Self::Seen)
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteAction {
    Accept = 0,
    Quarantine = 1,
    Drop = 2,
}

impl RouteAction {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Quarantine,
            2 => Self::Drop,
            _ => Self::Accept,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "ACCEPT",
            Self::Quarantine => "QUARANTINE",
            Self::Drop => "DROP",
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntityKind {
    Email = 1,
    Phone = 2,
    Ipv4 = 3,
    CreditCard = 4,
    Jwt = 5,
    ApiKey = 6,
    Ssn = 7,
    Bearer = 8,
}

impl EntityKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Email),
            2 => Some(Self::Phone),
            3 => Some(Self::Ipv4),
            4 => Some(Self::CreditCard),
            5 => Some(Self::Jwt),
            6 => Some(Self::ApiKey),
            7 => Some(Self::Ssn),
            8 => Some(Self::Bearer),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Ipv4 => "ipv4",
            Self::CreditCard => "credit_card",
            Self::Jwt => "jwt",
            Self::ApiKey => "api_key",
            Self::Ssn => "ssn",
            Self::Bearer => "bearer",
        }
    }
}

/// Byte-offset span into the caller's payload. No string allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: u32,
    pub end: u32,
    pub kind: EntityKind,
}

impl Span {
    pub fn len(self) -> u32 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(self) -> bool {
        self.len() == 0
    }

    pub fn as_bytes<'a>(&self, payload: &'a [u8]) -> Option<&'a [u8]> {
        let s = self.start as usize;
        let e = self.end as usize;
        payload.get(s..e)
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub opcode: Opcode,
    pub flags: u16,
    pub seq: u64,
    pub payload: Vec<u8>,
}

pub const FLAG_RETURN_SPANS: u16 = 0x0001;
pub const FLAG_APPLY_REDACT: u16 = 0x0002;
/// Drop when the malicious score is at or above the drop threshold (default 0.95).
/// Without this flag that score is quarantined (default quarantine threshold 0.80).
/// Scores are heuristic pattern blends, not a security boundary.
pub const FLAG_DROP_IF_MALICIOUS: u16 = 0x0004;
pub const FLAG_ECHO_PAYLOAD: u16 = 0x0008;
pub const FLAG_TOOLS: u16 = 0x0010;
pub const FLAG_DROP_REPLAY: u16 = 0x0020;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatKind {
    Empty = 0,
    Utf8Text = 1,
    Json = 2,
    Http = 3,
    Xml = 4,
    Binary = 5,
}

impl FormatKind {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Utf8Text,
            2 => Self::Json,
            3 => Self::Http,
            4 => Self::Xml,
            5 => Self::Binary,
            _ => Self::Empty,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Utf8Text => "utf8",
            Self::Json => "json",
            Self::Http => "http",
            Self::Xml => "xml",
            Self::Binary => "binary",
        }
    }
}

/// Packed OS-native tool results. 80-byte NX0T trailer after spans/payload.
/// Present iff response header byte 46 is nonzero. Extract/Redact/Route/Entropy
/// never set that bit unless the request included FLAG_TOOLS, so existing
/// reflex clients keep working. Kit/Fingerprint/Format/Seen always emit it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ToolReport {
    pub format: FormatKind,
    pub utf8_ok: bool,
    pub utf8_errors: u16,
    pub fingerprint: u64,
    pub simhash: u64,
    pub content_id: u64,
    pub redact_hash: u64,
    pub json_depth: u16,
    pub json_keys: u16,
    pub http_body_off: u32,
    pub token_budget: u32,
    pub priority: u8,
    pub replay: bool,
    pub triggers: u32,
    pub seen_count: u32,
}

pub const TOOL_BLOCK_LEN: usize = 80;
pub const TOOL_MAGIC: &[u8; 4] = b"NX0T";

impl ToolReport {
    pub fn encode(self, out: &mut Vec<u8>) {
        let start = out.len();
        out.extend_from_slice(TOOL_MAGIC);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.push(self.format as u8);
        out.push(self.utf8_ok as u8);
        out.extend_from_slice(&self.fingerprint.to_le_bytes());
        out.extend_from_slice(&self.simhash.to_le_bytes());
        out.extend_from_slice(&self.content_id.to_le_bytes());
        out.extend_from_slice(&self.redact_hash.to_le_bytes());
        out.extend_from_slice(&self.json_depth.to_le_bytes());
        out.extend_from_slice(&self.json_keys.to_le_bytes());
        out.extend_from_slice(&self.http_body_off.to_le_bytes());
        out.extend_from_slice(&self.token_budget.to_le_bytes());
        out.extend_from_slice(&self.utf8_errors.to_le_bytes());
        out.push(self.priority);
        out.push(self.replay as u8);
        out.extend_from_slice(&self.triggers.to_le_bytes());
        out.extend_from_slice(&self.seen_count.to_le_bytes());
        out.extend_from_slice(&[0u8; 16]);
        debug_assert_eq!(out.len() - start, TOOL_BLOCK_LEN);
    }

    pub fn decode(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < TOOL_BLOCK_LEN {
            return Err("short tool block");
        }
        if &buf[0..4] != TOOL_MAGIC {
            return Err("bad tool magic");
        }
        Ok(Self {
            format: FormatKind::from_u8(buf[6]),
            utf8_ok: buf[7] != 0,
            fingerprint: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            simhash: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
            content_id: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            redact_hash: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
            json_depth: u16::from_le_bytes([buf[40], buf[41]]),
            json_keys: u16::from_le_bytes([buf[42], buf[43]]),
            http_body_off: u32::from_le_bytes(buf[44..48].try_into().unwrap()),
            token_budget: u32::from_le_bytes(buf[48..52].try_into().unwrap()),
            utf8_errors: u16::from_le_bytes([buf[52], buf[53]]),
            priority: buf[54],
            replay: buf[55] != 0,
            triggers: u32::from_le_bytes(buf[56..60].try_into().unwrap()),
            seen_count: u32::from_le_bytes(buf[60..64].try_into().unwrap()),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Response {
    pub status: u8,
    pub opcode: Opcode,
    pub seq: u64,
    pub latency_ns: u64,
    pub malicious: f32,
    pub pii: f32,
    pub entropy: f32,
    pub ai_marker: f32,
    pub route: RouteAction,
    pub spans: Vec<Span>,
    pub payload: Option<Vec<u8>>,
    pub tools: Option<ToolReport>,
}

pub const STATUS_OK: u8 = 0;
pub const STATUS_DROPPED: u8 = 1;
pub const STATUS_QUARANTINE: u8 = 2;
pub const STATUS_ERROR: u8 = 3;

/// Request header is 20 bytes: magic(4) + ver(1) + opcode(1) + flags(2) + seq(8) + len(4).
pub const REQUEST_HEADER_LEN: usize = 20;
/// Response header before spans/payload: 48 bytes.
pub const RESPONSE_HEADER_LEN: usize = 48;
pub const SPAN_WIRE_LEN: usize = 12;

pub fn encode_request(req: &Request, out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&MAGIC);
    out.push(PROTOCOL_VERSION);
    out.push(req.opcode as u8);
    out.extend_from_slice(&req.flags.to_le_bytes());
    out.extend_from_slice(&req.seq.to_le_bytes());
    out.extend_from_slice(&(req.payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&req.payload);
}

pub fn decode_request_header(buf: &[u8]) -> Result<(Opcode, u16, u64, u32), &'static str> {
    if buf.len() < REQUEST_HEADER_LEN {
        return Err("short request header");
    }
    if buf[0..4] != MAGIC {
        return Err("bad magic");
    }
    if buf[4] != PROTOCOL_VERSION {
        return Err("unsupported version");
    }
    let opcode = Opcode::from_u8(buf[5]).ok_or("unknown opcode")?;
    let flags = u16::from_le_bytes([buf[6], buf[7]]);
    let seq = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let len = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    Ok((opcode, flags, seq, len))
}

pub fn encode_response(resp: &Response, out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(b"NX0R");
    out.push(resp.status);
    out.push(resp.opcode as u8);
    out.extend_from_slice(&resp.seq.to_le_bytes());
    out.extend_from_slice(&resp.latency_ns.to_le_bytes());
    out.extend_from_slice(&resp.malicious.to_le_bytes());
    out.extend_from_slice(&resp.pii.to_le_bytes());
    out.extend_from_slice(&resp.entropy.to_le_bytes());
    out.extend_from_slice(&resp.ai_marker.to_le_bytes());
    out.push(resp.route as u8);
    out.push(0);
    out.extend_from_slice(&(resp.spans.len() as u16).to_le_bytes());
    let plen = resp.payload.as_ref().map(|p| p.len()).unwrap_or(0) as u32;
    out.extend_from_slice(&plen.to_le_bytes());
    let has_tools = resp.tools.is_some();
    out.extend_from_slice(&[u8::from(has_tools), 0]);
    debug_assert_eq!(out.len(), RESPONSE_HEADER_LEN);
    for span in &resp.spans {
        out.extend_from_slice(&span.start.to_le_bytes());
        out.extend_from_slice(&span.end.to_le_bytes());
        out.push(span.kind as u8);
        out.extend_from_slice(&[0, 0, 0]);
    }
    if let Some(payload) = &resp.payload {
        out.extend_from_slice(payload);
    }
    if let Some(tools) = resp.tools {
        tools.encode(out);
    }
}

pub fn decode_response(buf: &[u8]) -> Result<Response, &'static str> {
    if buf.len() < RESPONSE_HEADER_LEN {
        return Err("short response");
    }
    if &buf[0..4] != b"NX0R" {
        return Err("bad response magic");
    }
    let status = buf[4];
    let opcode = Opcode::from_u8(buf[5]).ok_or("unknown opcode")?;
    let seq = u64::from_le_bytes(buf[6..14].try_into().unwrap());
    let latency_ns = u64::from_le_bytes(buf[14..22].try_into().unwrap());
    let malicious = f32::from_le_bytes(buf[22..26].try_into().unwrap());
    let pii = f32::from_le_bytes(buf[26..30].try_into().unwrap());
    let entropy = f32::from_le_bytes(buf[30..34].try_into().unwrap());
    let ai_marker = f32::from_le_bytes(buf[34..38].try_into().unwrap());
    let route = RouteAction::from_u8(buf[38]);
    let span_count = u16::from_le_bytes([buf[40], buf[41]]) as usize;
    let plen = u32::from_le_bytes(buf[42..46].try_into().unwrap()) as usize;
    let mut off = RESPONSE_HEADER_LEN;
    let need = off
        .checked_add(span_count.checked_mul(SPAN_WIRE_LEN).ok_or("overflow")?)
        .and_then(|v| v.checked_add(plen))
        .ok_or("overflow")?;
    if buf.len() < need {
        return Err("truncated response body");
    }
    let mut spans = Vec::with_capacity(span_count);
    for _ in 0..span_count {
        let start = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        let end = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap());
        let kind = EntityKind::from_u8(buf[off + 8]).ok_or("bad span kind")?;
        spans.push(Span { start, end, kind });
        off += SPAN_WIRE_LEN;
    }
    let payload = if plen > 0 {
        Some(buf[off..off + plen].to_vec())
    } else {
        None
    };
    off += plen;
    let tools = if buf[46] != 0 {
        if buf.len() < off + TOOL_BLOCK_LEN {
            return Err("truncated tool block");
        }
        Some(ToolReport::decode(&buf[off..off + TOOL_BLOCK_LEN])?)
    } else {
        None
    };
    Ok(Response {
        status,
        opcode,
        seq,
        latency_ns,
        malicious,
        pii,
        entropy,
        ai_marker,
        route,
        spans,
        payload,
        tools,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip_header() {
        let req = Request {
            opcode: Opcode::Reflex,
            flags: FLAG_RETURN_SPANS | FLAG_APPLY_REDACT,
            seq: 42,
            payload: b"hello".to_vec(),
        };
        let mut buf = Vec::new();
        encode_request(&req, &mut buf);
        let (op, flags, seq, len) = decode_request_header(&buf).unwrap();
        assert_eq!(op, Opcode::Reflex);
        assert_eq!(flags, FLAG_RETURN_SPANS | FLAG_APPLY_REDACT);
        assert_eq!(seq, 42);
        assert_eq!(len, 5);
        assert_eq!(&buf[REQUEST_HEADER_LEN..], b"hello");
        assert_eq!(
            buf,
            [
                b'N', b'X', b'0', 0, 1, 0x05, 0x03, 0x00, 0x2a, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0,
                b'h', b'e', b'l', b'l', b'o',
            ]
        );
    }

    #[test]
    fn response_roundtrip() {
        let resp = Response {
            status: STATUS_OK,
            opcode: Opcode::Extract,
            seq: 7,
            latency_ns: 1234,
            malicious: 0.1,
            pii: 0.8,
            entropy: 4.2,
            ai_marker: 0.3,
            route: RouteAction::Accept,
            spans: vec![Span {
                start: 2,
                end: 10,
                kind: EntityKind::Email,
            }],
            payload: Some(b"abc".to_vec()),
            tools: None,
        };
        let mut buf = Vec::new();
        encode_response(&resp, &mut buf);
        let back = decode_response(&buf).unwrap();
        assert_eq!(back.seq, 7);
        assert_eq!(back.spans.len(), 1);
        assert_eq!(back.spans[0].kind, EntityKind::Email);
        assert_eq!(back.payload.as_deref(), Some(&b"abc"[..]));
        assert!((back.pii - 0.8).abs() < 1e-6);
    }

    #[test]
    fn tool_block_roundtrip() {
        let tools = ToolReport {
            format: FormatKind::Json,
            utf8_ok: true,
            utf8_errors: 0,
            fingerprint: 0x1111,
            simhash: 0x2222,
            content_id: 0x3333,
            redact_hash: 0x4444,
            json_depth: 2,
            json_keys: 3,
            http_body_off: 0,
            token_budget: 8,
            priority: 1,
            replay: true,
            triggers: 4,
            seen_count: 9,
        };
        let resp = Response {
            status: STATUS_OK,
            opcode: Opcode::Kit,
            seq: 1,
            latency_ns: 10,
            malicious: 0.0,
            pii: 0.0,
            entropy: 1.0,
            ai_marker: 0.0,
            route: RouteAction::Accept,
            spans: vec![],
            payload: None,
            tools: Some(tools),
        };
        let mut buf = Vec::new();
        encode_response(&resp, &mut buf);
        assert_eq!(buf[46], 1);
        let back = decode_response(&buf).unwrap();
        assert_eq!(back.tools.unwrap().fingerprint, 0x1111);
        assert!(back.tools.unwrap().replay);
    }

    #[test]
    fn rejects_bad_magic_and_opcode() {
        let mut buf = vec![0u8; REQUEST_HEADER_LEN];
        assert_eq!(decode_request_header(&buf).unwrap_err(), "bad magic");
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4] = PROTOCOL_VERSION;
        buf[5] = 0x99;
        assert_eq!(decode_request_header(&buf).unwrap_err(), "unknown opcode");
        assert!(decode_response(&[0u8; 10]).is_err());
    }
}
