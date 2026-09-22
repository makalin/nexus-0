"""Shared NX0 wire helpers for the dashboard and Python examples."""

from __future__ import annotations

import os
import struct
import sys
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

MAGIC = b"NX0\0"
RESP_MAGIC = b"NX0R"
STATS_MAGIC = b"NX0S"
PROTOCOL_VERSION = 1

OPCODE_EXTRACT = 0x01
OPCODE_REDACT = 0x02
OPCODE_ROUTE = 0x03
OPCODE_ENTROPY = 0x04
OPCODE_REFLEX = 0x05
OPCODE_KIT = 0x06
OPCODE_FINGERPRINT = 0x07
OPCODE_FORMAT = 0x08
OPCODE_SEEN = 0x09

FLAG_RETURN_SPANS = 0x0001
FLAG_APPLY_REDACT = 0x0002
FLAG_DROP_IF_MALICIOUS = 0x0004
FLAG_ECHO_PAYLOAD = 0x0008
FLAG_TOOLS = 0x0010
FLAG_DROP_REPLAY = 0x0020

REQUEST_HEADER_LEN = 20
RESPONSE_HEADER_LEN = 48
SPAN_WIRE_LEN = 12
TOOL_BLOCK_LEN = 80
TELEMETRY_BYTES = 256
TOOL_MAGIC = b"NX0T"

FORMAT_NAMES = {0: "empty", 1: "utf8", 2: "json", 3: "http", 4: "xml", 5: "binary"}

KIND_NAMES = {
    1: "email",
    2: "phone",
    3: "ipv4",
    4: "credit_card",
    5: "jwt",
    6: "api_key",
    7: "ssn",
    8: "bearer",
}

ROUTE_NAMES = {0: "ACCEPT", 1: "QUARANTINE", 2: "DROP"}


def runtime_dir() -> str:
    """Match `nexus0::config::default_runtime_dir`."""
    base = tempfile.gettempdir()
    if os.name == "nt":
        return os.path.join(base, "nexus0")
    return os.path.join(base, f"nexus0-{os.getuid()}")


def default_bind() -> str:
    env = os.environ.get("NEXUS0_BIND")
    if env:
        return env
    if os.name == "nt":
        return "127.0.0.1:9800"
    return os.path.join(runtime_dir(), "nexus0.sock")


def default_stats_path() -> str:
    env = os.environ.get("NEXUS0_STATS")
    if env:
        return env
    return os.path.join(runtime_dir(), "nexus0.stats")


def default_events_path() -> str:
    env = os.environ.get("NEXUS0_EVENTS")
    if env:
        return env
    return os.path.join(runtime_dir(), "nexus0.events")


def encode_response(
    status: int,
    opcode: int,
    seq: int,
    latency_ns: int,
    malicious: float,
    pii: float,
    entropy: float,
    ai_marker: float,
    route: int,
    spans: list,
    payload: bytes | None = None,
    has_tools: bool = False,
) -> bytes:
    body = payload or b""
    header = struct.pack(
        "<4sBBQQ4fBBHI2s",
        RESP_MAGIC,
        status,
        opcode,
        seq,
        latency_ns,
        malicious,
        pii,
        entropy,
        ai_marker,
        route,
        0,
        len(spans),
        len(body),
        bytes([1 if has_tools else 0, 0]),
    )
    encoded = bytearray(header)
    for start, end, kind in spans:
        encoded += struct.pack("<IIB3s", start, end, kind, b"\0\0\0")
    encoded += body
    return bytes(encoded)


def encode_request(opcode: int, payload: bytes, flags: int = 0, seq: int = 0) -> bytes:
    header = struct.pack(
        "<4sBBHQI",
        MAGIC,
        PROTOCOL_VERSION,
        opcode,
        flags,
        seq,
        len(payload),
    )
    return header + payload


@dataclass
class Span:
    start: int
    end: int
    kind: int

    @property
    def name(self) -> str:
        return KIND_NAMES.get(self.kind, f"kind:{self.kind}")


@dataclass
class Response:
    status: int
    opcode: int
    seq: int
    latency_ns: int
    malicious: float
    pii: float
    entropy: float
    ai_marker: float
    route: int
    spans: List[Span] = field(default_factory=list)
    payload: Optional[bytes] = None
    tools: Optional["ToolReport"] = None

    @property
    def route_name(self) -> str:
        return ROUTE_NAMES.get(self.route, "?")


@dataclass
class ToolReport:
    format: int = 0
    utf8_ok: bool = False
    utf8_errors: int = 0
    fingerprint: int = 0
    simhash: int = 0
    content_id: int = 0
    redact_hash: int = 0
    json_depth: int = 0
    json_keys: int = 0
    http_body_off: int = 0
    token_budget: int = 0
    priority: int = 0
    replay: bool = False
    triggers: int = 0
    seen_count: int = 0

    @property
    def format_name(self) -> str:
        return FORMAT_NAMES.get(self.format, "?")


def decode_tools(buf: bytes, off: int) -> ToolReport:
    magic, _ver, fmt, utf8_ok, fp, sim, cid, rh, depth, keys, body, budget, err, pri, replay, trig, seen = struct.unpack_from(
        "<4sHBBQQQQHHIIHBBII", buf, off
    )
    if magic != TOOL_MAGIC:
        raise ValueError("bad tool magic")
    return ToolReport(
        format=fmt,
        utf8_ok=bool(utf8_ok),
        utf8_errors=err,
        fingerprint=fp,
        simhash=sim,
        content_id=cid,
        redact_hash=rh,
        json_depth=depth,
        json_keys=keys,
        http_body_off=body,
        token_budget=budget,
        priority=pri,
        replay=bool(replay),
        triggers=trig,
        seen_count=seen,
    )


def decode_response(buf: bytes) -> Response:
    if len(buf) < RESPONSE_HEADER_LEN:
        raise ValueError("short response")
    magic, status, opcode, seq, latency, mal, pii, entropy, ai, route, _pad, span_count, plen, pad2 = struct.unpack_from(
        "<4sBBQQ4fBBHI2s", buf, 0
    )
    if magic != RESP_MAGIC:
        raise ValueError("bad response magic")
    off = RESPONSE_HEADER_LEN
    spans = []
    for _ in range(span_count):
        start, end, kind, _p = struct.unpack_from("<IIB3s", buf, off)
        spans.append(Span(start, end, kind))
        off += SPAN_WIRE_LEN
    payload = buf[off : off + plen] if plen else None
    off += plen
    tools = None
    if pad2[:1] != b"\x00":
        if len(buf) < off + TOOL_BLOCK_LEN:
            raise ValueError("truncated tool block")
        tools = decode_tools(buf, off)
    return Response(
        status=status,
        opcode=opcode,
        seq=seq,
        latency_ns=latency,
        malicious=mal,
        pii=pii,
        entropy=entropy,
        ai_marker=ai,
        route=route,
        spans=spans,
        payload=payload,
        tools=tools,
    )


def read_framed_response(sock) -> Response:
    header = _recv_exact(sock, RESPONSE_HEADER_LEN)
    span_count = struct.unpack_from("<H", header, 40)[0]
    plen = struct.unpack_from("<I", header, 42)[0]
    extra = span_count * SPAN_WIRE_LEN + plen
    if header[46] != 0:
        extra += TOOL_BLOCK_LEN
    body = _recv_exact(sock, extra) if extra else b""
    return decode_response(header + body)


def _recv_exact(sock, n: int) -> bytes:
    chunks = []
    got = 0
    while got < n:
        chunk = sock.recv(n - got)
        if not chunk:
            raise ConnectionError("socket closed")
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


@dataclass
class Telemetry:
    connected: bool = False
    seq: int = 0
    requests_total: int = 0
    dropped: int = 0
    quarantine: int = 0
    pii_spans: int = 0
    extract_spans: int = 0
    entropy_flags: int = 0
    last_latency_ns: int = 0
    ema_latency_ns: int = 0
    min_latency_ns: int = 0
    max_latency_ns: int = 0
    last_malicious: float = 0.0
    last_pii: float = 0.0
    last_entropy: float = 0.0
    last_ai: float = 0.0
    bytes_in: int = 0
    bytes_out: int = 0
    active_conns: int = 0
    last_route: int = 0
    histogram: Tuple[int, ...] = tuple([0] * 16)
    bytes_redacted: int = 0
    uptime_ms: int = 0
    protocol_errors: int = 0
    last_publish_ns: int = 0


def load_telemetry(path: str) -> Telemetry:
    snap = Telemetry()
    try:
        with open(path, "rb") as f:
            buf = f.read(TELEMETRY_BYTES)
    except OSError:
        return snap
    if len(buf) < 216 or buf[0:4] != STATS_MAGIC:
        return snap
    snap.connected = True
    snap.seq = _u64(buf, 8)
    snap.requests_total = _u64(buf, 16)
    snap.dropped = _u64(buf, 24)
    snap.quarantine = _u64(buf, 32)
    snap.pii_spans = _u64(buf, 40)
    snap.extract_spans = _u64(buf, 48)
    snap.entropy_flags = _u64(buf, 56)
    snap.last_latency_ns = _u64(buf, 64)
    snap.ema_latency_ns = _u64(buf, 72)
    snap.min_latency_ns = _u64(buf, 80)
    snap.max_latency_ns = _u64(buf, 88)
    snap.last_malicious = _f32(buf, 96)
    snap.last_pii = _f32(buf, 100)
    snap.last_entropy = _f32(buf, 104)
    snap.last_ai = _f32(buf, 108)
    snap.bytes_in = _u64(buf, 112)
    snap.bytes_out = _u64(buf, 120)
    snap.active_conns = _u32(buf, 128)
    snap.last_route = _u32(buf, 132)
    snap.histogram = tuple(_u32(buf, 136 + i * 4) for i in range(16))
    snap.bytes_redacted = _u64(buf, 200)
    snap.uptime_ms = _u64(buf, 208)
    if len(buf) >= 224:
        snap.protocol_errors = _u64(buf, 216)
    if len(buf) >= 232:
        snap.last_publish_ns = _u64(buf, 224)
    return snap


def tail_events(path: str, limit: int = 14) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        return lines[-limit:]
    except OSError:
        return []


def connect_stream(bind: str):
    if ":" in bind and not bind.startswith("/"):
        host, port_s = bind.rsplit(":", 1)
        import socket

        sock = socket.create_connection((host, int(port_s)), timeout=3)
        return sock
    if sys.platform == "win32":
        raise RuntimeError("Unix sockets are not used on Windows; pass host:port")
    import socket

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect(bind)
    return sock


def _u64(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _f32(buf: bytes, off: int) -> float:
    return struct.unpack_from("<f", buf, off)[0]


if __name__ == "__main__":
    assert struct.calcsize("<4sBBHQI") == REQUEST_HEADER_LEN
    assert struct.calcsize("<4sBBQQ4fBBHI2s") == RESPONSE_HEADER_LEN
    assert struct.calcsize("<4sHBBQQQQHHIIHBBII") == 64
    print("protocol sizes ok")

