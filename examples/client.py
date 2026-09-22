#!/usr/bin/env python3
"""Python IPC client for a running NEXUS-0 core.

    cargo run --release
    python examples/client.py
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "ui"))

from protocol import (  # noqa: E402
    FLAG_APPLY_REDACT,
    FLAG_DROP_IF_MALICIOUS,
    FLAG_RETURN_SPANS,
    OPCODE_ENTROPY,
    OPCODE_EXTRACT,
    OPCODE_REDACT,
    OPCODE_REFLEX,
    OPCODE_ROUTE,
    connect_stream,
    default_bind,
    encode_request,
    read_framed_response,
)


def reflex(bind: str, opcode: int, payload: bytes):
    flags = FLAG_RETURN_SPANS | FLAG_APPLY_REDACT | FLAG_DROP_IF_MALICIOUS
    sock = connect_stream(bind)
    try:
        sock.sendall(encode_request(opcode, payload, flags=flags, seq=0))
        return read_framed_response(sock)
    finally:
        sock.close()


def main() -> int:
    bind = default_bind()
    print(f"connecting to {bind}")
    samples = [
        ("benign", OPCODE_REFLEX, b"ROUTING_REQ: User access token validation needed."),
        ("extract", OPCODE_EXTRACT, b"notify ada@nexus.dev from 10.0.0.8"),
        ("redact", OPCODE_REDACT, b"charge 4111111111111111 and mail jane.doe@example.com"),
        ("route", OPCODE_ROUTE, b"admin' OR 1=1-- union select ../etc/passwd"),
        ("entropy", OPCODE_ENTROPY, b"The system will now proceed to evaluate the incoming payload."),
    ]
    try:
        for label, opcode, payload in samples:
            resp = reflex(bind, opcode, payload)
            print(f"--- {label} ---")
            print(
                f"  route={resp.route_name} latency={resp.latency_ns/1000:.1f}us "
                f"mal={resp.malicious:.3f} pii={resp.pii:.3f} H={resp.entropy:.2f} ai={resp.ai_marker:.3f}"
            )
            for span in resp.spans:
                frag = payload[span.start : span.end]
                print(f"  span {span.start}..{span.end} {span.name} {frag!r}")
            if resp.payload is not None:
                try:
                    print(f"  payload: {resp.payload.decode('utf-8')}")
                except UnicodeDecodeError:
                    print(f"  payload: {resp.payload!r}")
    except OSError as exc:
        print(f"failed: {exc}", file=sys.stderr)
        print("start the core first:  cargo run --release", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
