#!/usr/bin/env python3
"""Golden bytes shared with src/schema.rs and tests/protocol_golden.rs.

Standalone: checks the request vector and a response round-trip.
With two paths: those files are the Rust encoder output and must match.
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from protocol import (  # noqa: E402
    FLAG_APPLY_REDACT,
    FLAG_RETURN_SPANS,
    OPCODE_EXTRACT,
    OPCODE_REFLEX,
    decode_response,
    encode_request,
    encode_response,
)

REQUEST = bytes.fromhex("4e583000010503002a000000000000000500000068656c6c6f")


def golden_response() -> bytes:
    return encode_response(
        0,
        OPCODE_EXTRACT,
        7,
        1234,
        0.5,
        0.25,
        4.0,
        0.5,
        0,
        [(2, 10, 1)],
        b"abc",
        False,
    )


def main() -> int:
    req = encode_request(
        OPCODE_REFLEX,
        b"hello",
        flags=FLAG_RETURN_SPANS | FLAG_APPLY_REDACT,
        seq=42,
    )
    if req != REQUEST:
        sys.stderr.write(f"request bytes drifted: {req.hex()}\n")
        return 1

    resp = golden_response()
    back = decode_response(resp)
    if back.seq != 7 or back.opcode != OPCODE_EXTRACT:
        sys.stderr.write("response round-trip lost the header\n")
        return 1
    if not back.spans or back.spans[0].start != 2 or back.spans[0].kind != 1:
        sys.stderr.write("response round-trip lost the span\n")
        return 1
    if back.payload != b"abc":
        sys.stderr.write("response round-trip lost the payload\n")
        return 1

    if len(sys.argv) == 3:
        with open(sys.argv[1], "rb") as handle:
            rust_req = handle.read()
        with open(sys.argv[2], "rb") as handle:
            rust_resp = handle.read()
        if rust_req != req:
            sys.stderr.write("Rust request encoder does not match protocol.py\n")
            return 1
        if rust_resp != resp:
            sys.stderr.write(
                "Rust response encoder does not match protocol.py\n"
                f"rust {rust_resp.hex()}\n"
                f"py   {resp.hex()}\n"
            )
            return 1

    print("protocol golden ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
