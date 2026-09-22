#!/usr/bin/env python3
"""Amiga Workbench-inspired framebuffer monitor for NEXUS-0.

Reads the packed telemetry block and event ticker written by the Rust core.
Does not sit on the request path.

    pip install -r ui/requirements.txt
    python ui/monitor.py
"""

from __future__ import annotations

import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from protocol import (  # noqa: E402
    ROUTE_NAMES,
    default_events_path,
    default_stats_path,
    load_telemetry,
    tail_events,
)

try:
    import pygame
except ImportError:
    sys.stderr.write("pygame is required:  pip install pygame\n")
    sys.exit(1)

# Classic WB 3.1-ish palette
BLUE = (0, 85, 170)
BLUE_DARK = (0, 34, 85)
ORANGE = (255, 136, 0)
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)
GRAY = (186, 186, 186)
SHADOW = (0, 0, 68)
GREEN = (0, 204, 85)
RED = (220, 40, 40)
YELLOW = (240, 200, 40)

W, H = 960, 640
TITLE = "NEXUS-0  //  REFLEX MONITOR"


def main() -> int:
    stats_path = os.environ.get("NEXUS0_STATS", default_stats_path())
    events_path = os.environ.get("NEXUS0_EVENTS", default_events_path())

    pygame.init()
    pygame.display.set_caption(TITLE)
    screen = pygame.display.set_mode((W, H))
    clock = pygame.time.Clock()
    font = _font(16)
    small = _font(14)
    tiny = _font(12)
    title_font = _font(18)

    running = True
    while running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
            elif event.type == pygame.KEYDOWN and event.key in (pygame.K_ESCAPE, pygame.K_q):
                running = False

        snap = load_telemetry(stats_path)
        events = tail_events(events_path, 12)

        screen.fill(BLUE)
        _top_bar(screen, title_font, small, snap)
        _window(
            screen,
            16,
            44,
            600,
            250,
            "LATENCY / THROUGHPUT",
            font,
        )
        _latency_panel(screen, 28, 70, 576, 210, snap, small, tiny)

        _window(screen, 628, 44, 316, 250, "ROUTER", font)
        _router_panel(screen, 640, 70, 292, 210, snap, small)

        _window(screen, 16, 306, 928, 150, "MEMORY  ·  SPANS  ·  ENTROPY", font)
        _memory_panel(screen, 28, 332, 904, 110, snap, small, tiny)

        _window(screen, 16, 468, 928, 156, "EVENT TICKER", font)
        _events_panel(screen, 28, 494, 904, 118, events, snap, tiny)

        pygame.display.flip()
        clock.tick(20)

    pygame.quit()
    return 0


def _font(size: int):
    for name in ("Topaz", "Courier New", "Consolas", "DejaVu Sans Mono", "monospace"):
        path = pygame.font.match_font(name)
        if path:
            return pygame.font.Font(path, size)
    return pygame.font.Font(None, size)


def _top_bar(screen, title_font, small, snap) -> None:
    pygame.draw.rect(screen, GRAY, (0, 0, W, 32))
    pygame.draw.rect(screen, WHITE, (0, 0, W, 32), 1)
    screen.blit(title_font.render(TITLE, True, BLACK), (10, 6))
    led = GREEN if snap.connected else RED
    pygame.draw.circle(screen, led, (W - 22, 16), 7)
    pygame.draw.circle(screen, BLACK, (W - 22, 16), 7, 1)
    status = "CORE ONLINE" if snap.connected else "AWAITING ENGINE CORE"
    screen.blit(small.render(status, True, BLACK), (W - 240, 8))
    clock = time.strftime("%H:%M:%S")
    screen.blit(small.render(clock, True, BLACK), (420, 8))


def _window(screen, x, y, w, h, title, font) -> None:
    pygame.draw.rect(screen, BLACK, (x + 3, y + 3, w, h))
    pygame.draw.rect(screen, GRAY, (x, y, w, h))
    pygame.draw.rect(screen, WHITE, (x, y, w, h), 1)
    pygame.draw.rect(screen, ORANGE, (x + 3, y + 3, w - 6, 20))
    pygame.draw.rect(screen, BLACK, (x + 3, y + 3, w - 6, 20), 1)
    screen.blit(font.render(title, True, BLACK), (x + 10, y + 4))
    pygame.draw.rect(screen, BLUE_DARK, (x + 3, y + 24, w - 6, h - 27))


def _latency_panel(screen, x, y, w, h, snap, small, tiny) -> None:
    ema_us = snap.ema_latency_ns / 1000.0
    last_us = snap.last_latency_ns / 1000.0
    min_us = snap.min_latency_ns / 1000.0
    max_us = snap.max_latency_ns / 1000.0
    lines = [
        f"requests     {snap.requests_total}",
        f"last         {last_us:.1f} us",
        f"ema          {ema_us:.1f} us",
        f"min / max    {min_us:.1f} / {max_us:.1f} us",
        f"in / out     {snap.bytes_in} / {snap.bytes_out} B",
        f"publish      {snap.last_publish_ns / 1000.0:.1f} us",
    ]
    for i, line in enumerate(lines):
        screen.blit(small.render(line, True, WHITE), (x, y + i * 18))

    hx, hy, hw, hh = x + 250, y + 8, w - 260, h - 24
    pygame.draw.rect(screen, SHADOW, (hx, hy, hw, hh))
    pygame.draw.rect(screen, WHITE, (hx, hy, hw, hh), 1)
    peak = max(snap.histogram) if snap.histogram and max(snap.histogram) > 0 else 1
    bw = max(2, (hw - 20) // 16)
    for i, count in enumerate(snap.histogram):
        bh = int((count / peak) * (hh - 28))
        bx = hx + 8 + i * bw
        by = hy + hh - 16 - bh
        color = ORANGE if i < 10 else YELLOW if i < 13 else RED
        pygame.draw.rect(screen, color, (bx, by, bw - 3, max(bh, 1)))
    screen.blit(tiny.render("1us        latency buckets        >=16ms", True, GRAY), (hx + 8, hy + hh - 14))


def _router_panel(screen, x, y, w, h, snap, small) -> None:
    route = ROUTE_NAMES.get(snap.last_route, "—")
    color = {"ACCEPT": GREEN, "QUARANTINE": YELLOW, "DROP": RED}.get(route, GRAY)
    pygame.draw.rect(screen, color, (x, y, w, 36))
    pygame.draw.rect(screen, BLACK, (x, y, w, 36), 1)
    screen.blit(small.render(f"LAST ROUTE  {route}", True, BLACK), (x + 10, y + 10))

    rows = [
        ("ACCEPT", snap.requests_total - snap.dropped - snap.quarantine, GREEN),
        ("QUARANTINE", snap.quarantine, YELLOW),
        ("DROP", snap.dropped, RED),
        ("FDs / CONN", snap.active_conns, WHITE),
        ("PROTO ERR", snap.protocol_errors, RED),
    ]
    for i, (label, value, col) in enumerate(rows):
        yy = y + 48 + i * 22
        pygame.draw.rect(screen, col, (x, yy + 6, 10, 10))
        screen.blit(small.render(f"{label:<12} {value}", True, WHITE), (x + 20, yy))

    _ = h  # layout reserved


def _memory_panel(screen, x, y, w, h, snap, small, tiny) -> None:
    _ = (w, h)
    metrics = [
        ("PII spans", snap.pii_spans, ORANGE),
        ("extract spans", snap.extract_spans, WHITE),
        ("bytes redacted", snap.bytes_redacted, YELLOW),
        ("AI flags", snap.entropy_flags, RED),
    ]
    col_w = 220
    for i, (label, value, col) in enumerate(metrics):
        cx = x + i * col_w
        screen.blit(small.render(label.upper(), True, GRAY), (cx, y))
        screen.blit(small.render(str(value), True, col), (cx, y + 20))

    screen.blit(small.render("SCORE  mal / pii / H / ai", True, GRAY), (x, y + 52))
    _bar(screen, x, y + 74, 200, 14, snap.last_malicious, RED, tiny, "MAL")
    _bar(screen, x + 220, y + 74, 200, 14, snap.last_pii, ORANGE, tiny, "PII")
    ent = min(snap.last_entropy / 8.0, 1.0)
    _bar(screen, x + 440, y + 74, 200, 14, ent, WHITE, tiny, "H")
    _bar(screen, x + 660, y + 74, 200, 14, snap.last_ai, YELLOW, tiny, "AI")


def _bar(screen, x, y, w, h, frac, color, tiny, label) -> None:
    frac = max(0.0, min(1.0, float(frac)))
    pygame.draw.rect(screen, SHADOW, (x, y, w, h))
    pygame.draw.rect(screen, color, (x, y, int(w * frac), h))
    pygame.draw.rect(screen, WHITE, (x, y, w, h), 1)
    screen.blit(tiny.render(f"{label} {frac:.2f}", True, WHITE), (x + 4, y - 14))


def _events_panel(screen, x, y, w, h, events, snap, tiny) -> None:
    _ = (w, h, snap)
    if not events:
        msg = "AWAITING ENGINE CORE  —  cargo run --release && python ui/monitor.py"
        screen.blit(tiny.render(msg, True, GRAY), (x, y + 8))
        return
    for i, line in enumerate(events[-10:]):
        screen.blit(tiny.render(line[:110], True, WHITE), (x, y + i * 11))


if __name__ == "__main__":
    raise SystemExit(main())
