#!/usr/bin/env python3
# traffic_gen.py
# Generate baseline "normal" traffic for model training, and out-of-norm spikes for testing.
# Now supports running indefinitely with --until-ctrl-c on any subcommand.

import argparse
import asyncio
import contextlib
import random
import socket
import string
import time
import threading
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from typing import Tuple, List

# ---------------------------
# Helpers (no external deps)
# ---------------------------


def _rand_user_agent() -> str:
    bases = [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "curl/8.4.0",
        "Wget/1.21.4",
    ]
    return random.choice(bases)


def _tcp_connect_and_http_get(host: str, port: int, path="/", timeout=1.5) -> None:
    """Small TCP GET to host:port (works with our local test server or real sites)."""
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.settimeout(timeout)
        s.connect((host, port))
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {_rand_user_agent()}\r\n"
            "Connection: close\r\n\r\n"
        )
        s.sendall(req.encode("ascii", "ignore"))
        with contextlib.suppress(TimeoutError, socket.timeout, OSError):
            s.recv(1024)


def _tcp_connect_only(host: str, port: int, timeout=0.4) -> None:
    """Bare TCP connect; close immediately. Good for scans and lightweight probes."""
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.settimeout(timeout)
        with contextlib.suppress(Exception):
            s.connect((host, port))


def _udp_fire_and_forget(host: str, port: int, payload: bytes) -> None:
    """Transmit a UDP datagram; do not wait for replies."""
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
        s.settimeout(0.5)
        s.sendto(payload, (host, port))


def _build_dns_query(qname: str, qtype: int = 1) -> bytes:
    """Minimal DNS query packet (A=1)."""

    def labels(name: str) -> bytes:
        out = b""
        for label in name.strip(".").split("."):
            lb = label.encode("ascii", "ignore")
            out += bytes([len(lb)]) + lb
        return out + b"\x00"

    txid = random.randint(0, 0xFFFF)
    header = (
        txid.to_bytes(2, "big")
        + b"\x01\x00"
        + b"\x00\x01"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
    )
    q = labels(qname) + qtype.to_bytes(2, "big") + b"\x00\x01"
    return header + q


def _random_payload(n: int = 48) -> bytes:
    return "".join(random.choice(string.ascii_letters) for _ in range(n)).encode()


# ---------------------------------
# Local HTTP server (baseline only)
# ---------------------------------


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence console
        pass


def start_local_http_server(
    host="127.0.0.1", port=8080
) -> Tuple[TCPServer, threading.Thread]:
    server = TCPServer((host, port), _QuietHandler)
    th = threading.Thread(target=server.serve_forever, daemon=True, name="local-http")
    th.start()
    return server, th


# ---------------------------
# Async traffic generators
# ---------------------------


async def _normal_mix(
    duration_s: int | None,
    local_only: bool,
    http_host_port=("127.0.0.1", 8080),
    ext_http_hosts: List[Tuple[str, int]] | None = None,
    dns_target=("127.0.0.1", 53),
    ntp_target=("127.0.0.1", 123),
    pps: int = 20,
) -> None:
    """
    Generate a benign blend of traffic:
      - HTTP GETs to a local server (default) or selected externals (optional)
      - DNS queries (UDP 53)
      - NTP-like small UDP (123)
      - Occasional HTTPS TCP connects (443)

    If duration_s is None, runs indefinitely until Ctrl+C.
    """
    if ext_http_hosts is None:
        ext_http_hosts = [("example.com", 80), ("example.com", 443)]

    t_end = None if duration_s is None else (time.time() + duration_s)
    period = 1.0 / max(1, pps)

    def _time_ok() -> bool:
        return True if t_end is None else (time.time() < t_end)

    while _time_ok():
        tasks = []
        # HTTP
        if local_only:
            tasks.append(
                asyncio.to_thread(
                    _tcp_connect_and_http_get, http_host_port[0], http_host_port[1], "/"
                )
            )
        else:
            host, port = random.choice(ext_http_hosts)
            tasks.append(asyncio.to_thread(_tcp_connect_and_http_get, host, port, "/"))

        # DNS (UDP 53)
        q = random.choice(
            ["example.com", "openai.com", "cloudflare.com", "wikipedia.org"]
        )
        tasks.append(
            asyncio.to_thread(
                _udp_fire_and_forget, dns_target[0], dns_target[1], _build_dns_query(q)
            )
        )

        # NTP-like (UDP 123)
        tasks.append(
            asyncio.to_thread(
                _udp_fire_and_forget, ntp_target[0], ntp_target[1], _random_payload(48)
            )
        )

        # Occasional HTTPS TCP connect
        if not local_only and random.random() < 0.3:
            tasks.append(asyncio.to_thread(_tcp_connect_only, "1.1.1.1", 443))

        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.sleep(period * random.uniform(0.7, 1.3))


async def _portscan(
    target: str, start_port: int, end_port: int, rate: int = 200
) -> None:
    """Quick port scan burst (TCP connect) across a range, at approx `rate`/sec."""
    ports = list(range(start_port, end_port + 1))
    random.shuffle(ports)
    sem = asyncio.Semaphore(200)

    async def do_connect(p: int):
        async with sem:
            await asyncio.to_thread(_tcp_connect_only, target, p)

    for p in ports:
        asyncio.create_task(do_connect(p))
        await asyncio.sleep(1.0 / max(1, rate))
    # wait for in-flight tasks to finish
    await asyncio.sleep(0.25)


async def _udp_burst(
    target: str, count: int, min_port=30000, max_port=65000, pps=300
) -> None:
    """Fire UDP to many random high ports (also inflates unique_dports_15s)."""
    for _ in range(count):
        port = random.randint(min_port, max_port)
        await asyncio.to_thread(_udp_fire_and_forget, target, port, _random_payload(64))
        await asyncio.sleep(1.0 / max(1, pps))


# ---------------------------
# CLI
# ---------------------------


def parse_args():
    ap = argparse.ArgumentParser(
        description="Generate 'normal' baseline traffic (for training) and 'abnormal' bursts (for testing)."
    )
    sub = ap.add_subparsers(dest="mode", required=True)

    # normal
    p_norm = sub.add_parser("normal", help="Generate baseline/benign traffic.")
    p_norm.add_argument(
        "--duration",
        type=int,
        default=120,
        help="Seconds to run (ignored if --until-ctrl-c).",
    )
    p_norm.add_argument(
        "--pps", type=int, default=20, help="Approx operations per second."
    )
    p_norm.add_argument(
        "--local-only",
        action="store_true",
        help="Use only localhost targets (default).",
    )
    p_norm.add_argument(
        "--allow-internet",
        action="store_true",
        help="Allow a few harmless external requests.",
    )
    p_norm.add_argument(
        "--http-port",
        type=int,
        default=8080,
        help="Local HTTP server port (if local-only).",
    )
    p_norm.add_argument(
        "--until-ctrl-c",
        "--until",
        action="store_true",
        help="Run indefinitely until Ctrl+C.",
    )

    # portscan
    p_scan = sub.add_parser(
        "portscan", help="Generate an obvious port scan burst (out-of-norm)."
    )
    p_scan.add_argument(
        "--target",
        default="127.0.0.1",
        help="Target host (use your own machine/lab only).",
    )
    p_scan.add_argument(
        "--ports", default="20-1024", help="Port range, e.g. 20-40 or 1000-2000."
    )
    p_scan.add_argument(
        "--rate", type=int, default=250, help="Rough connects per second."
    )
    p_scan.add_argument(
        "--until-ctrl-c",
        "--until",
        action="store_true",
        help="Repeat the scan loop until Ctrl+C.",
    )
    p_scan.add_argument(
        "--sleep",
        type=float,
        default=1.0,
        help="Pause between repeated scans (seconds).",
    )

    # udp burst
    p_burst = sub.add_parser(
        "udpburst", help="Fire UDP packets to many random high ports."
    )
    p_burst.add_argument(
        "--target",
        default="127.0.0.1",
        help="Target host (use your own machine/lab only).",
    )
    p_burst.add_argument(
        "--count", type=int, default=1000, help="How many packets per burst."
    )
    p_burst.add_argument("--pps", type=int, default=300, help="Packets per second.")
    p_burst.add_argument(
        "--until-ctrl-c",
        "--until",
        action="store_true",
        help="Repeat bursts until Ctrl+C.",
    )
    p_burst.add_argument(
        "--sleep",
        type=float,
        default=1.0,
        help="Pause between repeated bursts (seconds).",
    )

    return ap.parse_args()


def _parse_range(s: str) -> Tuple[int, int]:
    if "-" not in s:
        p = int(s)
        return p, p
    a, b = s.split("-", 1)
    return int(a), int(b)


async def main_async():
    args = parse_args()
    random.seed(42)

    if args.mode == "normal":
        local_only = not args.allow_internet
        server = None
        if local_only:
            server, _ = start_local_http_server(port=args.http_port)
            print(f"[normal] Local HTTP server on 127.0.0.1:{args.http_port}")
        dur = None if getattr(args, "until_ctrl_c", False) else int(args.duration)
        label = "∞ (until Ctrl+C)" if dur is None else f"{dur}s"
        print(f"[normal] Running {label}, pps≈{args.pps}, local_only={local_only}")
        try:
            await _normal_mix(
                duration_s=dur,
                local_only=local_only,
                http_host_port=("127.0.0.1", args.http_port),
                pps=args.pps,
            )
        finally:
            if server:
                with contextlib.suppress(Exception):
                    server.shutdown()
                    server.server_close()
        print("[normal] Done.")
        return

    if args.mode == "portscan":
        sp, ep = _parse_range(args.ports)
        if getattr(args, "until_ctrl_c", False):
            print(
                f"[portscan] Target={args.target} ports={sp}-{ep} rate≈{args.rate}/s (looping until Ctrl+C)"
            )
            try:
                while True:
                    await _portscan(args.target, sp, ep, rate=args.rate)
                    await asyncio.sleep(max(0.0, args.sleep))
            except KeyboardInterrupt:
                print("\n[portscan] Interrupted.")
        else:
            print(f"[portscan] Target={args.target} ports={sp}-{ep} rate≈{args.rate}/s")
            await _portscan(args.target, sp, ep, rate=args.rate)
            print("[portscan] Done.")
        return

    if args.mode == "udpburst":
        if getattr(args, "until_ctrl_c", False):
            print(
                f"[udpburst] Target={args.target} burst={args.count} pps≈{args.pps} (looping until Ctrl+C)"
            )
            try:
                while True:
                    await _udp_burst(args.target, args.count, pps=args.pps)
                    await asyncio.sleep(max(0.0, args.sleep))
            except KeyboardInterrupt:
                print("\n[udpburst] Interrupted.")
        else:
            print(f"[udpburst] Target={args.target} count={args.count} pps≈{args.pps}")
            await _udp_burst(args.target, args.count, pps=args.pps)
            print("[udpburst] Done.")
        return


def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\nInterrupted.")


if __name__ == "__main__":
    main()
