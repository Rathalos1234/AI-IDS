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
import textwrap

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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
        except (TimeoutError, socket.timeout, OSError):
            return
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {_rand_user_agent()}\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(req.encode("ascii", "ignore"))
        with contextlib.suppress(TimeoutError, socket.timeout, OSError):
            sock.recv(1024)


def _tcp_connect_only(host: str, port: int, timeout=0.4) -> None:
    """Bare TCP connect; close immediately. Good for scans and lightweight probes."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        with contextlib.suppress(Exception):
            sock.connect((host, port))


def _udp_fire_and_forget(host: str, port: int, payload: bytes) -> None:
    """Transmit a UDP datagram; do not wait for replies."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.5)
        sock.sendto(payload, (host, port))


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
    server_version = "LocalHTTP/1.0"

    def log_message(self, fmt, *args):  # silence console
        pass

    def do_GET(self) -> None:  # noqa: D401 - simple test handler
        path = self.path or "/"
        if path in {"/", "/health", "/healthz"}:
            body = b"ok"
        elif path.startswith("/parallel/"):
            body = path.encode("utf-8", "ignore")
        else:
            # Fallback to default static file handling
            super().do_GET()
            return

        body += b"\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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
    duration_s: float | int | None,
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
        prog="traffic_gen.py",
        description=(
            "Generate baseline ('normal') traffic for model training and targeted 'abnormal' spikes for testing.\n"
            "All generators support long-running loops via --until-ctrl-c, so you can keep a background stream going "
            "while the IDS trains or monitors."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent("""
            Examples
            --------
            # Baseline: local-only HTTP + DNS + NTP for 2 minutes
            traffic_gen.py normal --duration 120 --pps 20

            # Baseline indefinitely (until Ctrl+C), ~15 ops/sec
            traffic_gen.py normal --until-ctrl-c --pps 15

            # Baseline with a few harmless internet touches (HTTP/HTTPS)
            traffic_gen.py normal --allow-internet --duration 60

            # One pass quick port scan on localhost (20..1024)
            traffic_gen.py portscan --target 127.0.0.1 --ports 20-1024 --rate 300

            # Repeated scans until Ctrl+C with a short pause between rounds
            traffic_gen.py portscan --target 127.0.0.1 --ports 1-65535 --rate 500 --until-ctrl-c --sleep 2

            # UDP burst to random high ports (inflates unique_dports_15s)
            traffic_gen.py udpburst --target 127.0.0.1 --count 1500 --pps 500

            # Keep firing bursts until Ctrl+C
            traffic_gen.py udpburst --target 127.0.0.1 --count 800 --pps 400 --until-ctrl-c --sleep 0.5

            Notes
            -----
            • Use these generators only on your own machine or lab networks.
            • 'normal' will auto-start a local HTTP server on --http-port when --local-only (default).
            • 'pps' is an approximate rate; actual cadence varies slightly by random jitter and system load.
        """),
    )
    sub = ap.add_subparsers(dest="mode", required=True)

    # normal
    p_norm = sub.add_parser(
        "normal",
        help="Generate baseline/benign traffic (HTTP GETs, DNS queries, NTP-like UDP, optional HTTPS connects).",
        description=textwrap.dedent("""
            Produce a benign blend suitable for training a 'normal' model:
            • Local HTTP GETs to a tiny server (auto-started) when --local-only
            • UDP DNS queries (port 53)
            • NTP-sized UDP packets (port 123)
            • Occasional HTTPS TCP connects (only when --allow-internet)
        """),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p_norm.add_argument(
        "--duration",
        type=int,
        default=120,
        help="How long to run, in seconds. Ignored when --until-ctrl-c is used.",
    )
    p_norm.add_argument(
        "--pps",
        type=int,
        default=20,
        help="Approximate operations per second across the mixed activities (default: 20).",
    )
    p_norm.add_argument(
        "--local-only",
        action="store_true",
        help="Restrict activity to localhost only (default behavior).",
    )
    p_norm.add_argument(
        "--allow-internet",
        action="store_true",
        help="Allow a handful of harmless external HTTP/HTTPS touches (disables --local-only).",
    )
    p_norm.add_argument(
        "--http-port",
        type=int,
        default=8080,
        help="Port for the auto-started local HTTP server when --local-only (default: 8080).",
    )
    p_norm.add_argument(
        "--until-ctrl-c",
        "--until",
        action="store_true",
        help="Run indefinitely until Ctrl+C instead of stopping after --duration.",
    )

    # portscan
    p_scan = sub.add_parser(
        "portscan",
        help="Generate a conspicuous TCP connect() scan across a port range (out-of-norm).",
        description=textwrap.dedent("""
            Fire TCP connect attempts across a contiguous port range on a target host.
            Useful to trip 'port-scan' style signatures and raise anomaly scores.
            Combine --until-ctrl-c with --sleep to repeat scans in a loop.
        """),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p_scan.add_argument(
        "--target",
        default="127.0.0.1",
        help="Target host/IP (use only on your own machine or lab networks). Default: 127.0.0.1",
    )
    p_scan.add_argument(
        "--ports",
        default="20-1024",
        help="Port range inclusive, e.g. 20-40 or 1000-2000. Default: 20-1024",
    )
    p_scan.add_argument(
        "--rate",
        type=int,
        default=250,
        help="Approximate connect attempts per second (default: 250).",
    )
    p_scan.add_argument(
        "--until-ctrl-c",
        "--until",
        action="store_true",
        help="Repeat the scan loop until Ctrl+C instead of a single pass.",
    )
    p_scan.add_argument(
        "--sleep",
        type=float,
        default=1.0,
        help="Pause in seconds between repeated scans when --until-ctrl-c is set (default: 1.0).",
    )

    # udp burst
    p_burst = sub.add_parser(
        "udpburst",
        help="Send UDP packets to random high ports (amplifies unique_dports_15s; out-of-norm).",
        description=textwrap.dedent("""
            Fire-and-forget UDP datagrams to random high-numbered ports on a target host.
            Good for exercising 'unique destination ports' features and anomaly scoring.
        """),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p_burst.add_argument(
        "--target",
        default="127.0.0.1",
        help="Target host/IP (use only on your own machine or lab networks). Default: 127.0.0.1",
    )
    p_burst.add_argument(
        "--count",
        type=int,
        default=1000,
        help="How many UDP packets to send per burst (default: 1000).",
    )
    p_burst.add_argument(
        "--pps",
        type=int,
        default=300,
        help="Approximate packets per second (default: 300).",
    )
    p_burst.add_argument(
        "--until-ctrl-c",
        "--until",
        action="store_true",
        help="Repeat bursts until Ctrl+C instead of stopping after a single burst.",
    )
    p_burst.add_argument(
        "--sleep",
        type=float,
        default=1.0,
        help="Pause in seconds between repeated bursts when --until-ctrl-c is set (default: 1.0).",
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
