"""Unit tests for traffic_gen helpers exercising live sockets and async helpers."""

from __future__ import annotations

import asyncio
import concurrent.futures
import random
import socket
import socketserver
import threading
import time
from contextlib import suppress
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import traffic_gen
from types import SimpleNamespace


@pytest.mark.unit
def test_rand_user_agent_returns_variety():
    """Legacy coverage: ensure the random user agent helper still varies."""
    random.seed(42)
    observed = {traffic_gen._rand_user_agent() for _ in range(8)}
    assert len(observed) >= 2


@pytest.mark.unit
def test_parse_range_handles_single_value_and_span():
    """Range parsing aligns with the production helper (inclusive tuple)."""
    assert traffic_gen._parse_range("80-82") == (80, 82)
    assert traffic_gen._parse_range("443") == (443, 443)


@pytest.mark.unit
def test_random_payload_and_dns_query_helpers():
    """Low-level helper outputs should match expected wire-format constraints."""
    payload = traffic_gen._random_payload(32)
    assert isinstance(payload, bytes)
    assert len(payload) == 32
    assert payload.isascii()

    query = traffic_gen._build_dns_query("example.com")
    # Header (12 bytes) + label-encoded body; ensure trailing null and qtype/qclass
    assert len(query) > 12
    assert query[-4:] == b"\x00\x01\x00\x01"


@pytest.mark.unit
def test_tcp_udp_helpers_complete_successfully():
    """TCP/UDP helpers should complete without raising and reach the target service."""

    class ProbeHandler(socketserver.BaseRequestHandler):
        hits = 0

        def handle(self):  # type: ignore[override]
            type(self).hits += 1
            with suppress(Exception):
                self.request.recv(1024)

    tcp_server = socketserver.TCPServer(("127.0.0.1", 0), ProbeHandler)
    tcp_port = tcp_server.server_address[1]
    tcp_thread = threading.Thread(target=tcp_server.serve_forever, daemon=True)
    tcp_thread.start()

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("127.0.0.1", 0))
    udp_port = udp_sock.getsockname()[1]
    udp_sock.settimeout(0.2)

    http_server, http_thread = traffic_gen.start_local_http_server(port=0)
    http_port = http_server.server_address[1]

    try:
        traffic_gen._tcp_connect_only("127.0.0.1", tcp_port)
        traffic_gen._tcp_connect_and_http_get("127.0.0.1", http_port, "/")
        traffic_gen._udp_fire_and_forget("127.0.0.1", udp_port, b"ping")
        with suppress(socket.timeout):
            udp_sock.recvfrom(4096)
    finally:
        tcp_server.shutdown()
        tcp_server.server_close()
        tcp_thread.join(timeout=1)
        udp_sock.close()
        http_server.shutdown()
        http_server.server_close()
        http_thread.join(timeout=1)

    assert ProbeHandler.hits >= 1


@pytest.mark.unit
def test_start_local_http_server_serves_requests():
    """The helper HTTP server should respond to a simple GET."""
    server, thread = traffic_gen.start_local_http_server(port=0)
    port = server.server_address[1]
    try:
        import urllib.request

        response = urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)
        assert response.status == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.unit
def test_start_local_http_server_handles_parallel_requests():
    """Multiple concurrent requests should be served successfully."""
    server, thread = traffic_gen.start_local_http_server(port=0)
    port = server.server_address[1]

    def make_request(idx: int) -> int:
        import urllib.request

        try:
            response = urllib.request.urlopen(
                f"http://127.0.0.1:{port}/parallel/{idx}", timeout=1
            )
            return response.status
        except Exception:
            return 0

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(make_request, range(5)))
        assert all(status == 200 for status in results)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.unit
def test_normal_mix_hits_local_http_server():
    """The normal traffic generator should make HTTP requests against the helper server."""
    hits: list[str] = []

    class CountingHandler(traffic_gen._QuietHandler):
        def do_GET(self):  # type: ignore[override]
            hits.append(self.path)
            super().do_GET()

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(traffic_gen, "_QuietHandler", CountingHandler)
        server, thread = traffic_gen.start_local_http_server(port=0)
        port = server.server_address[1]
        try:
            asyncio.run(
                traffic_gen._normal_mix(
                    duration_s=1,
                    local_only=True,
                    http_host_port=("127.0.0.1", port),
                    pps=40,
                )
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

    assert hits, "Expected at least one HTTP GET request to be captured"


@pytest.mark.asyncio
async def test_normal_mix_generates_various_traffic():
    """Normal mix should exercise TCP and UDP helpers via sockets."""
    with patch("socket.socket") as mock_socket_class:
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect.return_value = None
        mock_socket.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"

        await traffic_gen._normal_mix(
            duration_s=0.4,
            local_only=True,
            http_host_port=("127.0.0.1", 80),
            pps=60,
        )

        assert mock_socket_class.call_count > 0


class _TCPProbeHandler(socketserver.BaseRequestHandler):
    hits = 0

    def handle(self):  # type: ignore[override]
        type(self).hits += 1
        with suppress(Exception):
            self.request.recv(16)


@pytest.mark.unit
def test_portscan_connects_to_open_ports():
    """Port scan bursts should open connections to reachable ports."""
    server = socketserver.TCPServer(("127.0.0.1", 0), _TCPProbeHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        asyncio.run(traffic_gen._portscan("127.0.0.1", port, port, rate=200))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert _TCPProbeHandler.hits > 0


@pytest.mark.asyncio
async def test_portscan_handles_closed_ports():
    """Port scan should handle closed ports gracefully."""
    closed_port = 59999
    await traffic_gen._portscan("127.0.0.1", closed_port, closed_port, rate=100)


@pytest.mark.asyncio
async def test_portscan_rate_limiting():
    """Port scan should roughly respect the configured rate limit."""
    with patch("socket.socket") as mock_socket_class:
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect_ex.return_value = 1

        start = time.time()
        await traffic_gen._portscan("127.0.0.1", 1000, 1010, rate=100)
        elapsed = time.time() - start

    assert elapsed > 0.08


@pytest.mark.unit
def test_udp_burst_delivers_packets():
    """UDP bursts should transmit datagrams to the configured port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.2)
    port = sock.getsockname()[1]

    asyncio.run(
        traffic_gen._udp_burst(
            "127.0.0.1", count=20, min_port=port, max_port=port, pps=400
        )
    )

    received = 0
    while True:
        try:
            sock.recvfrom(4096)
            received += 1
        except socket.timeout:
            break
    sock.close()

    assert received >= 10


@pytest.mark.asyncio
async def test_udp_burst_rate_control():
    """UDP bursts should respect the requested packets-per-second cadence."""
    sent_times: list[float] = []

    def mock_sendto(data, addr):
        sent_times.append(time.time())
        return len(data)

    with patch("socket.socket") as mock_socket_class:
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.sendto = mock_sendto

        await traffic_gen._udp_burst(
            "127.0.0.1",
            count=10,
            min_port=5000,
            max_port=5000,
            pps=50,
        )

    if len(sent_times) > 1:
        intervals = [
            sent_times[i + 1] - sent_times[i] for i in range(len(sent_times) - 1)
        ]
        avg_interval = sum(intervals) / len(intervals)
        expected = 1.0 / 50
        assert abs(avg_interval - expected) < 0.05


@pytest.mark.unit
def test_main_async_dispatches_normal(monkeypatch):
    """CLI entry point should invoke the normal traffic generator with the parsed args."""
    calls: dict[str, Any] = {}

    args = SimpleNamespace(
        mode="normal",
        allow_internet=False,
        duration=1,
        pps=5,
        http_port=0,
        until_ctrl_c=False,
    )

    async def fake_normal_mix(**kwargs):
        calls["normal"] = kwargs

    class DummyServer:
        def shutdown(self):
            calls["shutdown"] = True

        def server_close(self):
            calls["close"] = True

    monkeypatch.setattr(traffic_gen, "parse_args", lambda: args)
    monkeypatch.setattr(traffic_gen, "_normal_mix", fake_normal_mix)
    monkeypatch.setattr(
        traffic_gen, "start_local_http_server", lambda **_: (DummyServer(), None)
    )

    asyncio.run(traffic_gen.main_async())

    assert "normal" in calls
    assert calls["normal"]["local_only"] is True


@pytest.mark.unit
def test_main_async_dispatches_portscan(monkeypatch):
    """Portscan mode should parse ranges and call the async helper once."""
    args = SimpleNamespace(
        mode="portscan",
        target="127.0.0.1",
        ports="10-12",
        rate=100,
        until_ctrl_c=False,
        sleep=0.1,
    )
    calls: list[tuple] = []

    async def fake_portscan(target, start_port, end_port, rate):
        calls.append((target, start_port, end_port, rate))

    monkeypatch.setattr(traffic_gen, "parse_args", lambda: args)
    monkeypatch.setattr(traffic_gen, "_portscan", fake_portscan)

    asyncio.run(traffic_gen.main_async())

    assert calls == [("127.0.0.1", 10, 12, 100)]


@pytest.mark.unit
def test_main_async_dispatches_udpburst(monkeypatch):
    """UDP burst mode should call the helper with the provided cadence."""
    args = SimpleNamespace(
        mode="udpburst",
        target="127.0.0.1",
        count=25,
        pps=200,
        until_ctrl_c=False,
        sleep=0.1,
    )
    calls: list[tuple] = []

    async def fake_udp(target, count, pps):
        calls.append((target, count, pps))

    monkeypatch.setattr(traffic_gen, "parse_args", lambda: args)
    monkeypatch.setattr(traffic_gen, "_udp_burst", fake_udp)

    asyncio.run(traffic_gen.main_async())

    assert calls == [("127.0.0.1", 25, 200)]
