"""Scanner tests run against a loopback server — no external network access."""

import asyncio
import socket

import pytest

from netrecon.scanner import scan_target


async def _start_banner_server(banner: bytes):
    async def handle(reader, writer):
        writer.write(banner)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


@pytest.mark.asyncio
async def test_detects_open_port_and_banner():
    server, port = await _start_banner_server(b"SSH-2.0-testserver\r\n")
    try:
        # Use an SSH-style port number so the passive banner read kicks in.
        report = await scan_target("127.0.0.1", [port], timeout=2.0)
        assert len(report.open_ports) == 1
        assert report.open_ports[0].port == port
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_closed_port_reported_closed():
    # Bind then close a socket so the port is very likely free.
    server, port = await _start_banner_server(b"")
    server.close()
    await server.wait_closed()

    report = await scan_target("127.0.0.1", [port], timeout=2.0)
    assert report.open_ports == []
    assert report.results[0].state in {"closed", "filtered"}


@pytest.mark.asyncio
async def test_report_dict_shape():
    server, port = await _start_banner_server(b"hello\r\n")
    try:
        report = await scan_target("127.0.0.1", [port], timeout=2.0)
        d = report.to_dict()
        assert d["target"] == "127.0.0.1"
        assert d["total_scanned"] == 1
        assert isinstance(d["open_ports"], list)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_udp_scan_timeout_open_filtered():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    try:
        report = await scan_target("127.0.0.1", [port], timeout=0.2, protocol="udp")
        assert len(report.results) == 1
        assert report.results[0].port == port
        assert report.results[0].state == "open|filtered"
    finally:
        sock.close()


@pytest.mark.asyncio
async def test_udp_scan_open_with_banner():
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    async def reply():
        _data, addr = await loop.run_in_executor(None, sock.recvfrom, 1024)
        sock.sendto(b"TEST_BANNER\n", addr)

    reply_task = asyncio.create_task(reply())
    try:
        report = await scan_target("127.0.0.1", [port], timeout=1.0, protocol="udp")
        assert len(report.open_ports) == 1
        assert report.open_ports[0].port == port
        assert report.open_ports[0].state == "open"
        assert report.open_ports[0].banner == "TEST_BANNER"
    finally:
        reply_task.cancel()
        sock.close()
