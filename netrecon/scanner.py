"""Async TCP connect scanner with optional banner grabbing."""

from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import dataclass, field

from netrecon.ports import service_name

# Ports where the server speaks first, so a passive read yields a banner.
_SERVER_TALKS_FIRST = {21, 22, 25, 110, 143, 465, 587, 993, 995, 6379}

# A polite probe for HTTP-like ports; everything else gets a passive read.
_HTTP_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"
_HTTP_PORTS = {80, 443, 8000, 8080, 8443, 8888}


@dataclass
class PortResult:
    port: int
    state: str  # "open" | "closed" | "filtered"
    service: str = "unknown"
    banner: str = ""


@dataclass
class ScanReport:
    target: str
    resolved_ip: str
    started_at: float
    duration: float = 0.0
    results: list[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        return [r for r in self.results if r.state == "open"]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "started_at": self.started_at,
            "duration_seconds": round(self.duration, 3),
            "open_ports": [
                {"port": r.port, "service": r.service, "banner": r.banner}
                for r in self.open_ports
            ],
            "total_scanned": len(self.results),
        }


async def _grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                       port: int, timeout: float) -> str:
    try:
        if port in _HTTP_PORTS:
            writer.write(_HTTP_PROBE)
            await writer.drain()
        elif port not in _SERVER_TALKS_FIRST:
            return ""
        raw = await asyncio.wait_for(reader.read(256), timeout=timeout)
        return raw.decode("utf-8", errors="replace").strip()
    except (asyncio.TimeoutError, ConnectionError, OSError):
        return ""


async def _probe_port(ip: str, port: int, timeout: float, grab_banners: bool,
                      sem: asyncio.Semaphore) -> PortResult:
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
        except asyncio.TimeoutError:
            return PortResult(port, "filtered")
        except ConnectionRefusedError:
            return PortResult(port, "closed")
        except OSError:
            return PortResult(port, "filtered")

        banner = ""
        if grab_banners:
            banner = await _grab_banner(reader, writer, port, timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        return PortResult(port, "open", service_name(port), banner)


def resolve(target: str) -> str:
    """Resolve a hostname to an IPv4 address (returns the input if already an IP)."""
    return socket.getaddrinfo(target, None, socket.AF_INET)[0][4][0]


async def scan_target(target: str, ports: list[int], *, timeout: float = 2.0,
                      concurrency: int = 200, grab_banners: bool = True) -> ScanReport:
    """Scan ``ports`` on ``target`` concurrently and return a ScanReport."""
    ip = resolve(target)
    report = ScanReport(target=target, resolved_ip=ip, started_at=time.time())
    t0 = time.monotonic()
    sem = asyncio.Semaphore(concurrency)
    tasks = [_probe_port(ip, p, timeout, grab_banners, sem) for p in ports]
    report.results = sorted(await asyncio.gather(*tasks), key=lambda r: r.port)
    report.duration = time.monotonic() - t0
    return report
