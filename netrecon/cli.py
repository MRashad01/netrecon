"""Command-line interface for netrecon."""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import sys

from netrecon import __version__
from netrecon.ports import TOP_PORTS, parse_port_spec
from netrecon.scanner import ScanReport, scan_target

LEGAL_NOTE = "Scan only systems you own or have explicit written permission to test."


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netrecon",
        description=f"Async TCP port scanner with banner grabbing. {LEGAL_NOTE}",
    )
    p.add_argument("target", help="hostname or IPv4 address to scan")
    p.add_argument("-p", "--ports", default=None,
                   help='ports to scan, e.g. "22,80,8000-8100" (default: common ports)')
    p.add_argument("-t", "--timeout", type=float, default=2.0,
                   help="connect timeout in seconds (default: 2.0)")
    p.add_argument("-c", "--concurrency", type=int, default=200,
                   help="max simultaneous connections (default: 200)")
    p.add_argument("--no-banners", action="store_true", help="skip banner grabbing")
    p.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def render_table(report: ScanReport) -> str:
    lines = [
        f"netrecon report for {report.target} ({report.resolved_ip})",
        (f"scanned {len(report.results)} ports in {report.duration:.2f}s — "
         f"{len(report.open_ports)} open"),
        "",
    ]
    if report.open_ports:
        lines.append(f"{'PORT':>7}  {'SERVICE':<15} BANNER")
        for r in report.open_ports:
            banner = r.banner.splitlines()[0][:60] if r.banner else "-"
            lines.append(f"{r.port:>7}  {r.service:<15} {banner}")
    else:
        lines.append("no open ports found")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ports = parse_port_spec(args.ports) if args.ports else sorted(TOP_PORTS)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    try:
        report = asyncio.run(scan_target(
            args.target, ports,
            timeout=args.timeout,
            concurrency=args.concurrency,
            grab_banners=not args.no_banners,
        ))
    except socket.gaierror:
        print(f"error: cannot resolve host: {args.target}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130

    print(json.dumps(report.to_dict(), indent=2) if args.json else render_table(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
