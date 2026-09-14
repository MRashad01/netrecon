from netrecon.cli import build_parser, render_table
from netrecon.scanner import PortResult, ScanReport


def test_parser_udp_flag():
    parser = build_parser()
    args = parser.parse_args(["127.0.0.1", "--udp"])
    assert args.udp is True
    assert args.target == "127.0.0.1"


def test_render_table_tcp():
    report = ScanReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        started_at=0.0,
        duration=0.1,
        protocol="tcp",
        results=[
            PortResult(port=22, state="open", service="ssh", banner="OpenSSH_9.0"),
            PortResult(port=80, state="closed", service="http"),
        ],
    )
    table = render_table(report)
    assert "PORT  SERVICE         BANNER" in table
    assert "22  ssh             OpenSSH_9.0" in table


def test_render_table_udp():
    report = ScanReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        started_at=0.0,
        duration=0.1,
        protocol="udp",
        results=[
            PortResult(port=53, state="open|filtered", service="dns", banner=""),
        ],
    )
    table = render_table(report)
    assert "PORT  STATE         SERVICE         BANNER" in table
    assert "53  open|filtered dns             -" in table
