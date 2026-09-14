import json
import socket
import threading
from unittest.mock import patch

from netrecon.cli import build_parser, main
from netrecon.scanner import PortResult, ScanReport


def test_parser_output_flag():
    parser = build_parser()
    args_none = parser.parse_args(["127.0.0.1"])
    assert args_none.output is None

    args_short = parser.parse_args(["127.0.0.1", "-o", "report.json"])
    assert args_short.output == "report.json"

    args_long = parser.parse_args(["127.0.0.1", "--output", "report.json"])
    assert args_long.output == "report.json"


def test_cli_output_to_file(tmp_path, capsys):
    out_file = tmp_path / "report.json"
    dummy_report = ScanReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        started_at=1000.0,
        duration=0.05,
        results=[PortResult(80, "open", "http", "HTTP/1.1 200 OK")],
    )

    with patch("netrecon.cli.scan_target", return_value=dummy_report):
        exit_code = main(["127.0.0.1", "-o", str(out_file)])
        assert exit_code == 0

    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["target"] == "127.0.0.1"
    assert data["total_scanned"] == 1
    assert len(data["open_ports"]) == 1
    assert data["open_ports"][0]["port"] == 80
    assert data["open_ports"][0]["service"] == "http"

    captured = capsys.readouterr()
    assert "netrecon report for 127.0.0.1" in captured.out
    assert "80  http" in captured.out


def test_cli_output_with_json_flag(tmp_path, capsys):
    out_file = tmp_path / "report.json"
    dummy_report = ScanReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        started_at=1000.0,
        duration=0.05,
        results=[PortResult(22, "open", "ssh", "SSH-2.0-OpenSSH")],
    )

    with patch("netrecon.cli.scan_target", return_value=dummy_report):
        exit_code = main(["127.0.0.1", "--json", "--output", str(out_file)])
        assert exit_code == 0

    assert out_file.exists()
    file_data = json.loads(out_file.read_text(encoding="utf-8"))
    stdout_data = json.loads(capsys.readouterr().out)
    assert file_data == stdout_data
    assert file_data["target"] == "127.0.0.1"
    assert file_data["open_ports"][0]["port"] == 22


def test_cli_output_write_error(tmp_path, capsys):
    invalid_path = tmp_path / "nonexistent_dir" / "report.json"
    dummy_report = ScanReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        started_at=1000.0,
        duration=0.05,
        results=[],
    )

    with patch("netrecon.cli.scan_target", return_value=dummy_report):
        exit_code = main(["127.0.0.1", "-o", str(invalid_path)])
        assert exit_code == 1

    captured = capsys.readouterr()
    assert "error: cannot write output file" in captured.err


def test_cli_output_integration_loopback(tmp_path):
    out_file = tmp_path / "integration_report.json"

    # Start a loopback TCP listener on a free port
    server = socket.create_server(("127.0.0.1", 0))
    port = server.getsockname()[1]
    stop_server = threading.Event()

    def run_server():
        server.settimeout(0.5)
        while not stop_server.is_set():
            try:
                conn, _ = server.accept()
                conn.close()
            except TimeoutError:
                continue
            except OSError:
                break

    thread = threading.Thread(target=run_server)
    thread.start()

    try:
        exit_code = main(["127.0.0.1", "-p", str(port), "-t", "0.5", "-o", str(out_file)])
        assert exit_code == 0
    finally:
        stop_server.set()
        server.close()
        thread.join()

    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["target"] == "127.0.0.1"
    assert any(p["port"] == port for p in data["open_ports"])
