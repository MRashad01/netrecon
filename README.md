# netrecon

Async TCP port scanner with service banner grabbing, written in pure Python (no dependencies).

Built as a practical reconnaissance tool for **authorized** network assessments: fast concurrent scanning, best-effort service identification, and machine-readable JSON output for pipelines.

## Features

- ⚡ **Async I/O** — scans hundreds of ports concurrently with a configurable connection limit
- 🏷️ **Banner grabbing** — passive reads for server-first protocols (SSH, FTP, SMTP…), polite `HEAD` probe for HTTP ports
- 🎯 **Flexible port specs** — `-p 22,80,8000-8100` or a curated default list of common services
- 📄 **JSON output** — `--json` for feeding results into other tooling
- 🐍 **Zero dependencies** — standard library only, Python 3.10+

## Install

```bash
git clone https://github.com/MRashad01/netrecon
cd netrecon
pip install .
```

## Usage

```bash
# Scan common ports on a host you are authorized to test
netrecon scanme.example.com

# Specific ports and ranges, JSON output
netrecon 192.168.1.10 -p 22,80,443,8000-8100 --json

# Faster scan: shorter timeout, higher concurrency, no banners
netrecon 10.0.0.5 -t 0.5 -c 500 --no-banners
```

Example output:

```
netrecon report for 192.168.1.10 (192.168.1.10)
scanned 36 ports in 1.84s — 3 open

   PORT  SERVICE         BANNER
     22  ssh             SSH-2.0-OpenSSH_9.6
     80  http            HTTP/1.1 200 OK
   3306  mysql           -
```

## How it works

`netrecon` performs TCP **connect** scans (full three-way handshake) using `asyncio.open_connection`, bounded by a semaphore. A refused connection is reported `closed`, a timeout `filtered`. For open ports it attempts a short banner read: protocols where the server speaks first are read passively; HTTP-like ports get a minimal `HEAD / HTTP/1.0` probe.

Connect scans need no raw sockets or elevated privileges, at the cost of being more visible in target logs than SYN scans — a deliberate trade-off for a tool aimed at authorized assessments.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

Tests run entirely against loopback servers — no external network access.

## Legal

This tool is for **authorized security testing, research, and education only**. Port scanning systems without the owner's explicit permission may be illegal in your jurisdiction. You are responsible for how you use it.

## License

MIT — see [LICENSE](LICENSE).
