"""Well-known port lists and service name lookup."""

# The most commonly exposed TCP services, ordered roughly by prevalence.
TOP_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    593: "http-rpc-epmap",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1025: "nfs-or-iis",
    1433: "mssql",
    1723: "pptp",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5060: "sip",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

# The most commonly exposed UDP services.
TOP_UDP_PORTS: dict[int, str] = {
    53: "dns",
    67: "dhcps",
    68: "dhcpc",
    69: "tftp",
    123: "ntp",
    137: "netbios-ns",
    138: "netbios-dgm",
    161: "snmp",
    162: "snmptrap",
    500: "isakmp",
    514: "syslog",
    1194: "openvpn",
    1900: "ssdp",
    4500: "ipsec-nat-t",
    5353: "mdns",
}


def service_name(port: int, protocol: str = "tcp") -> str:
    """Best-effort service name for a TCP or UDP port."""
    if protocol.lower() == "udp":
        return TOP_UDP_PORTS.get(port, TOP_PORTS.get(port, "unknown"))
    return TOP_PORTS.get(port, "unknown")


def parse_port_spec(spec: str) -> list[int]:
    """Parse a port specification like ``"22,80,8000-8100"`` into a sorted list.

    Raises ValueError on malformed input or out-of-range ports.
    """
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, _, hi_s = part.partition("-")
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                raise ValueError(f"invalid range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    for p in ports:
        if not 1 <= p <= 65535:
            raise ValueError(f"port out of range: {p}")
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)
