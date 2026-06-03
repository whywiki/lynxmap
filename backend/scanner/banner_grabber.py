import asyncio
import re
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.scan_result import Service


# --- Timeout for banner reading ---
BANNER_TIMEOUT = 3.0

# --- Generic probe sent to listeners ---
# many services respond to this even if
# they aren't HTTP giving us something to parse
GENERIC_PROBE = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"


# --- Service fingerprint patterns ---
# Each entry is (regex_pattern, service_name)
# We try these against the raw banner string

SERVICE_PATTERNS = [
    # SSH - "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    (r"SSH-[\d.]+-OpenSSH[_\s]([\d.p]+)", "OpenSSH"),

    # Apache - "Apache/2.4.41 (Ubuntu)"
    (r"Apache/([\d.]+)", "Apache httpd"),

    # Nginx - "nginx/1.18.0"
    (r"nginx/([\d.]+)", "nginx"),

    # OpenSSL
    (r"OpenSSL/([\d.]+\w*)", "OpenSSL"),

    # MySQL - "5.7.38-MySQL Community Server"
    (r"([\d.]+)-MySQL", "MySQL"),

    # PostgreSQL - appears in error banners
    (r"PostgreSQL\s+([\d.]+)", "PostgreSQL"),

    # ProFTPD / vsftpd / Pure-FTPd
    (r"ProFTPD\s+([\d.]+)", "ProFTPD"),
    (r"vsftpd\s+([\d.]+)", "vsftpd"),
    (r"Pure-FTPd", "Pure-FTPd"),

    # Microsoft IIS
    (r"Microsoft-IIS/([\d.]+)", "Microsoft IIS"),

    # SMB / Samba
    (r"Samba\s+([\d.]+)", "Samba"),

    # Generic HTTP server header fallback
    (r"Server:\s*([^\r\n]+)", "HTTP Server"),
]


def parse_banner(raw_banner: str) -> tuple[str, str | None]:
    """
    Try to extract a service name and version from a raw banner string.

    Returns a tuple of (service_name, version_or_None).

    We try each pattern in SERVICE_PATTERNS. The first group in the
    regex (if present) is treated as the version string.
    """
    for pattern, service_name in SERVICE_PATTERNS:
        match = re.search(pattern, raw_banner, re.IGNORECASE)
        if match:
            # If the pattern has a capture group it's the version
            # If not version is None
            version = match.group(1) if match.lastindex and match.lastindex >= 1 else None

            # Clean up version string
            if version:
                version = version.strip()

            return service_name, version

    # Nothing matched
    return "Unknown", None

async def grab_banner(
    host: str,
    port: int,
    timeout: float = BANNER_TIMEOUT
) -> Service | None:
    """
    Connect to an open port and attempt to read its service banner.
    Handles plain TCP, HTTP, and HTTPS (TLS) connections.
    """

    # --- Determine if this port needs TLS ---
    USE_TLS = port in (443, 8443, 9443)

    # --- Determine the right probe for known listener ports ---
    # HTTP/1.1 with a real Host header works on far more servers than HTTP/1.0
    HTTP_PROBE = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    try:
        # --- Open connection (with or without TLS) ---
        if USE_TLS:
            import ssl
            # create_default_context() sets up TLS but we disable cert
            # verification — we're scanning, not authenticating
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )

        raw_banner = ""

        try:
            # --- Step 1: wait for spontaneous banner (talkers like SSH) ---
            data = await asyncio.wait_for(
                reader.read(1024),
                timeout=2.0
            )
            if data:
                raw_banner = data.decode("utf-8", errors="ignore").strip()

        except asyncio.TimeoutError:
            # --- Step 2: service is a listener, send probe ---
            try:
                # Use HTTP probe for web ports, generic probe for others
                probe = HTTP_PROBE if port in (80, 443, 8080, 8443) else GENERIC_PROBE
                writer.write(probe)
                await writer.drain()

                data = await asyncio.wait_for(
                    reader.read(2048),  # larger buffer for HTTP responses
                    timeout=2.0
                )
                if data:
                    raw_banner = data.decode("utf-8", errors="ignore").strip()

            except (asyncio.TimeoutError, Exception):
                pass

        # --- Close cleanly ---
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if not raw_banner:
            return Service(name=_well_known_service(port), raw_banner=None)

        service_name, version = parse_banner(raw_banner)

        return Service(
            name=service_name,
            version=version,
            raw_banner=raw_banner[:500]
        )

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError, Exception):
        return None


def _well_known_service(port: int) -> str:
    """
    Fallback - if we connected but got no banner, at least label
    the port by its well-known service name.
    """
    WELL_KNOWN = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        27017: "MongoDB",
    }
    return WELL_KNOWN.get(port, f"port-{port}")
