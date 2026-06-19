import httpx
import asyncio
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.scan_result import CVE, Severity, CveMode
from dotenv import load_dotenv


def _load_env_files() -> None:
    project_root = Path(__file__).resolve().parents[2]
    load_dotenv(project_root / '.env', override=False)
    load_dotenv(project_root / 'backend' / '.env', override=False)


_load_env_files()


# --- Config ---

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

MAX_RESULTS = 5

# NVD rate limits (official):
#   no key  -> 5 requests / 30s -> minimum 6s between requests
#   with key -> 50 requests / 30s -> minimum 0.6s between requests
#
# We add a safety buffer: 7s without key, 0.8s with key.
_API_KEY = os.environ.get("NVD_API_KEY", "")
_BASE_DELAY = 0.8 if _API_KEY else 7.0


# Per-mode settings
# delay    - seconds to wait between NVD requests
# retries  - how many times to retry a 503/429 before giving up
# backoff  - base seconds for exponential backoff on retry
# strategies - which lookup strategies to attempt, in order:
#              "cpe"               - CPE-based version-specific query
#              "keyword_versioned" - canonical name + cleaned version
#              "keyword_name"      - canonical name only (broadest)

_MODE_CONFIG: dict[CveMode, dict] = {
    CveMode.SKIP: {},  # handled before any requests are made

    CveMode.QUICK: {
        "delay":      _BASE_DELAY,
        "retries":    1,
        "backoff":    5.0,
        "strategies": ["cpe", "keyword_versioned"],
        # quick: one shot per strategy, no name-only fallback
    },

    CveMode.FULL: {
        "delay":      _BASE_DELAY,
        "retries":    3,
        "backoff":    10.0,
        "strategies": ["cpe", "keyword_versioned", "keyword_name"],
    },

}


# CPE vendor/product mappings.
# Key: our internal service name lowercased.
# Value: (nvd_vendor, nvd_product, nvd_canonical_keyword)
#   nvd_canonical_keyword is what NVD actually calls the product in CVE text,
#   used as the keyword fallback instead of our internal service name.
CPE_MAPPINGS = {
    "openssh":             ("openbsd",      "openssh",                       "OpenSSH"),
    "apache httpd":        ("apache",       "http_server",                   "Apache HTTP Server"),
    "nginx":               ("nginx",        "nginx",                         "nginx"),
    "mysql":               ("mysql",        "mysql",                         "MySQL"),
    "mariadb":             ("mariadb",      "mariadb",                       "MariaDB"),
    "postgresql":          ("postgresql",   "postgresql",                    "PostgreSQL"),
    "proftpd":             ("proftpd",      "proftpd",                       "ProFTPD"),
    "vsftpd":              ("vsftpd",       "vsftpd",                        "vsftpd"),
    "microsoft iis":       ("microsoft",    "internet_information_services", "Microsoft IIS"),
    "samba":               ("samba",        "samba",                         "Samba"),
    "openssl":             ("openssl",      "openssl",                       "OpenSSL"),
    "redis":               ("redis",        "redis",                         "Redis"),
    "mongodb":             ("mongodb",      "mongodb",                       "MongoDB"),
    "apache tomcat":       ("apache",       "tomcat",                        "Apache Tomcat"),
    "dropbear ssh":        ("matt_johnston","dropbear_ssh",                  "Dropbear"),
    "exim":                ("exim",         "exim",                          "Exim"),
    "postfix":             ("wietse_venema","postfix",                       "Postfix"),
    "dovecot imap":        ("dovecot",      "dovecot",                       "Dovecot"),
    "dovecot pop3":        ("dovecot",      "dovecot",                       "Dovecot"),
    "filezilla server":    ("filezilla-project","filezilla_server",          "FileZilla Server"),
    "pure-ftpd":           ("pure-ftpd",    "pure-ftpd",                     "Pure-FTPd"),
    "cups":                ("apple",        "cups",                          "CUPS"),
    "elasticsearch":       ("elastic",      "elasticsearch",                 "Elasticsearch"),
    "apache activemq":     ("apache",       "activemq",                      "Apache ActiveMQ"),
    "isc bind":            ("isc",          "bind",                          "ISC BIND"),
    "lighttpd":            ("lighttpd",     "lighttpd",                      "lighttpd"),
    "mikrotik routeros":   ("mikrotik",     "routeros",                      "RouterOS"),
    "vnc":                 ("realvnc",      "vnc",                           "VNC"),
}


# --- In-memory cache ---
# Key: "service_name_lower:version_or_unknown:mode"
# Value: (list[CVE], timestamp)
# Mode is part of the key so a QUICK miss doesn't block a later DEEP hit.

_cache: dict[str, tuple[list[CVE], datetime]] = {}
CACHE_TTL_HOURS = 24


def _cache_key(service_name: str, version: str | None, mode: CveMode) -> str:
    return f"{service_name.lower()}:{version or 'unknown'}:{mode.value}"


def _is_cache_valid(timestamp: datetime) -> bool:
    return datetime.now() - timestamp < timedelta(hours=CACHE_TTL_HOURS)


def _parse_severity(score: float | None, severity_str: str | None) -> Severity:
    if severity_str:
        s = severity_str.upper()
        if s == "CRITICAL": return Severity.CRITICAL
        if s == "HIGH":     return Severity.HIGH
        if s == "MEDIUM":   return Severity.MEDIUM
        if s == "LOW":      return Severity.LOW

    if score is not None:
        if score >= 9.0: return Severity.CRITICAL
        if score >= 7.0: return Severity.HIGH
        if score >= 4.0: return Severity.MEDIUM
        if score > 0:    return Severity.LOW

    return Severity.NONE


def _parse_cvss_metrics(metrics: dict) -> tuple[float | None, Severity]:
    """
    Prefer v3.1 -> v3.0 -> v4.0 -> v2.
    v4.0 is included now that NVD has started publishing it.
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = _parse_severity(score, data.get("baseSeverity"))
            return score, severity

    # v2 has no baseSeverity string
    v2 = metrics.get("cvssMetricV2", [])
    if v2:
        data = v2[0].get("cvssData", {})
        score = data.get("baseScore")
        return score, _parse_severity(score, None)

    return None, Severity.NONE


def _parse_cve_item(item: dict) -> CVE | None:
    try:
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")
        if not cve_id:
            return None

        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available"
        )
        if len(description) > 500:
            description = description[:497] + "..."

        metrics = cve_data.get("metrics", {})
        cvss_score, severity = _parse_cvss_metrics(metrics)
        published = cve_data.get("published", None)

        return CVE(
            cve_id=cve_id,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            published_date=published
        )
    except Exception:
        return None


def _clean_version(version: str) -> str:
    """
    Strip OS-packaging suffixes so CPE matching works.

    Examples:
      "8.9p1 Ubuntu-3ubuntu0.6"  -> "8.9p1"
      "2.4.7+dfsg"               -> "2.4.7"
      "10.6.11-MariaDB-2~ubuntu" -> "10.6.11"
    """
    version = version.split()[0]
    for delim in ("+", "~", "-"):
        version = version.split(delim)[0]
    return version.strip()


async def _do_nvd_request(
    params: dict,
    headers: dict,
    retries: int,
    backoff: float,
) -> list[CVE]:
    """
    Execute one NVD API request with exponential-backoff retry on 503/429.
    Returns parsed CVEs, or [] on permanent failure.
    """
    for attempt in range(retries):
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    NVD_BASE_URL,
                    params=params,
                    headers=headers
                )

            if response.status_code in (503, 429):
                wait = backoff * (2 ** attempt)
                print(f"  [nvd] HTTP {response.status_code} - "
                      f"backing off {wait:.0f}s (attempt {attempt + 1}/{retries})")
                await asyncio.sleep(wait)
                continue

            response.raise_for_status()
            data = response.json()

        except httpx.HTTPStatusError as e:
            print(f"  [nvd] HTTP error {e.response.status_code}")
            return []
        except httpx.RequestError as e:
            print(f"  [nvd] Request failed: {e}")
            if attempt < retries - 1:
                await asyncio.sleep(backoff)
                continue
            return []
        except Exception as e:
            print(f"  [nvd] Unexpected error: {e}")
            return []

        vulnerabilities = data.get("vulnerabilities", [])
        return [c for item in vulnerabilities if (c := _parse_cve_item(item))]

    print(f"  [nvd] All {retries} attempts failed, giving up")
    return []


async def fetch_cves_for_service(
    service_name: str,
    version: str | None,
    mode: CveMode = CveMode.FULL,
) -> list[CVE]:
    """
    Query NVD for CVEs affecting a given service + version.

    Behaviour is controlled by `mode`:
      SKIP  - returns [] immediately, no network calls
      QUICK - CPE + versioned keyword, single attempt, short backoff
      FULL  - CPE + versioned keyword + name-only fallback, 3 retries (default)

    Results are cached per (service, version, mode) for CACHE_TTL_HOURS.
    Empty results are also cached to avoid re-hammering on known misses.
    """
    if mode == CveMode.SKIP:
        return []

    key = _cache_key(service_name, version, mode)

    if key in _cache:
        cached_cves, timestamp = _cache[key]
        if _is_cache_valid(timestamp):
            print(f"  [cache] {service_name} {version or ''} ({mode.value}) -> "
                  f"{len(cached_cves)} CVEs")
            return cached_cves

    cfg = _MODE_CONFIG[mode]
    delay: float       = cfg["delay"]
    retries: int       = cfg["retries"]
    backoff: float     = cfg["backoff"]
    strategies: list   = cfg["strategies"]

    # Always wait before the first real request to respect rate limits
    await asyncio.sleep(delay)

    api_key = os.environ.get("NVD_API_KEY", "")
    headers = {"User-Agent": "LynxMap/0.1.0"}
    if api_key:
        headers["apiKey"] = api_key

    service_key = service_name.lower()
    mapping = CPE_MAPPINGS.get(service_key)
    canonical_name = mapping[2] if mapping else service_name

    cves: list[CVE] = []

    for strategy in strategies:
        if cves:
            break  # stop as soon as we get a hit

        if strategy == "cpe":
            if not (version and mapping):
                continue
            vendor, product, _ = mapping
            clean_ver = _clean_version(version)
            cpe_name = f"cpe:2.3:a:{vendor}:{product}:{clean_ver}:*:*:*:*:*:*:*"
            print(f"  [nvd:{mode.value}] CPE query: '{cpe_name}'")
            cves = await _do_nvd_request(
                {"cpeName": cpe_name, "resultsPerPage": MAX_RESULTS},
                headers, retries, backoff
            )
            print(f"  [nvd:{mode.value}] CPE found {len(cves)} CVEs")

        elif strategy == "keyword_versioned":
            if not version:
                continue
            clean_ver = _clean_version(version)
            query = f"{canonical_name} {clean_ver}"
            print(f"  [nvd:{mode.value}] Keyword (versioned): '{query}'")
            await asyncio.sleep(delay)
            cves = await _do_nvd_request(
                {"keywordSearch": query, "resultsPerPage": MAX_RESULTS},
                headers, retries, backoff
            )
            print(f"  [nvd:{mode.value}] Keyword (versioned) found {len(cves)} CVEs")

        elif strategy == "keyword_name":
            print(f"  [nvd:{mode.value}] Keyword (name only): '{canonical_name}'")
            await asyncio.sleep(delay)
            cves = await _do_nvd_request(
                {"keywordSearch": canonical_name, "resultsPerPage": MAX_RESULTS},
                headers, retries, backoff
            )
            print(f"  [nvd:{mode.value}] Keyword (name only) found {len(cves)} CVEs")

    # Sort: CRITICAL first
    severity_order = {
        Severity.CRITICAL: 0, Severity.HIGH: 1,
        Severity.MEDIUM: 2,   Severity.LOW: 3, Severity.NONE: 4
    }
    cves.sort(key=lambda c: severity_order.get(c.severity, 5))

    _cache[key] = (cves, datetime.now())
    return cves
