import httpx
import asyncio
import os
import sys
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.scan_result import CVE, Severity
from dotenv import load_dotenv

# Load .env file so os.environ can see NVD_API_KEY
load_dotenv()


# --- Config ---

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# How many results to request from NVD per query
MAX_RESULTS = 20

# Rate limiting - be polite to the API
# Without key: 5 requests per 30s -> wait 6s between requests
# With key:    50 requests per 30s -> wait 0.6s between requests
REQUEST_DELAY = 0.6  # seconds between API calls

# CPE vendor/product mappings for common services
# Format: "Our service name" -> (vendor, product)
# These match NVD's official CPE naming conventions
CPE_MAPPINGS = {
    "openssh":      ("openbsd",  "openssh"),
    "apache httpd": ("apache",   "http_server"),
    "nginx":        ("nginx",    "nginx"),
    "mysql":        ("mysql",    "mysql"),
    "postgresql":   ("postgresql", "postgresql"),
    "proftpd":      ("proftpd", "proftpd"),
    "vsftpd":       ("vsftpd",  "vsftpd"),
    "microsoft iis":("microsoft", "internet_information_services"),
    "samba":        ("samba",   "samba"),
    "openssl":      ("openssl", "openssl"),
}


# --- In-memory cache ---
# Key: "ServiceName version" e.g. "OpenSSH 6.6.1p1"
# Value: list of CVE objects
# We also store a timestamp so we could expire old entries if needed

_cache: dict[str, tuple[list[CVE], datetime]] = {}
CACHE_TTL_HOURS = 24  # cache results for 24 hours


def _cache_key(service_name: str, version: str | None) -> str:
    """Build a consistent cache key from service name and version."""
    return f"{service_name.lower()}:{version or 'unknown'}"


def _is_cache_valid(timestamp: datetime) -> bool:
    """Check if a cached result is still fresh."""
    return datetime.now() - timestamp < timedelta(hours=CACHE_TTL_HOURS)


def _parse_severity(score: float | None, severity_str: str | None) -> Severity:
    """
    Convert a CVSS score or severity string into our Severity enum.
    NVD provides both - we prefer the string.
    """
    if severity_str:
        severity_str = severity_str.upper()
        if severity_str in ("CRITICAL",):
            return Severity.CRITICAL
        elif severity_str in ("HIGH",):
            return Severity.HIGH
        elif severity_str in ("MEDIUM",):
            return Severity.MEDIUM
        elif severity_str in ("LOW",):
            return Severity.LOW

    # Fall back to score-based calculation
    if score is not None:
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score > 0:
            return Severity.LOW

    return Severity.NONE


def _parse_cvss_metrics(metrics: dict) -> tuple[float | None, Severity]:
    """
    Extract CVSS score and severity from the metrics block.

    NVD has multiple CVSS versions (v2, v3.0, v3.1, v4.0).
    We prefer v3.1 > v3.0 > v4.0 > v2 in that order because
    v3.1 is the most widely used standard right now.
    """
    score = None
    severity = Severity.NONE

    # Try CVSS v3.1 first
    v31 = metrics.get("cvssMetricV31", [])
    if v31:
        data = v31[0].get("cvssData", {})
        score = data.get("baseScore")
        severity = _parse_severity(score, data.get("baseSeverity"))
        return score, severity

    # Fall back to v3.0
    v30 = metrics.get("cvssMetricV30", [])
    if v30:
        data = v30[0].get("cvssData", {})
        score = data.get("baseScore")
        severity = _parse_severity(score, data.get("baseSeverity"))
        return score, severity

    # Fall back to v2
    v2 = metrics.get("cvssMetricV2", [])
    if v2:
        data = v2[0].get("cvssData", {})
        score = data.get("baseScore")
        severity = _parse_severity(score, None)  # v2 has no severity string
        return score, severity

    return None, Severity.NONE


def _parse_cve_item(item: dict) -> CVE | None:
    """
    Parse a single CVE item from the NVD API response into our CVE model.
    Returns None if the item is malformed or missing critical fields.
    """
    try:
        cve_data = item.get("cve", {})

        cve_id = cve_data.get("id", "")
        if not cve_id:
            return None

        # Get English description
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available"
        )

        # Truncate very long descriptions
        if len(description) > 500:
            description = description[:497] + "..."

        # Parse CVSS metrics
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

async def fetch_cves_for_service(
    service_name: str,
    version: str | None,
    delay: float = REQUEST_DELAY
) -> list[CVE]:
    """
    Query the NVD API for CVEs affecting a given service and version.

    Strategy:
    1. Try CPE-based query first (version-aware, most accurate)
    2. Fall back to keyword search if CPE returns nothing

    Results are cached to avoid redundant API calls.
    """

    key = _cache_key(service_name, version)

    # Check cache first
    if key in _cache:
        cached_cves, timestamp = _cache[key]
        if _is_cache_valid(timestamp):
            print(f"  [cache] {service_name} {version or ''} — "
                  f"{len(cached_cves)} CVEs (cached)")
            return cached_cves

    await asyncio.sleep(delay)

    api_key = os.environ.get("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key else {}

    cves = []

    # --- Strategy 1: CPE query ---
    service_key = service_name.lower()
    if version and service_key in CPE_MAPPINGS:
        vendor, product = CPE_MAPPINGS[service_key]

        # Clean version — strip ubuntu/debian packaging suffixes
        # "6.6.1p1" stays as is, "2.4.7+dfsg" → "2.4.7"
        clean_version = version.split("+")[0].split("~")[0]

        cpe_name = f"cpe:2.3:a:{vendor}:{product}:{clean_version}:*:*:*:*:*:*:*"

        print(f"  [nvd] CPE query: '{cpe_name}'")

        params = {
            "cpeName": cpe_name,
            "resultsPerPage": MAX_RESULTS,
        }

        cves = await _do_nvd_request(params, headers)
        print(f"  [nvd] CPE found {len(cves)} CVEs")

    # --- Strategy 2: Keyword fallback ---
    # Triggers if CPE found nothing OR service has no CPE mapping
    if not cves:
        if version:
            clean_version = version.split("p")[0].split("-")[0].split("+")[0]
            query = f"{service_name} {clean_version}"
        else:
            query = service_name

        print(f"  [nvd] Keyword fallback: '{query}'")

        params = {
            "keywordSearch": query,
            "resultsPerPage": MAX_RESULTS,
        }

        await asyncio.sleep(delay)  # extra delay for second request
        cves = await _do_nvd_request(params, headers)
        print(f"  [nvd] Keyword found {len(cves)} CVEs")

    # Sort by severity — CRITICAL first
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.NONE: 4
    }
    cves.sort(key=lambda c: severity_order.get(c.severity, 5))

    _cache[key] = (cves, datetime.now())
    return cves


async def _do_nvd_request(
    params: dict,
    headers: dict
) -> list[CVE]:
    """
    Execute a single NVD API request and return parsed CVEs.
    Extracted so both CPE and keyword strategies share the same logic.
    """
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(
                NVD_BASE_URL,
                params=params,
                headers=headers
            )
            response.raise_for_status()
            data = response.json()

    except httpx.HTTPStatusError as e:
        print(f"  [nvd] HTTP error {e.response.status_code}")
        return []
    except httpx.RequestError as e:
        print(f"  [nvd] Request failed: {e}")
        return []
    except Exception as e:
        print(f"  [nvd] Unexpected error: {e}")
        return []

    vulnerabilities = data.get("vulnerabilities", [])
    cves = []

    for item in vulnerabilities:
        cve = _parse_cve_item(item)
        if cve:
            cves.append(cve)

    return cves
