import asyncio
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.scan_result import PortResult, ScanResult
from vulns.nvd_client import fetch_cves_for_service


async def enrich_with_cves(scan_result: ScanResult) -> ScanResult:
    """
    For each open port with a known service, fetch CVEs from NVD
    and attach them to the service object.

    Modifies the scan_result in place and returns it.
    """

    open_with_service = [
        port for port in scan_result.results
        if port.service and port.service.name not in ("Unknown", None)
    ]

    if not open_with_service:
        print("[*] No identifiable services found - skipping CVE lookup")
        return scan_result

    print(f"[*] Looking up CVEs for {len(open_with_service)} services...")

    # We query NVD sequentially (not all at once) to respect rate limits
    # Parallel CVE lookups would immediately trigger rate limiting
    for port_result in open_with_service:
        service = port_result.service
        cves = await fetch_cves_for_service(
            service_name=service.name,
            version=service.version
        )
        service.cves = cves

    return scan_result
