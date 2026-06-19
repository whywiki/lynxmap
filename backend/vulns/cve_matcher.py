import asyncio
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.scan_result import PortResult, ScanResult, CveMode
from vulns.nvd_client import fetch_cves_for_service


async def enrich_with_cves(scan_result: ScanResult, mode: CveMode = CveMode.FULL) -> ScanResult:
    """
    For each open port with a known service, fetch CVEs from NVD
    and attach them to the service object.

    `mode` controls lookup depth:
      SKIP  - skips all NVD calls, ports will have empty cves lists
      QUICK - one attempt per service, no name-only fallback
      FULL  - default: retries + all three strategies

    Modifies scan_result in place and returns it.
    """
    if mode == CveMode.SKIP:
        print("[*] CVE lookup skipped (mode=skip)")
        return scan_result

    open_with_service = [
        port for port in scan_result.results
        if port.service and port.service.name not in ("Unknown", None)
    ]

    if not open_with_service:
        print("[*] No identifiable services found - skipping CVE lookup")
        return scan_result

    print(f"[*] Looking up CVEs for {len(open_with_service)} services (mode={mode.value})...")

    # Sequential to respect NVD rate limits - parallel would immediately trigger 429s
    for port_result in open_with_service:
        service = port_result.service
        cves = await fetch_cves_for_service(
            service_name=service.name,
            version=service.version,
            mode=mode,
        )
        service.cves = cves

    return scan_result
