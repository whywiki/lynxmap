import asyncio
import uuid
from datetime import datetime
from typing import Optional

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.scan_result import PortResult, PortState, ScanResult, Service, CveMode

from scanner.banner_grabber import grab_banner, _well_known_service

from scanner.os_fingerprint import detect_os

from vulns.cve_matcher import enrich_with_cves


# --- Constants ---

# Maximum simultaneous TCP connections
MAX_CONCURRENT = 500

# How long to wait for a response before giving up (seconds)
DEFAULT_TIMEOUT = 1.0


async def scan_port(
    host: str,
    port: int,
    semaphore: asyncio.Semaphore,
    timeout: float = DEFAULT_TIMEOUT
) -> PortResult:
    """
    Attempt a TCP connection to a single port.
    Returns a PortResult with state OPEN, CLOSED, or FILTERED.
    """
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            return PortResult(port=port, state=PortState.OPEN)

        except asyncio.TimeoutError:
            return PortResult(port=port, state=PortState.FILTERED)

        except (ConnectionRefusedError, OSError):
            return PortResult(port=port, state=PortState.CLOSED)

async def scan_host(
    target: str,
    port_start: int = 1,
    port_end: int = 1024,
    timeout: float = DEFAULT_TIMEOUT,
    cve_mode: CveMode = CveMode.FULL,
    max_concurrent: int = MAX_CONCURRENT
) -> ScanResult:
    """
    Scan all ports in range on the target host.
    Returns a complete ScanResult with all PortResults.
    """
    scan_id = str(uuid.uuid4())
    start_time = datetime.now()
    print(f"[*] Starting scan of {target} - ports {port_start}-{port_end} "
          f"(cve_mode={cve_mode.value})")

    semaphore = asyncio.Semaphore(max_concurrent)

    # --- OS Detection ---
    print(f"[*] Attempting OS detection on {target}...")
    os_guess = await detect_os(target)

    if os_guess:
        print(f"[*] OS guess: {os_guess.os_name} "
              f"(TTL={os_guess.ttl_observed}, "
              f"confidence={os_guess.confidence})")
    else:
        print(f"[*] OS detection failed (host may block ICMP)")

    ports = range(port_start, port_end + 1)

    tasks = [
        scan_port(target, port, semaphore, timeout)
        for port in ports
    ]

    results: list[PortResult] = await asyncio.gather(
        *tasks,
        return_exceptions=True
    )

    clean_results = [r for r in results if isinstance(r, PortResult)]

    end_time = datetime.now()
    open_ports = [r for r in clean_results if r.state == PortState.OPEN]

    # --- Banner grabbing ---
    print(f"[*] Grabbing banners for {len(open_ports)} open ports...")

    banner_tasks = [
        grab_banner(target, port_result.port)
        for port_result in open_ports
    ]

    banners = await asyncio.gather(*banner_tasks, return_exceptions=True)

    for port_result, banner in zip(open_ports, banners):
        if isinstance(banner, Service):
            port_result.service = banner
            version_str = f" ({banner.version})" if banner.version else ""
            print(f"[+] Port {port_result.port}/tcp OPEN - {banner.name}{version_str}")
        else:
            port_result.service = Service(
                name=_well_known_service(port_result.port),
                raw_banner=None
            )
            print(f"[+] Port {port_result.port}/tcp OPEN - "
                  f"{port_result.service.name} (no banner)")

    print(f"[*] Scan complete in {(end_time - start_time).seconds}s - "
          f"{len(open_ports)} open ports found")

    scan = ScanResult(
        scan_id=scan_id,
        target=target,
        start_time=start_time,
        end_time=end_time,
        ports_scanned=len(ports),
        open_ports=len(open_ports),
        os_guess=os_guess,
        cve_mode=cve_mode,
        results=[r for r in clean_results if r.state != PortState.CLOSED]
    )

    scan = await enrich_with_cves(scan, mode=cve_mode)
    scan.end_time = datetime.now()

    return scan

async def run_scan(
    target: str,
    port_start: int = 1,
    port_end: int = 1024,
    timeout: float = DEFAULT_TIMEOUT,
    cve_mode: CveMode = CveMode.FULL,
) -> ScanResult:
    """
    Main entry point for running a full scan.
    Called by the API and CLI.
    """
    return await scan_host(
        target=target,
        port_start=port_start,
        port_end=port_end,
        timeout=timeout,
        cve_mode=cve_mode,
    )


# --- Direct execution for testing ---
if __name__ == "__main__":
    import json

    result = asyncio.run(run_scan(
        target="scanme.nmap.org",
        port_start=1,
        port_end=1024
    ))

    print(result.model_dump_json(indent=2, exclude_none=True))
