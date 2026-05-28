import asyncio
import uuid
from datetime import datetime
from typing import Optional

import sys
import os
# We go up two levels (scanner -> backend -> root) to import our models
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.scan_result import PortResult, PortState, ScanResult, Service

from scanner.banner_grabber import grab_banner

from vulns.cve_matcher import enrich_with_cves


# --- Constants ---

# Maximum simultaneous TCP connections
MAX_CONCURRENT = 500 # we might lower it idk for now

# How long to wait for a response before giving up (seconds)
# filtered ports will wait this long
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

    The semaphore is passed in (not created here) so all port tasks
    share the same concurrency limit across the entire scan.
    """

    # Wait until a slot is free then proceed
    # When this block exits the slot is released for the next waiting task
    async with semaphore:
        try:
            # wraps a coroutine with a timeout
            # If open_connection doesn't complete within timeout seconds,
            # it raises asyncio.TimeoutError - which means FILTERED
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )

            # three-way handshake completed - port is OPEN
            # Close the connection cleanly
            # Sends RST/FIN to the server
            writer.close()

            # ensures the OS fully releases the socket
            # Without this we can leak file descriptors on long scans
            try:
                await writer.wait_closed()
            except Exception:
                pass  # Some systems don't support wait_closed cleanly

            return PortResult(port=port, state=PortState.OPEN)

        except asyncio.TimeoutError:
            # No response within timeout window
            # A firewall is silently dropping our packets
            return PortResult(port=port, state=PortState.FILTERED)

        except (ConnectionRefusedError, OSError):
            # ConnectionRefusedError = got RST back = port is CLOSED
            # OSError catches other low-level network errors
            # (unreachable host, network down, etc.)
            return PortResult(port=port, state=PortState.CLOSED)


async def scan_host(
    target: str,
    port_start: int = 1,
    port_end: int = 1024,
    timeout: float = DEFAULT_TIMEOUT,
    max_concurrent: int = MAX_CONCURRENT
) -> ScanResult:
    """
    Scan all ports in range on the target host.
    Returns a complete ScanResult with all PortResults.
    """

    scan_id = str(uuid.uuid4())
    start_time = datetime.now()

    print(f"[*] Starting scan of {target} - ports {port_start}-{port_end}")

    # Create ONE semaphore shared across all port scan tasks
    # if each task created its own semaphore,
    # the concurrency limit would have no effect
    semaphore = asyncio.Semaphore(max_concurrent)

    # Build the list of all ports to scan
    ports = range(port_start, port_end + 1)

    # Create a coroutine for every port (nothing doing anything yet)
    tasks = [
        scan_port(target, port, semaphore, timeout)
        for port in ports
    ]

    # asyncio.gather fires all tasks concurrently and collects results
    # The semaphore inside each task controls how many actually run at once
    # return_exceptions=True means if one task crashes the others keep going
    results: list[PortResult] = await asyncio.gather(
        *tasks,
        return_exceptions=True
    )

    # Filter out any exceptions that slipped through
    clean_results = [r for r in results if isinstance(r, PortResult)]

    end_time = datetime.now()
    open_ports = [r for r in clean_results if r.state == PortState.OPEN]

    # --- Banner grabbing ---
    # Grab banners concurrently for each banner
    print(f"[*] Grabbing banners for {len(open_ports)} open ports...")

    banner_tasks = [
        grab_banner(target, port_result.port)
        for port_result in open_ports
    ]

    banners = await asyncio.gather(*banner_tasks, return_exceptions=True)

    # Attach banners to their port results
    for port_result, banner in zip(open_ports, banners):
        if isinstance(banner, Service):
            port_result.service = banner
            version_str = f" ({banner.version})" if banner.version else ""
            print(f"[+] Port {port_result.port}/tcp OPEN - {banner.name}{version_str}")
        else:
            print(f"[+] Port {port_result.port}/tcp OPEN - banner grab failed")
            print(f"[*] Scan complete in {(end_time - start_time).seconds}s - "
          f"{len(open_ports)} open ports found")

    scan = ScanResult(
            scan_id=scan_id,
            target=target,
            start_time=start_time,
            end_time=end_time,
            ports_scanned=len(ports),
            open_ports=len(open_ports),
            # Only return open and filtered ports
            results=[r for r in clean_results if r.state != PortState.CLOSED]
        )

    # Enrich open ports with CVE data from NVD
    scan = await enrich_with_cves(scan)

    # Update end time to include enrichment time
    scan.end_time = datetime.now()

    return scan

async def run_scan(
    target: str,
    port_start: int = 1,
    port_end: int = 1024,
    timeout: float = DEFAULT_TIMEOUT
) -> ScanResult:
    """
    Main entry point for running a full scan.
    This is what the API and CLI will call.
    Runs port scan -> banner grabbing → CVE enrichment.
    """
    # probably more usefull later idk
    return await scan_host(
        target=target,
        port_start=port_start,
        port_end=port_end,
        timeout=timeout
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
