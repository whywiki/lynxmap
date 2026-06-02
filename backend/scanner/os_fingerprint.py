import asyncio
import subprocess
import re
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.scan_result import OSGuess


# --- TTL fingerprint map ---
# Maps starting TTL -> OS family
# We find which starting TTL the observed value is closest to

TTL_MAP = [
    (64,  "Linux / macOS"),
    (128, "Windows"),
    (255, "Cisco / Network Device"),
]


def _identify_os_from_ttl(observed_ttl: int) -> tuple[str, str]:
    """
    Given an observed TTL value, return the most likely OS name
    and a confidence level.

    Logic: find the smallest standard starting TTL that is >= observed TTL.
    The difference between starting TTL and observed TTL is the hop count.

    Confidence is based on how many hops away the machine is:
    - 0-5 hops  -> high confidence (TTL barely decremented)
    - 6-15 hops -> medium confidence
    - 16+ hops  -> low confidence (TTL has decremented a lot, less certain)
    """

    # Find the closest starting TTL that is >= observed TTL
    best_match = None
    best_diff = float('inf')

    for starting_ttl, os_name in TTL_MAP:
        if starting_ttl >= observed_ttl:
            diff = starting_ttl - observed_ttl
            if diff < best_diff:
                best_diff = diff
                best_match = (os_name, starting_ttl)

    if not best_match:
        return "Unknown", "low"

    os_name, _ = best_match
    hop_count = best_diff

    if hop_count <= 5:
        confidence = "high"
    elif hop_count <= 15:
        confidence = "medium"
    else:
        confidence = "low"

    return os_name, confidence


def _parse_ttl_from_ping(ping_output: str) -> int | None:
    """
    Extract TTL value from ping command output.

    Linux ping output looks like:
      64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms

    macOS ping output looks like:
      64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.052 ms

    Both have ttl= so the same regex works on both platforms.
    """
    match = re.search(r'ttl=(\d+)', ping_output, re.IGNORECASE)
    if match:
        return int(match.group(1))
    return None


async def detect_os(host: str, timeout: float = 3.0) -> OSGuess | None:
    """
    Attempt OS detection via TTL fingerprinting.

    Sends a single ping to the target and reads the TTL from the response.
    Returns an OSGuess if successful, None if the host doesn't respond to ping.

    Note: some hosts block ICMP (ping) entirely - in that case we return None
    rather than guessing. A None result doesn't mean the host is down,
    just that it blocks ping.
    """

    # Build ping command
    # -c 1 = send only 1 packet
    # We use different timeout flags per platform
    if sys.platform == "darwin":
        # macOS: -W in milliseconds
        cmd = ["ping", "-c", "1", "-W", "3000", host]
    else:
        # Linux: -W in seconds
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]

    try:
        # asyncio.create_subprocess_exec runs a command asynchronously
        # stdout=PIPE captures the output so we can parse it
        # stderr=PIPE captures errors so they don't print to terminal
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Wait for ping to complete with a timeout
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout + 1
            )
        except asyncio.TimeoutError:
            process.kill()
            return None

        output = stdout.decode("utf-8", errors="ignore")

        # Parse TTL from output
        ttl = _parse_ttl_from_ping(output)

        if ttl is None:
            # Ping succeeded but no TTL found — shouldn't happen
            # but handle gracefully
            return None

        os_name, confidence = _identify_os_from_ttl(ttl)

        return OSGuess(
            os_name=os_name,
            ttl_observed=ttl,
            confidence=confidence
        )

    except FileNotFoundError:
        # ping command not found — shouldn't happen on Linux/Mac
        print("[!] ping command not found")
        return None
    except Exception as e:
        print(f"[!] OS detection failed: {e}")
        return None
