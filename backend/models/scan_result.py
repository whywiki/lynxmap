from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum


# --- Enums ---

class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


# --- CVE ---

class CVE(BaseModel):
    cve_id: str                          # e.g. "CVE-2023-38408"
    description: str                     # human readable summary
    severity: Severity                   # CRITICAL / HIGH / MEDIUM / LOW / NONE
    cvss_score: Optional[float] = None  # e.g. 9.8  (can be missing in NVD data)
    published_date: Optional[str] = None


# --- Service ---

class Service(BaseModel):
    name: str                            # e.g. "OpenSSH"
    version: Optional[str] = None       # e.g. "8.9p1"
    raw_banner: Optional[str] = None    # the raw string grabbed from the port
    cves: list[CVE] = Field(default_factory=list)


# --- Port ---

class PortResult(BaseModel):
    port: int                            # e.g. 22
    state: PortState                     # open / closed / filtered
    protocol: str = "tcp"
    service: Optional[Service] = None   # None if we couldn't grab a banner


# --- OS Detection ---

class OSGuess(BaseModel):
    os_name: str                         # e.g. "Linux", "Windows", "macOS"
    ttl_observed: int                    # the TTL value we actually saw
    confidence: str                      # "high" / "medium" / "low"


# --- Top level Scan Result ---

class ScanResult(BaseModel):
    scan_id: str                         # unique ID for this scan
    target: str                          # IP address that was scanned
    start_time: datetime
    end_time: Optional[datetime] = None
    ports_scanned: int = 0              # how many ports we tried
    open_ports: int = 0                 # how many came back open
    os_guess: Optional[OSGuess] = None
    results: list[PortResult] = Field(default_factory=list)


# --- Scan Request --- (what the user sends to kick off a scan)

class ScanRequest(BaseModel):
    target: str                          # IP address to scan
    port_range_start: int = 1
    port_range_end: int = 1024           # default to well-known ports
    timeout: float = 1.0                 # seconds to wait per port
