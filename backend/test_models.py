from models.scan_result import ScanResult, PortResult, PortState, Service, CVE, Severity
from datetime import datetime
import uuid

# Build a fake scan result manually to prove the models work
test_scan = ScanResult(
    scan_id=str(uuid.uuid4()),
    target="192.168.1.1",
    start_time=datetime.now(),
    ports_scanned=1024,
    open_ports=2,
    results=[
        PortResult(
            port=22,
            state=PortState.OPEN,
            service=Service(
                name="OpenSSH",
                version="8.9p1",
                raw_banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
                cves=[
                    CVE(
                        cve_id="CVE-2023-38408",
                        description="Remote code execution in ssh-agent",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8
                    )
                ]
            )
        )
    ]
)

print(test_scan.model_dump_json(indent=2))
