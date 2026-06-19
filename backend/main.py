import asyncio
import uuid
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from models.scan_result import ScanRequest, ScanResult, PortState, CveMode
from scanner.port_scanner import run_scan


def _parse_cors_origins(raw_value: str | None) -> list[str]:
    if not raw_value:
        return ['http://localhost:5173', 'http://127.0.0.1:5173']
    return [origin.strip() for origin in raw_value.split(',') if origin.strip()]
CORS_ORIGINS = _parse_cors_origins(os.getenv('CORS_ORIGINS'))


# --- App setup ---

app = FastAPI(
    title="LynxMap",
    description="Network vulnerability scanner",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- In-memory scan store ---
# Key: scan_id (string UUID)
# Value: dict with status and result

scans: dict[str, dict[str, Any]] = {}


# --- Background scan runner ---

async def _run_scan_background(
    scan_id: str,
    target: str,
    port_start: int,
    port_end: int,
    timeout: float,
    cve_mode: CveMode,
) -> None:
    """
    Runs the scan and updates the scans store when done.
    """
    scans[scan_id]["status"] = "running"

    try:
        result = await run_scan(
            target=target,
            port_start=port_start,
            port_end=port_end,
            timeout=timeout,
            cve_mode=cve_mode,
        )
        scans[scan_id]["status"] = "complete"
        scans[scan_id]["result"] = result

    except Exception as e:
        scans[scan_id]["status"] = "error"
        scans[scan_id]["error"] = str(e)
        print(f"[!] Scan {scan_id} failed: {e}")


# --- Routes ---

@app.get("/")
async def root():
    return {"status": "ok", "app": "LynxMap", "version": "0.1.0"}


@app.post("/scan", status_code=202)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Kick off a new scan. Returns immediately with a scan_id.
    Poll GET /scan/{scan_id} for results.
    """
    if request.port_range_start < 1 or request.port_range_end > 65535:
        raise HTTPException(
            status_code=422,
            detail="Port range must be between 1 and 65535"
        )
    if request.port_range_start > request.port_range_end:
        raise HTTPException(
            status_code=422,
            detail="port_range_start must be less than port_range_end"
        )

    scan_id = str(uuid.uuid4())

    scans[scan_id] = {
        "status": "pending",
        "result": None,
        "error": None,
        "created_at": datetime.now().isoformat(),
        "cve_mode": request.cve_mode.value,
    }

    asyncio.create_task(
        _run_scan_background(
            scan_id=scan_id,
            target=request.target,
            port_start=request.port_range_start,
            port_end=request.port_range_end,
            timeout=request.timeout,
            cve_mode=request.cve_mode,
        )
    )

    return {
        "scan_id": scan_id,
        "status": "pending",
        "message": f"Scan started for {request.target}",
        "poll_url": f"/scan/{scan_id}",
        "cve_mode": request.cve_mode.value,
    }


@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    scan = scans[scan_id]

    if scan["status"] == "complete":
        return {"status": "complete", "result": scan["result"]}

    if scan["status"] == "error":
        return {"status": "error", "error": scan["error"]}

    return {
        "status": scan["status"],
        "scan_id": scan_id,
        "created_at": scan["created_at"],
        "cve_mode": scan.get("cve_mode", "full"),
    }


@app.get("/scans")
async def list_scans():
    summary = []

    for scan_id, scan in scans.items():
        entry = {
            "scan_id": scan_id,
            "status": scan["status"],
            "created_at": scan["created_at"],
            "cve_mode": scan.get("cve_mode", "full"),
        }

        if scan["status"] == "complete" and scan["result"]:
            result: ScanResult = scan["result"]
            entry["target"] = result.target
            entry["open_ports"] = result.open_ports
            entry["ports_scanned"] = result.ports_scanned

        summary.append(entry)

    return {"scans": summary, "total": len(summary)}


@app.delete("/scan/{scan_id}", status_code=204)
async def delete_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    del scans[scan_id]
