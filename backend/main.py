import asyncio
import uuid
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from models.scan_result import ScanRequest, ScanResult, PortState
from scanner.port_scanner import run_scan


# --- App setup ---

app = FastAPI(
    title="LynxMap",
    description="Network vulnerability scanner",
    version="0.1.0"
)

# CORS
# browsers block cross-origin requests by default
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- In-memory scan store ---
# Key: scan_id (string UUID)
# Value: dict with status and result
#
# Structure of each entry:
# {
#   "status": "pending" | "running" | "complete" | "error",
#   "result": ScanResult | None,
#   "error": str | None,
#   "created_at": datetime
# }

scans: dict[str, dict[str, Any]] = {}


# --- Background scan runner ---

async def _run_scan_background(
    scan_id: str,
    target: str,
    port_start: int,
    port_end: int,
    timeout: float
) -> None:
    """
    Runs the scan and updates the scans store when done.
    This runs in the background - the HTTP request that triggered
    it has already returned a scan_id to the client.
    """
    scans[scan_id]["status"] = "running"

    try:
        result = await run_scan(
            target=target,
            port_start=port_start,
            port_end=port_end,
            timeout=timeout
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
    """Health check - confirms the API is running."""
    return {"status": "ok", "app": "LynxMap", "version": "0.1.0"}


@app.post("/scan", status_code=202)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Kick off a new scan.

    Returns immediately with a scan_id.
    The scan runs in the background.
    Poll GET /scan/{scan_id} for results.

    202 Accepted means "I got your request and I'm working on it"
    as opposed to 200 OK which means "here's your result right now"
    """

    # Validate port range
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

    # Register scan in store before starting background task
    # so GET /scan/{id} can return "pending" immediately
    scans[scan_id] = {
        "status": "pending",
        "result": None,
        "error": None,
        "created_at": datetime.now().isoformat()
    }

    # BackgroundTasks is FastAPI's built-in way to run something
    # after the response has been sent
    # We use asyncio.create_task instead because our scanner is
    # async and BackgroundTasks works better with sync functions
    asyncio.create_task(
        _run_scan_background(
            scan_id=scan_id,
            target=request.target,
            port_start=request.port_range_start,
            port_end=request.port_range_end,
            timeout=request.timeout
        )
    )

    return {
        "scan_id": scan_id,
        "status": "pending",
        "message": f"Scan started for {request.target}",
        "poll_url": f"/scan/{scan_id}"
    }


@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    """
    Get the status and results of a scan by ID.

    While running: returns status "running"
    When complete: returns full ScanResult
    On error: returns status "error" with message
    """

    if scan_id not in scans:
        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found"
        )

    scan = scans[scan_id]

    if scan["status"] == "complete":
        return {
            "status": "complete",
            "result": scan["result"]
        }

    if scan["status"] == "error":
        return {
            "status": "error",
            "error": scan["error"]
        }

    # Still pending or running
    return {
        "status": scan["status"],
        "scan_id": scan_id,
        "created_at": scan["created_at"]
    }


@app.get("/scans")
async def list_scans():
    """
    List all scans in the current session.
    Returns summary info without full results.
    """
    summary = []

    for scan_id, scan in scans.items():
        entry = {
            "scan_id": scan_id,
            "status": scan["status"],
            "created_at": scan["created_at"]
        }

        # Add target and open port count if scan is complete
        if scan["status"] == "complete" and scan["result"]:
            result: ScanResult = scan["result"]
            entry["target"] = result.target
            entry["open_ports"] = result.open_ports
            entry["ports_scanned"] = result.ports_scanned

        summary.append(entry)

    return {"scans": summary, "total": len(summary)}


@app.delete("/scan/{scan_id}", status_code=204)
async def delete_scan(scan_id: str):
    """
    Remove a scan from the store.
    Returns 204 No Content on success.
    """
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    del scans[scan_id]
