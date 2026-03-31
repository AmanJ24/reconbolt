"""Scan CRUD and execution endpoints."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from reconbolt.engine.events import EventEmitter, ScanEvent
from reconbolt.engine.orchestrator import ScanOrchestrator
from reconbolt.models.scan import ScanConfig, ScanResult, ScanStatus

router = APIRouter()

# In-memory storage for scan results (swap with DB in production)
_scan_store: dict[str, ScanResult] = {}
_active_tasks: dict[str, asyncio.Task] = {}


@router.post("/", response_model=dict)
async def start_scan(config: ScanConfig) -> dict[str, Any]:
    """Start a new reconnaissance scan.

    Returns immediately with a scan_id. Use the WebSocket endpoint
    or GET /api/scans/{scan_id} to monitor progress.
    """
    emitter = EventEmitter()
    orchestrator = ScanOrchestrator(config, emitter)
    scan_id = orchestrator.result.scan_id

    # Store initial result
    _scan_store[scan_id] = orchestrator.result

    # Run scan in background
    async def run_scan():
        result = await orchestrator.run()
        _scan_store[scan_id] = result

    task = asyncio.create_task(run_scan())
    _active_tasks[scan_id] = task

    return {
        "scan_id": scan_id,
        "target": config.target,
        "status": "running",
        "message": f"Scan started. Monitor at GET /api/scans/{scan_id}",
    }


@router.get("/", response_model=list[dict])
async def list_scans() -> list[dict[str, Any]]:
    """List all scans (recent first)."""
    scans = []
    for scan_id, result in sorted(_scan_store.items(), key=lambda x: x[1].started_at, reverse=True):
        scans.append({
            "scan_id": scan_id,
            "target": result.target,
            "status": result.status.value,
            "started_at": result.started_at.isoformat(),
            "risk_score": result.summary.risk_score,
            "risk_level": result.summary.risk_level,
        })
    return scans


@router.get("/{scan_id}")
async def get_scan(scan_id: str) -> dict[str, Any]:
    """Get full results of a specific scan."""
    if scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return _scan_store[scan_id].model_dump()


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str) -> dict[str, str]:
    """Delete a scan and cancel if running."""
    if scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    # Cancel if still running
    if scan_id in _active_tasks:
        task = _active_tasks[scan_id]
        if not task.done():
            task.cancel()
        del _active_tasks[scan_id]

    del _scan_store[scan_id]
    return {"message": f"Scan {scan_id} deleted"}


@router.websocket("/{scan_id}/ws")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for real-time scan progress.

    Connect before or after starting a scan to receive live events.
    """
    await websocket.accept()

    # Create a new scan with events streamed via WebSocket
    event_queue: asyncio.Queue[ScanEvent] = asyncio.Queue()

    async def event_handler(event: ScanEvent):
        await event_queue.put(event)

    try:
        # Wait for scan config from client
        data = await websocket.receive_json()
        config = ScanConfig(**data)

        # Setup emitter that pushes to our queue
        emitter = EventEmitter()

        def sync_handler(event: ScanEvent):
            asyncio.get_event_loop().call_soon_threadsafe(event_queue.put_nowait, event)

        emitter.on_event(sync_handler)

        # Run scan in background
        orchestrator = ScanOrchestrator(config, emitter)
        _scan_store[orchestrator.result.scan_id] = orchestrator.result
        scan_task = asyncio.create_task(orchestrator.run())

        # Stream events to WebSocket
        while not scan_task.done() or not event_queue.empty():
            try:
                event = await asyncio.wait_for(event_queue.get(), timeout=0.5)
                await websocket.send_json(event.to_dict())
            except asyncio.TimeoutError:
                continue

        # Send final result
        result = scan_task.result()
        _scan_store[result.scan_id] = result
        await websocket.send_json({
            "phase": "completed",
            "level": "success",
            "message": "Scan complete",
            "progress": 100.0,
            "result": result.model_dump(mode="json"),
        })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"phase": "error", "level": "error", "message": str(e)})
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
