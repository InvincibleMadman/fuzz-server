from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, WebSocket

from ...debugger.models import DebugRequest, TargetConfig
from ...models import ApiResponse

router = APIRouter()


def _stable_manual_artifact_id(path: Path) -> str:
    payload = f"manual:{path.resolve(strict=False)}".encode("utf-8")
    return "artifact-" + hashlib.sha256(payload).hexdigest()[:16]


def _operation_id(request: Request, body: dict | None = None) -> str | None:
    return (body or {}).get("operation_id") or request.headers.get("x-operation-id")


@router.get("/api/v1/debug/candidates")
def debug_candidates(request: Request, job_id: str | None = None):
    """Return crash seed paths discovered from fuzz jobs for UI selection.

    This endpoint does not start GDB. It exposes job_id/artifact_id/seed_path/target
    so the frontend can let a user select a seed and explicitly call
    /api/v1/debug/sessions.
    """
    return ApiResponse(data={"job_id": job_id, "items": request.app.state.core.runner.debug_candidates(job_id)}).model_dump()


@router.post("/api/v1/debug/sessions")
def create_debug_session(request: Request, body: dict):
    protocol = body.get("protocol") or "legacy-default"
    artifact_path = body.get("artifact_path") or body.get("seed_path")
    if not artifact_path:
        raise HTTPException(status_code=400, detail="artifact_path or seed_path is required")
    p = Path(artifact_path)
    if not p.exists() or not p.is_file():
        raise HTTPException(status_code=404, detail=f"seed file not found: {artifact_path}")

    target_body = body.get("target") or {}
    target_body.setdefault("protocol", protocol)
    target = TargetConfig.model_validate(target_body)

    req = DebugRequest(
        protocol=protocol,
        artifact_path=str(p),
        artifact_id=body.get("artifact_id") or _stable_manual_artifact_id(p),
        job_id=body.get("job_id"),
        operation_id=_operation_id(request, body),
        kb_entry_ids=body.get("kb_entry_ids") or [],
        source_doc_ids=body.get("source_doc_ids") or [],
        target=target,
    )
    result = request.app.state.core.debugger.run(req)
    return ApiResponse(data=result).model_dump()


@router.post("/api/v1/debug/sessions/batch")
def create_debug_sessions_batch(request: Request, body: dict):
    protocol = body.get("protocol") or "legacy-default"
    seed_dir = body.get("seed_dir")
    if not seed_dir:
        raise HTTPException(status_code=400, detail="seed_dir is required")
    root = Path(seed_dir)
    if not root.exists() or not root.is_dir():
        raise HTTPException(status_code=404, detail=f"seed_dir not found: {seed_dir}")

    glob_pattern = body.get("glob") or "*"
    recursive = bool(body.get("recursive", False))
    max_cases = int(body.get("max_cases") or 50)
    iterator = root.rglob(glob_pattern) if recursive else root.glob(glob_pattern)
    files = [p for p in sorted(iterator) if p.is_file() and not p.name.startswith(".") and p.stat().st_size > 0][:max_cases]

    target_body = body.get("target") or {}
    target_body.setdefault("protocol", protocol)
    target = TargetConfig.model_validate(target_body)

    base_op = _operation_id(request, body)
    items = []
    for idx, p in enumerate(files):
        case_op = f"{base_op}-{idx:04d}" if base_op else None
        req = DebugRequest(
            protocol=protocol,
            artifact_path=str(p),
            artifact_id=_stable_manual_artifact_id(p),
            job_id=body.get("job_id"),
            operation_id=case_op,
            source_doc_ids=body.get("source_doc_ids") or [],
            kb_entry_ids=body.get("kb_entry_ids") or [],
            target=target,
        )
        items.append(request.app.state.core.debugger.run(req))

    return ApiResponse(data={
        "protocol": request.app.state.core.paths.protocol(protocol),
        "seed_dir": str(root),
        "glob": glob_pattern,
        "recursive": recursive,
        "count": len(items),
        "items": items,
    }).model_dump()


@router.get("/api/v1/debug/sessions/{session_id}")
def get_debug_session(session_id: str, request: Request):
    session = request.app.state.core.debugger.persistence.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="debug session not found")
    return ApiResponse(data=session).model_dump()


@router.get("/api/v1/debug/sessions/{session_id}/logs/tail")
def debug_session_logs_tail(session_id: str, request: Request, since: int = 0, limit: int = 200):
    session = request.app.state.core.debugger.persistence.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="debug session not found")
    op_id = session.get("operation_id") or (session.get("debug_report") or {}).get("operation_id") or session_id
    return ApiResponse(data=request.app.state.core.operations.tail(op_id, since, limit)).model_dump()


@router.websocket("/api/v1/debug/sessions/{session_id}/logs/ws")
async def debug_session_logs_ws(websocket: WebSocket, session_id: str):
    await websocket.accept()
    session = websocket.app.state.core.debugger.persistence.get(session_id)
    if not session:
        await websocket.send_json({"type": "error", "message": "debug session not found"})
        await websocket.close()
        return
    op_id = session.get("operation_id") or (session.get("debug_report") or {}).get("operation_id") or session_id
    service = websocket.app.state.core.operations
    since = 0
    try:
        while True:
            payload = service.tail(op_id, since=since, limit=100)
            since = payload.get("next_seq", since)
            await websocket.send_json({"type": "debug_session_logs", "session_id": session_id, "data": payload})
            if payload.get("status") in {"finished", "failed"}:
                break
            await asyncio.sleep(1.0)
    finally:
        await websocket.close()


@router.get("/api/v1/protocols/{protocol}/debug/sessions")
def list_protocol_debug_sessions(protocol: str, request: Request, coarse_type: str | None = None, limit: int = 50, offset: int = 0):
    proto = request.app.state.core.paths.protocol(protocol)
    items = request.app.state.core.debugger.persistence.list(proto, coarse_type=coarse_type, limit=limit, offset=offset)
    return ApiResponse(data={"protocol": proto, "coarse_type": coarse_type, "limit": limit, "offset": offset, "items": items}).model_dump()
