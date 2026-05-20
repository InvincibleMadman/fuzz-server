from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, Field
from datetime import datetime, timezone

COARSE_TYPES = [
    "memory-corruption", "bounds-check", "null-deref", "use-after-free",
    "integer-issue", "parser-state", "auth-logic", "resource-exhaustion",
    "protocol-state-machine", "unknown",
]

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

class ApiResponse(BaseModel):
    ok: bool = True
    message: str = "ok"
    data: Any = None

class CompatResponse(BaseModel):
    is_success: bool = True
    msg: str = "ok"
    data: Any = None

class VulDocRecord(BaseModel):
    doc_id: str
    protocol: str
    filename: str
    raw_path: str
    sha256: str
    size: int
    source: str = "upload"
    source_type: str = "vuldoc"
    created_at: str = Field(default_factory=now_iso)
    metadata: dict[str, Any] = Field(default_factory=dict)

class KBEntry(BaseModel):
    entry_id: str
    protocol: str
    doc_id: str | None = None
    title: str = "Untitled vulnerability"
    summary: str = ""
    source_type: str = "vuldoc"
    source_ref: str = ""
    affected_versions: list[str] = Field(default_factory=list)
    vuln_type: str = "unknown"
    coarse_type: str = "unknown"
    cwe: str = ""
    trigger_condition: str = ""
    input_shape: str = ""
    message_fields: list[str] = Field(default_factory=list)
    sink_function: str = ""
    file_path: str = ""
    function_name: str = ""
    evidence: list[str] = Field(default_factory=list)
    poc_hint: str = ""
    fix_hint: str = ""
    confidence: float = 0.4
    tags: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=now_iso)
    metadata: dict[str, Any] = Field(default_factory=dict)

class SeedGenerationResult(BaseModel):
    protocol: str
    generation_mode: Literal["spec_only","spec_plus_kb","kb_only_fallback","raw_doc_fallback","degraded_no_spec"]
    seeds: list[dict[str, Any]]
    used_spec_id: str | None = None
    used_vuldoc_ids: list[str] = Field(default_factory=list)
    used_kb_entry_ids: list[str] = Field(default_factory=list)
    confidence: float = 0.3
    warnings: list[str] = Field(default_factory=list)
    output_dir: str | None = None
    created_at: str = Field(default_factory=now_iso)

class VulnHistoryRecord(BaseModel):
    record_id: str
    protocol: str
    coarse_type: str = "unknown"
    vuln_type: str = "unknown"
    cwe: str = ""
    title: str = ""
    root_cause: str = ""
    direct_cause: str = ""
    crash_signature: str = ""
    file: str = ""
    function: str = ""
    line: int | None = None
    stack_summary: str = ""
    repro_steps: list[str] = Field(default_factory=list)
    poc_concept: str = ""
    fix_suggestion: str = ""
    confidence: float = 0.4
    debug_session_id: str | None = None
    artifact_id: str | None = None
    source_doc_ids: list[str] = Field(default_factory=list)
    kb_entry_ids: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=now_iso)
    metadata: dict[str, Any] = Field(default_factory=dict)
