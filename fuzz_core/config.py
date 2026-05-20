from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field


class WorkspaceConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    root: str = "./workspace"
    default_protocol: str = "legacy-default"


class CorsConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    enabled: bool = True
    allow_origins: list[str] = Field(default_factory=lambda: [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ])
    allow_origin_regex: str | None = None
    allow_credentials: bool = True
    allow_methods: list[str] = Field(default_factory=lambda: ["GET", "POST", "PATCH", "OPTIONS"])
    allow_headers: list[str] = Field(default_factory=lambda: ["Authorization", "Content-Type", "X-Operation-Id"])
    expose_headers: list[str] = Field(default_factory=list)
    max_age: int = 3600


class ServerConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    host: str = "127.0.0.1"
    port: int = 8000
    cors: CorsConfig = Field(default_factory=CorsConfig)


class LLMConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    provider: str = "local"
    model: str = "local-rule-based"
    base_url: str = ""
    api_key: str = ""
    api_key_env: str = "FUZZ_CORE_LLM_API_KEY"
    timeout_sec: int = 120
    models: dict[str, str] = Field(default_factory=dict)


class PathConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    afl_fuzz: str = "afl-fuzz"
    afl_showmap: str = "afl-showmap"
    preeny_desock: str = ""


class DebuggerConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    gdb_path: str = "gdb"
    timeout_sec: int = 20
    allow_network_replay: bool = False


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    workspace: WorkspaceConfig = Field(default_factory=WorkspaceConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    paths: PathConfig = Field(default_factory=PathConfig)
    debugger: DebuggerConfig = Field(default_factory=DebuggerConfig)

    @property
    def llm_api_key(self) -> str:
        return self.llm.api_key or os.getenv(self.llm.api_key_env, "")

    def llm_model_for(self, task: str, default: str | None = None) -> str:
        return self.llm.models.get(task) or default or self.llm.model


def _normalize_legacy_config(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize both the new v2 schema and the original fuzz-core config.yaml.

    Accepted legacy fields include:
      server.http.host / server.http.port -> server.host / server.port
      server.cors.*                       -> server.cors.*
      paths.workspace                     -> workspace.root
      afl.afl_binary                      -> paths.afl_fuzz
      runtime.preeny_desock_path          -> paths.preeny_desock
      llm.api_key                         -> llm.api_key
      llm.models.*                        -> llm.models.*
    """
    normalized = deepcopy(data or {})

    server = normalized.get("server") or {}
    if isinstance(server, dict):
        http = server.get("http") if isinstance(server.get("http"), dict) else {}
        cors = server.get("cors") if isinstance(server.get("cors"), dict) else None
        normalized["server"] = {
            **server,
            "host": server.get("host") or http.get("host") or "127.0.0.1",
            "port": server.get("port") or http.get("port") or 8000,
        }
        if cors is not None:
            normalized["server"]["cors"] = cors

    paths = normalized.get("paths") or {}
    workspace = normalized.get("workspace") or {}
    if isinstance(paths, dict) and isinstance(workspace, dict):
        workspace_root = workspace.get("root") or paths.get("workspace") or paths.get("workspace_root")
        if workspace_root:
            workspace["root"] = workspace_root
        workspace.setdefault("default_protocol", "legacy-default")
        normalized["workspace"] = workspace

    afl = normalized.get("afl") or {}
    runtime = normalized.get("runtime") or {}
    new_paths = normalized.get("paths") if isinstance(normalized.get("paths"), dict) else {}
    if isinstance(afl, dict):
        new_paths.setdefault("afl_fuzz", afl.get("afl_binary") or "afl-fuzz")
    if isinstance(runtime, dict):
        new_paths.setdefault("preeny_desock", runtime.get("preeny_desock_path") or "")
    normalized["paths"] = new_paths

    llm = normalized.get("llm") or {}
    if isinstance(llm, dict):
        models = llm.get("models") or {}
        if isinstance(models, dict) and not llm.get("model"):
            llm["model"] = (
                models.get("protocol_extract")
                or models.get("seed_generation")
                or models.get("risk_analysis")
                or models.get("debug_reasoning")
                or "local-rule-based"
            )
        normalized["llm"] = llm

    normalized.setdefault("workspace", {})
    normalized.setdefault("server", {})
    normalized.setdefault("llm", {})
    normalized.setdefault("paths", {})
    normalized.setdefault("debugger", {})
    return normalized


def load_config(path: str | None = None) -> AppConfig:
    config_path = path or os.getenv("FUZZ_CORE_CONFIG", "config.yaml")
    p = Path(config_path)
    if p.exists():
        data: dict[str, Any] = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    else:
        data = {}
    return AppConfig.model_validate(_normalize_legacy_config(data))


def save_config(cfg: AppConfig, path: str | None = None) -> None:
    config_path = Path(path or os.getenv("FUZZ_CORE_CONFIG", "config.yaml"))
    config_path.write_text(
        yaml.safe_dump(cfg.model_dump(), allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


class ConfigStore:
    """Compatibility wrapper for older imports.

    New code should use load_config()/save_config(). Keeping this lightweight
    wrapper prevents older scripts from crashing during migration.
    """

    def __init__(self, path: str | None = None):
        self.path = path
        self._cfg = load_config(path)

    def get(self) -> AppConfig:
        return self._cfg

    def set(self, cfg: AppConfig) -> None:
        self._cfg = cfg
        save_config(cfg, self.path)

    def update(self, patch: dict[str, Any]) -> AppConfig:
        data = self._cfg.model_dump()
        _deep_merge(data, patch)
        self._cfg = AppConfig.model_validate(data)
        save_config(self._cfg, self.path)
        return self._cfg


def _deep_merge(dst: dict[str, Any], src: dict[str, Any]) -> None:
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(dst.get(key), dict):
            _deep_merge(dst[key], value)
        else:
            dst[key] = value
