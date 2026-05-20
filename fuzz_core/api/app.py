from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..config import load_config
from ..debugger.classifier import VulnerabilityClassifier
from ..debugger.gdb_driver import GDBDriver
from ..debugger.persistence import DebugPersistence
from ..debugger.replayer import Replayer
from ..debugger.session_manager import DebugSessionManager
from ..runner.manager import RunnerManager
from ..services.distill_service import DistillService
from ..services.history_service import HistoryService
from ..services.kb_service import KBService
from ..services.operation_log_service import OperationLogService
from ..services.risk_service import RiskService
from ..services.seed_service import SeedService
from ..services.vuldoc_service import VulDocService
from ..state import CoreState
from ..storage.path_resolver import PathResolver
from ..storage.repository import Repository


def create_app(config_path: str | None = None) -> FastAPI:
    cfg = load_config(config_path)
    paths = PathResolver(cfg.workspace.root, cfg.workspace.default_protocol)
    repo = Repository(paths.root / "fuzz_core.sqlite3")
    kb = KBService(paths, repo)
    history = HistoryService(paths, repo)
    operations = OperationLogService(paths.root)

    debugger = DebugSessionManager(
        GDBDriver(cfg.debugger.gdb_path, cfg.debugger.timeout_sec),
        Replayer(cfg.debugger.allow_network_replay),
        VulnerabilityClassifier(),
        DebugPersistence(paths, repo),
        history,
        operations=operations,
    )

    app = FastAPI(title="fuzz-core enhanced", version="0.2.2")

    if cfg.server.cors.enabled:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cfg.server.cors.allow_origins,
            allow_origin_regex=cfg.server.cors.allow_origin_regex,
            allow_credentials=cfg.server.cors.allow_credentials,
            allow_methods=cfg.server.cors.allow_methods,
            allow_headers=cfg.server.cors.allow_headers,
            expose_headers=cfg.server.cors.expose_headers,
            max_age=cfg.server.cors.max_age,
        )

    app.state.core = CoreState(
        config=cfg,
        paths=paths,
        repo=repo,
        vuldocs=VulDocService(paths, repo),
        distill=DistillService(paths, repo),
        kb=kb,
        seeds=SeedService(paths, repo, kb),
        risk=RiskService(paths),
        history=history,
        debugger=debugger,
        runner=RunnerManager(paths, debugger),
        operations=operations,
    )

    from .routers import compat, config_router, debug, jobs, offline, operations as operations_router, protocols, system

    app.include_router(config_router.router)
    app.include_router(system.router)
    app.include_router(offline.router)
    app.include_router(protocols.router)
    app.include_router(jobs.router)
    app.include_router(debug.router)
    app.include_router(operations_router.router)
    app.include_router(compat.router)
    return app
