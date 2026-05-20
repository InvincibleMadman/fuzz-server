from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import AppConfig


@dataclass
class CoreState:
    config: AppConfig
    paths: Any
    repo: Any
    vuldocs: Any
    distill: Any
    kb: Any
    seeds: Any
    risk: Any
    history: Any
    debugger: Any
    runner: Any
    operations: Any
