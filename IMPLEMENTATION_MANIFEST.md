# Implementation manifest

## Directly runnable

This package is a standalone FastAPI backend. Start with:

```bash
pip install -r requirements.txt
uvicorn fuzz_core.main:app --reload
```

## New files

- `fuzz_core/storage/path_resolver.py`
- `fuzz_core/storage/repository.py`
- `fuzz_core/services/*.py`
- `fuzz_core/debugger/*.py`
- `fuzz_core/api/routers/protocols.py`
- `scripts/migrate_workspace.py`
- `docs/*.md`
- `tests/test_protocol_scope.py`

## Files intended to replace or patch original fuzz-core

- `fuzz_core/config.py`
- `fuzz_core/api/app.py`
- `fuzz_core/api/routers/config_router.py`
- `fuzz_core/api/routers/offline.py`
- `fuzz_core/api/routers/jobs.py`
- `fuzz_core/api/routers/compat.py`
- `fuzz_core/runner/manager.py`
- `fuzz_core/runner/models.py`
- `fuzz_core/runner/storage.py`

## Compatibility locks

The following route groups are preserved:

- `/api/v1/config`, `/api/v1/system/*`
- `/api/v1/offline/*`
- `/api/v1/jobs/*` including WebSocket paths
- `/extract_protocol`, `/upload_Vuldoc`, `/gen_init_seed`, `/risk_code_analysis`,
  `/risk_analysis_preview`, `/riskres_upload`, `/risk_code_instrument`,
  `/fuzztesting`, `/stop_fuzztesting`, `/get_fuzz_stats`,
  `/get_branch_coverage_history`, `/download_fuzz_log`

Modern routes use `ok/message/data`; legacy routes use `is_success/msg/data`.


## 0.2.1 二次补丁清单

- 修复 `artifact_id`：由 Python `hash()` 改为 SHA-256 稳定 hash，避免后端重启后 ID 变化。
- 解耦 GDB：`/api/v1/jobs/{job_id}/artifacts/{artifact_id}/analyze` 不再启动 GDB，仅返回可用于 UI 选择和独立调试的 `debug_session_request`。
- 新增独立 GDB API：`/api/v1/debug/sessions`、`/api/v1/debug/sessions/batch`、`/api/v1/debug/candidates`。
- 增强 artifact 列表：返回 `job_id`、`artifact_id`、`seed_path`、`target`、`debug_session_request`。
- 调试报告约束：新增 `debug_report` 和 `.report.json`，包含位置、错误类型、可能利用方式描述、PoC 概念说明和复现步骤。
- 实时过程日志：新增 `OperationLogService` 和 `/api/v1/operations...` API，并接入 protocol analyze、seed generate、risk analyze、instrument、VulDoc upload/distill 及兼容接口。
- 测试：新增稳定 artifact、独立 debug、批量 debug、operation log 测试。
