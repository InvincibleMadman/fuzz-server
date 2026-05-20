# fuzz-core enhanced completion package

This package is a runnable, protocol-scoped backend implementation intended as an overlay for `InvincibleMadman/fuzz-core`.

It preserves the published modern `/api/v1/...` and legacy-compatible routes, while adding:

- protocol-scoped workspace storage
- VulDoc upload, distillation, KB search, graph, summary, timeline
- seed generation with explicit `generation_mode`
- generalized GDB debug sessions with persistence and vulnerability history
- runner artifact replay/analyze integration
- migration scripts and tests

## Run

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn fuzz_core.main:app --reload
```

Open:

```bash
curl http://127.0.0.1:8000/api/v1/system/capabilities
```

## Test

```bash
pytest -q
```

## Overlay use

See `docs/FILE_MIGRATION_GUIDE.md`. Files are intentionally organized under the same package name `fuzz_core` so they can be copied into the original repository after review.


## 0.2.1 更新：独立 GDB 调试与实时操作日志

本版本将 GDB 智能体从 fuzz job artifact analyze 中解耦。`POST /api/v1/jobs/{job_id}/artifacts/{artifact_id}/analyze` 仍保留，但不再直接启动 GDB，而是返回 `seed_path`、`target` 与 `debug_session_request`，供前端在 Web UI 中选择崩溃种子后调用独立调试接口。

新增独立调试接口：

- `GET /api/v1/debug/candidates?job_id=...`
- `POST /api/v1/debug/sessions`
- `POST /api/v1/debug/sessions/batch`
- `GET /api/v1/debug/sessions/{session_id}`
- `GET /api/v1/protocols/{protocol}/debug/sessions`

每次调试都会返回并落盘一个受约束 JSON：`workspace/protocols/{protocol}/debug/reports/{session_id}.report.json`，其中包含函数名、文件行号范围、错误类型、可能利用方式描述、PoC 概念说明、复现步骤和修复建议，便于前端回显。

新增实时中间过程日志接口：

- `GET /api/v1/operations`
- `GET /api/v1/operations/{operation_id}`
- `GET /api/v1/operations/{operation_id}/logs/tail`
- `WebSocket /api/v1/operations/{operation_id}/logs/ws`

协议提取、种子生成、风险分析、风险插桩、VulDoc 上传和蒸馏接口均已写入 operation log。前端可以在请求体或 `X-Operation-Id` 中传入自定义 `operation_id`，请求运行时同步轮询日志，用于“后端输出实时显示区域”。

详见：

- `docs/GDB_DEBUG_WORKFLOW.md`
- `docs/REALTIME_OPERATION_LOGS.md`
- `docs/APPLY_TO_REMOTE_REPO.md`


## 0.2.2 更新：配置 schema、CORS 与 GDB 实时 stdout/stderr

本版本修复了远程仓库同步后残留的旧入口与旧状态对象问题：

- `fuzz_core/main.py` 改为直接使用 `create_app()` 与 `load_config()`；
- `fuzz_core/state.py` 只保留当前服务需要的 `CoreState`；
- `fuzz_core/config.py` 同时兼容新 schema 与旧 `config.yaml` 中的 `server.http.*`、`paths.workspace`、`afl.afl_binary`、`runtime.preeny_desock_path`；
- `llm.base_url`、`llm.api_key`、`llm.api_key_env`、`llm.models.*` 均可在 YAML 中配置；
- CORS 未删除，已统一放在 `server.cors`，并由 FastAPI `CORSMiddleware` 实际生效；
- GDB 调试的 stdout/stderr 现在通过 `subprocess.Popen` 逐行捕获，并写入 operation log；
- 新增 `GET /api/v1/debug/sessions/{session_id}/logs/tail` 与 `WebSocket /api/v1/debug/sessions/{session_id}/logs/ws` 作为调试会话日志别名；
- 删除了不再需要的占位文件：`fuzz_core/ipc/`、`fuzz_core/sdk.py`、`fuzz_core/runner/engine.py`。

前端实时显示 GDB 输出的推荐方式：

1. 调用 `POST /api/v1/debug/sessions` 时传入 `operation_id`；
2. 请求执行期间轮询 `GET /api/v1/operations/{operation_id}/logs/tail?since=...` 或连接 `WebSocket /api/v1/operations/{operation_id}/logs/ws`；
3. 如果只知道 `session_id`，使用 `GET /api/v1/debug/sessions/{session_id}/logs/tail`。
