# Apply This Package to the Remote fuzz-core Repository

This package is intended to replace the current partially-synchronized remote repository state.
The remote repository previously showed several Python/YAML files collapsed into one line and still contained old `AppState`/`ConfigStore` entrypoint code. Apply the files below as formatted source files.

## 1. Files to replace

Replace these files in the remote repository:

- `config.yaml`
- `fuzz_core/config.py`
- `fuzz_core/main.py`
- `fuzz_core/state.py`
- `fuzz_core/api/app.py`
- `fuzz_core/api/routers/debug.py`
- `fuzz_core/api/routers/operations.py`
- `fuzz_core/debugger/models.py`
- `fuzz_core/debugger/gdb_driver.py`
- `fuzz_core/debugger/session_manager.py`
- `tests/test_protocol_scope.py`
- `README.md`

## 2. Files to keep from v2/enhanced implementation

Ensure these files exist and are formatted with real newlines:

- `fuzz_core/api/routers/compat.py`
- `fuzz_core/api/routers/config_router.py`
- `fuzz_core/api/routers/jobs.py`
- `fuzz_core/api/routers/offline.py`
- `fuzz_core/api/routers/protocols.py`
- `fuzz_core/api/routers/system.py`
- `fuzz_core/services/operation_log_service.py`
- `fuzz_core/storage/path_resolver.py`
- `fuzz_core/storage/repository.py`
- `fuzz_core/runner/manager.py`
- `fuzz_core/runner/models.py`
- `fuzz_core/runner/storage.py`
- `fuzz_core/debugger/classifier.py`
- `fuzz_core/debugger/persistence.py`
- `fuzz_core/debugger/replayer.py`

## 3. Files/directories removed as obsolete placeholders

Delete these if they exist in the remote repository:

- `fuzz_core/ipc/`
- `fuzz_core/sdk.py`
- `fuzz_core/runner/engine.py`

They were placeholder compatibility files and are not used by the current API/service path.

## 4. Important behavior preserved

- Existing `/api/v1/...` endpoints are preserved.
- Legacy compatibility endpoints such as `/extract_protocol`, `/gen_init_seed`, `/upload_Vuldoc`, `/fuzztesting` remain preserved.
- CORS is not deleted. It is now modeled under `server.cors` in `config.yaml` and applied by `fastapi.middleware.cors.CORSMiddleware`.
- LLM `base_url` and `api_key` can both be configured in YAML. If `llm.api_key` is empty, the backend falls back to `llm.api_key_env`.
- GDB is no longer started from the job artifact analyze endpoint. Job artifact analyze returns a `debug_session_request`; the frontend explicitly starts GDB via `POST /api/v1/debug/sessions`.
- GDB stdout/stderr is captured line by line and written to operation logs for frontend real-time refresh.

## 5. Verification commands

```bash
python -m compileall fuzz_core
pytest -q
uvicorn fuzz_core.main:app --host 127.0.0.1 --port 18000
```

Smoke-check endpoints:

```bash
curl http://127.0.0.1:18000/api/v1/config
curl http://127.0.0.1:18000/api/v1/operations
curl http://127.0.0.1:18000/api/v1/debug/candidates
```
