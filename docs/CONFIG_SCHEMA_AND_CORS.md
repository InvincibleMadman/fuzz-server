# Config Schema and CORS

CORS should not be removed. Without CORS, a Vite/React frontend running from `http://127.0.0.1:5173` or `http://localhost:5173` will be blocked by the browser when it calls the backend.

The current schema keeps CORS under `server.cors`:

```yaml
server:
  host: 0.0.0.0
  port: 18000
  cors:
    enabled: true
    allow_origins:
      - http://127.0.0.1:5173
      - http://localhost:5173
    allow_credentials: true
    allow_methods: [GET, POST, PATCH, OPTIONS]
    allow_headers: [Authorization, Content-Type, X-Operation-Id]
```

The backend applies this through FastAPI `CORSMiddleware` in `fuzz_core/api/app.py`.

LLM configuration can be provided directly in YAML:

```yaml
llm:
  provider: openai-compatible
  base_url: https://api.example.com/v1
  api_key: sk-xxxx
  api_key_env: FUZZ_CORE_LLM_API_KEY
  model: gpt-5.4
  models:
    protocol_extract: gpt-5.4
    risk_analysis: gpt-5.4
    seed_generation: gpt-5.4
    debug_reasoning: gpt-5.4
```

`llm.api_key` has priority. If it is empty, the backend reads the environment variable named by `llm.api_key_env`.

The loader also accepts the older config shape used by the original repo:

- `server.http.host` -> `server.host`
- `server.http.port` -> `server.port`
- `paths.workspace` -> `workspace.root`
- `afl.afl_binary` -> `paths.afl_fuzz`
- `runtime.preeny_desock_path` -> `paths.preeny_desock`
