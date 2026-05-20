from pathlib import Path
from fastapi.testclient import TestClient

def make_client(tmp_path, monkeypatch):
    cfg=tmp_path/"config.yaml"
    cfg.write_text(f"""
workspace:
  root: "{tmp_path / 'workspace'}"
  default_protocol: "legacy-default"
server:
  host: "127.0.0.1"
  port: 8000
llm:
  provider: "local"
  model: "local-rule-based"
  base_url: ""
  api_key_env: "FUZZ_CORE_LLM_API_KEY"
paths:
  afl_fuzz: "afl-fuzz"
  afl_showmap: "afl-showmap"
  preeny_desock: ""
debugger:
  gdb_path: "gdb"
  timeout_sec: 3
  allow_network_replay: false
""", encoding="utf-8")
    monkeypatch.setenv("FUZZ_CORE_CONFIG", str(cfg))
    from fuzz_core.api.app import create_app
    return TestClient(create_app())

def test_protocol_vuldocs_do_not_mix(tmp_path, monkeypatch):
    c=make_client(tmp_path, monkeypatch)
    r1=c.post("/api/v1/protocols/bacnet/vuldocs/upload", files=[("files", ("a.txt", b"out-of-bounds length parser", "text/plain"))])
    r2=c.post("/api/v1/protocols/opener/vuldocs/upload", files=[("files", ("b.txt", b"authentication state bug", "text/plain"))])
    assert r1.status_code == 200 and r2.status_code == 200
    assert c.get("/api/v1/protocols/bacnet/vuldocs").json()["data"]["items"][0]["filename"] == "a.txt"
    assert c.get("/api/v1/protocols/opener/vuldocs").json()["data"]["items"][0]["filename"] == "b.txt"

def test_specs_do_not_override_and_seed_modes(tmp_path, monkeypatch):
    c=make_client(tmp_path, monkeypatch)
    c.post("/api/v1/offline/protocol/analyze", json={"protocol":"bacnet","content":"{\"name\":\"bacnet\"}"})
    c.post("/api/v1/offline/protocol/analyze", json={"protocol":"opener","content":"{\"name\":\"opener\"}"})
    a=c.post("/api/v1/offline/seeds/generate", json={"protocol":"bacnet","count":1}).json()["data"]
    b=c.post("/api/v1/offline/seeds/generate", json={"protocol":"opener","count":1}).json()["data"]
    assert a["generation_mode"] == "spec_only"
    assert b["generation_mode"] == "spec_only"
    assert "bacnet" in a["output_dir"]
    assert "opener" in b["output_dir"]

def test_kb_summary_graph_timeline_and_fallback(tmp_path, monkeypatch):
    c=make_client(tmp_path, monkeypatch)
    up=c.post("/api/v1/protocols/iec61850/vuldocs/upload", files=[("files", ("v.txt", b"CWE out-of-bounds decode length crash PoC", "text/plain"))]).json()
    assert up["ok"]
    dist=c.post("/api/v1/protocols/iec61850/vuldocs/distill", json={}).json()["data"]
    assert dist["entries"][0]["coarse_type"] == "bounds-check"
    assert c.get("/api/v1/protocols/iec61850/kb/summary").json()["data"]["total"] == 1
    assert c.get("/api/v1/protocols/iec61850/kb/graph").json()["data"]["nodes"]
    assert c.get("/api/v1/protocols/iec61850/kb/timeline").json()["data"]["events"]
    seed=c.post("/api/v1/offline/seeds/generate", json={"protocol":"iec61850","count":1}).json()["data"]
    assert seed["generation_mode"] == "kb_only_fallback"
    assert seed["used_kb_entry_ids"]

def test_compat_routes_and_legacy_default(tmp_path, monkeypatch):
    c=make_client(tmp_path, monkeypatch)
    r=c.post("/upload_Vuldoc", files={"file":("legacy.txt", b"legacy null pointer crash", "text/plain")})
    assert r.json()["is_success"]
    gen=c.post("/gen_init_seed", json={"count":1}).json()["data"]
    assert gen["protocol"] == "legacy-default"
    assert gen["generation_mode"] in {"raw_doc_fallback","degraded_no_spec"}
    listed=c.get("/api/v1/protocols/legacy-default/vuldocs").json()["data"]["items"]
    assert listed and listed[0]["filename"] == "legacy.txt"

def test_debugger_history_and_runner_artifact_analyze(tmp_path, monkeypatch):
    c=make_client(tmp_path, monkeypatch)
    # direct debugger service
    st=c.app.state.core
    art=tmp_path/"crash.bin"; art.write_bytes(b"AAAA")
    sess=st.debugger.run({"protocol":"modbus","artifact_path":str(art),"artifact_id":"a1","target":{"protocol":"modbus","transport_type":"stdin"}})
    assert sess["status"] == "archived"
    hist=c.get("/api/v1/protocols/modbus/vulns/history").json()["data"]["items"]
    assert hist and hist[0]["debug_session_id"] == sess["session_id"]

    # runner artifact discovery now exposes stable IDs and a standalone debug request template.
    out=tmp_path/"out"; crash=out/"default"/"crashes"/"id:000000,sig:11"; crash.parent.mkdir(parents=True); crash.write_bytes(b"CRASH")
    job=c.post("/api/v1/jobs", json={"protocol":"modbus","output_dir":str(out),"dry_run":True,"debug":{"transport_type":"stdin"}}).json()["data"]
    arts1=c.get(f"/api/v1/jobs/{job['job_id']}/artifacts").json()["data"]["items"]
    arts2=c.get(f"/api/v1/jobs/{job['job_id']}/artifacts").json()["data"]["items"]
    assert arts1 and arts1[0]["artifact_id"] == arts2[0]["artifact_id"]
    assert arts1[0]["seed_path"] == str(crash)
    analyzed=c.post(f"/api/v1/jobs/{job['job_id']}/artifacts/{arts1[0]['artifact_id']}/analyze").json()["data"]
    assert analyzed["gdb_binding_removed"] is True
    assert analyzed["debug_session_request"]["artifact_path"] == str(crash)
    dbg=c.post("/api/v1/debug/sessions", json=analyzed["debug_session_request"]).json()["data"]
    assert dbg["status"] == "archived"
    assert dbg["debug_report"]["schema_version"] == "debug-report.v1"
    assert dbg["debug_report"]["artifact"]["seed_path"] == str(crash)


def test_operation_logs_are_queryable(tmp_path, monkeypatch):
    c=make_client(tmp_path, monkeypatch)
    op_id="op-ui-visible-001"
    r=c.post("/api/v1/offline/risk/analyze", json={"protocol":"bacnet","source_path":str(tmp_path),"operation_id":op_id})
    assert r.status_code == 200
    assert r.json()["data"]["operation_id"] == op_id
    tail=c.get(f"/api/v1/operations/{op_id}/logs/tail").json()["data"]
    assert tail["status"] == "finished"
    assert any("Scanning source tree" in e["message"] for e in tail["items"])
    ops=c.get("/api/v1/operations", params={"kind":"offline.risk.analyze"}).json()["data"]["items"]
    assert any(x["operation_id"] == op_id for x in ops)

def test_batch_debug_api(tmp_path, monkeypatch):
    c=make_client(tmp_path, monkeypatch)
    seed_dir=tmp_path/"seeds"; seed_dir.mkdir()
    (seed_dir/"id_000001").write_bytes(b"A")
    (seed_dir/"id_000002").write_bytes(b"B")
    res=c.post("/api/v1/debug/sessions/batch", json={
        "protocol":"opener",
        "seed_dir":str(seed_dir),
        "max_cases":2,
        "target":{"protocol":"opener","transport_type":"stdin"}
    }).json()["data"]
    assert res["count"] == 2
    assert all(x["debug_report_path"].endswith(".report.json") for x in res["items"])

def test_legacy_config_schema_cors_and_yaml_key(tmp_path, monkeypatch):
    cfg = tmp_path / "legacy-config.yaml"
    cfg.write_text(f"""
server:
  http:
    host: 0.0.0.0
    port: 18000
  cors:
    enabled: true
    allow_origins:
      - http://127.0.0.1:5173
    allow_credentials: true
    allow_methods:
      - GET
      - POST
      - PATCH
      - OPTIONS
    allow_headers:
      - Authorization
      - Content-Type
      - X-Operation-Id
llm:
  provider: openai-compatible
  base_url: https://api.example.test/v1
  api_key: yaml-secret
  models:
    protocol_extract: gpt-test-protocol
    debug_reasoning: gpt-test-debug
paths:
  workspace: "{tmp_path / 'workspace'}"
afl:
  afl_binary: /usr/bin/afl-fuzz
runtime:
  preeny_desock_path: /tmp/desock.so
debugger:
  gdb_path: gdb
  timeout_sec: 3
  allow_network_replay: false
""", encoding="utf-8")
    monkeypatch.setenv("FUZZ_CORE_CONFIG", str(cfg))
    from fuzz_core.api.app import create_app
    c = TestClient(create_app())
    data = c.get("/api/v1/config").json()["data"]
    assert data["server"]["host"] == "0.0.0.0"
    assert data["server"]["port"] == 18000
    assert data["server"]["cors"]["enabled"] is True
    assert data["llm"]["api_key"] == "yaml-secret"
    assert data["paths"]["afl_fuzz"] == "/usr/bin/afl-fuzz"
    assert data["paths"]["preeny_desock"] == "/tmp/desock.so"
    preflight = c.options(
        "/api/v1/config",
        headers={
            "Origin": "http://127.0.0.1:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert preflight.status_code in {200, 400}
    assert preflight.headers.get("access-control-allow-origin") == "http://127.0.0.1:5173"


def test_gdb_stdout_is_streamed_to_operation_logs(tmp_path, monkeypatch):
    fake_gdb = tmp_path / "gdb"
    fake_gdb.write_text("""#!/usr/bin/env python3
import sys
print('GNU gdb fake')
print('Program received signal SIGSEGV, Segmentation fault.')
print('---BACKTRACE---')
print('#0  parse_packet () at parser.c:42')
print('---THREADS---')
print('Thread 1')
print('---REGISTERS---')
print('pc 0xdeadbeef')
print('---FRAME---')
print('len = 9999')
print('---DISASM---')
print('=> 0xdeadbeef <parse_packet+1>: mov (%rax),%rbx')
""", encoding="utf-8")
    fake_gdb.chmod(0o755)
    target = tmp_path / "parser"
    target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    target.chmod(0o755)
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"AAAA")

    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"""
workspace:
  root: "{tmp_path / 'workspace'}"
server:
  host: "127.0.0.1"
  port: 8000
llm:
  provider: "local"
  model: "local-rule-based"
paths:
  afl_fuzz: "afl-fuzz"
  afl_showmap: "afl-showmap"
debugger:
  gdb_path: "{fake_gdb}"
  timeout_sec: 3
  allow_network_replay: false
""", encoding="utf-8")
    monkeypatch.setenv("FUZZ_CORE_CONFIG", str(cfg))
    from fuzz_core.api.app import create_app
    c = TestClient(create_app())
    res = c.post("/api/v1/debug/sessions", json={
        "operation_id": "op-gdb-stream-001",
        "protocol": "modbus",
        "artifact_path": str(seed),
        "target": {"binary_path": str(target), "cwd": str(tmp_path), "transport_type": "stdin"},
    }).json()["data"]
    assert res["debug_report"]["vulnerability_location"]["function_name"] == "parse_packet"
    assert res["debug_report"]["vulnerability_location"]["line"] == 42
    tail = c.get("/api/v1/operations/op-gdb-stream-001/logs/tail", params={"since": 0, "limit": 200}).json()["data"]
    messages = [x["message"] for x in tail["items"]]
    assert any("Program received signal SIGSEGV" in msg for msg in messages)
    assert any("#0  parse_packet" in msg for msg in messages)
    session_tail = c.get(f"/api/v1/debug/sessions/{res['session_id']}/logs/tail").json()["data"]
    assert session_tail["operation_id"] == "op-gdb-stream-001"
