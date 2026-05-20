# GDB Real-Time Log Output

The debugger remains a non-interactive intelligent triage pipeline. It does not expose an interactive GDB PTY.
Instead, it captures command-line stdout/stderr from the GDB subprocess and writes each output line into the operation log system.

## Start one debug session

```bash
curl -X POST http://127.0.0.1:18000/api/v1/debug/sessions \
  -H 'Content-Type: application/json' \
  -d '{
    "operation_id": "op-debug-001",
    "protocol": "modbus",
    "artifact_path": "/tmp/crashes/id_000001",
    "target": {
      "binary_path": "/tmp/parser",
      "cwd": "/tmp",
      "args": [],
      "transport_type": "stdin"
    }
  }'
```

## Poll real-time logs

```bash
curl 'http://127.0.0.1:18000/api/v1/operations/op-debug-001/logs/tail?since=0&limit=200'
```

## WebSocket logs

```text
ws://127.0.0.1:18000/api/v1/operations/op-debug-001/logs/ws
```

## Session-specific log alias

After a debug session is created, the frontend can also use:

```text
GET       /api/v1/debug/sessions/{session_id}/logs/tail
WebSocket /api/v1/debug/sessions/{session_id}/logs/ws
```

The alias resolves the session's `operation_id` and returns the same operation log stream.
