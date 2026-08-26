import asyncio
from io import BytesIO
import textwrap
from pathlib import Path
from urllib.parse import urlparse

import httpx
import pytest

from agentflow.connectors import ConnectorManager, ConnectorProcess
from agentflow.specs import ConnectorSpec, PipelineSpec


SERVER = textwrap.dedent(
    r"""
    import hashlib
    import hmac
    import json
    import os
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    run_id = os.environ["AGENTFLOW_RUN_ID"]
    secret = os.environ["AGENTFLOW_CONTEXT_SECRET"]
    control_token = os.environ["AGENTFLOW_CONTROL_TOKEN"]
    nonce = os.environ["AGENTFLOW_CONNECTOR_NONCE"]
    port = int(os.environ["TEST_CONNECTOR_PORT"])

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, payload=None, *, session=False):
            body = b"" if payload is None else json.dumps(payload).encode()
            self.send_response(status)
            if payload is not None:
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
            if session:
                self.send_header("mcp-session-id", "test-session")
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):
            if self.path != "/healthz" or self.headers.get("x-agentflow-control-token") != control_token:
                self.reply(403, {"error": "forbidden"})
                return
            reported_nonce = "wrong" if os.environ.get("BAD_NONCE") else nonce
            self.reply(200, {"ok": True, "runId": run_id, "nonce": reported_nonce})

        def do_POST(self):
            expected = hmac.new(secret.encode(), run_id.encode(), hashlib.sha256).hexdigest()
            if (
                self.path != "/mcp"
                or self.headers.get("x-agentflow-run-id") != run_id
                or not hmac.compare_digest(self.headers.get("x-agentflow-run-signature", ""), expected)
            ):
                self.reply(403, {"error": "forbidden"})
                return
            size = int(self.headers.get("content-length", "0"))
            request = json.loads(self.rfile.read(size))
            if request["method"] == "initialize":
                self.reply(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "result": {
                            "protocolVersion": "2025-03-26",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "test", "version": "1"},
                        },
                    },
                    session=True,
                )
            elif request["method"] == "notifications/initialized":
                self.reply(202)
            elif request["method"] == "tools/list":
                self.reply(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "result": {
                            "tools": [
                                {
                                    "name": "finish_hunt",
                                    "description": "Finish one Hunt",
                                    "inputSchema": {"type": "object"},
                                }
                            ]
                        },
                    },
                )
            else:
                self.reply(400, {"error": "unknown method"})

        def log_message(self, *_args):
            pass

    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
    """
)


def _pipeline(
    tmp_path: Path,
    *,
    allowed_tools: list[str] | None = None,
    **env: str,
) -> PipelineSpec:
    return PipelineSpec.model_validate(
        {
            "name": "isolated-connector",
            "working_dir": str(tmp_path),
            "connectors": [
                {
                    "name": "bugdb",
                    "url": "http://127.0.0.1:{port}/mcp",
                    "command": "python3",
                    "args": ["-c", SERVER],
                    "env": {"TEST_CONNECTOR_PORT": "{port}", **env},
                    "startup_timeout_seconds": 1,
                }
            ],
            "nodes": [
                {
                    "id": "hunt",
                    "agent": "codex",
                    "prompt": "finish",
                    "connectors": ["bugdb"],
                    "connector_tools": {
                        "bugdb": allowed_tools or ["finish_hunt"]
                    },
                }
            ],
        }
    )


@pytest.mark.asyncio
async def test_managed_connectors_get_distinct_authenticated_endpoints(tmp_path: Path):
    manager = ConnectorManager()
    first = _pipeline(tmp_path)
    second = _pipeline(tmp_path)

    try:
        await asyncio.gather(
            manager.start("run-a", first, tmp_path / "run-a"),
            manager.start("run-b", second, tmp_path / "run-b"),
        )

        first_binding = first.node_map["hunt"].connector_bindings[0]
        second_binding = second.node_map["hunt"].connector_bindings[0]
        assert urlparse(first_binding.url).port != urlparse(second_binding.url).port
        assert first.connectors[0].url == "http://127.0.0.1:{port}/mcp"
        assert first.node_map["hunt"].mcps == []
        assert [tool.name for tool in first_binding.tools] == ["finish_hunt"]
        assert first_binding.headers["x-agentflow-run-id"] == "run-a"

        health_url = first_binding.url.replace("/mcp", "/healthz")
        async with httpx.AsyncClient() as client:
            assert (await client.get(health_url)).status_code == 403
    finally:
        await asyncio.gather(manager.stop("run-a"), manager.stop("run-b"))


@pytest.mark.asyncio
async def test_managed_connector_rejects_wrong_health_identity(tmp_path: Path):
    manager = ConnectorManager()
    pipeline = _pipeline(tmp_path, BAD_NONCE="1")
    pipeline.connectors[0].startup_timeout_seconds = 0.2

    with pytest.raises(TimeoutError, match="health identity did not match"):
        await manager.start("run-wrong", pipeline, tmp_path / "run-wrong")


@pytest.mark.asyncio
async def test_managed_connector_reports_child_exit_during_startup(tmp_path: Path):
    manager = ConnectorManager()
    pipeline = _pipeline(tmp_path)
    connector = pipeline.connectors[0]
    connector.args = ["-c", "raise SystemExit(7)"]

    with pytest.raises(RuntimeError, match="exited during startup with code 7"):
        await manager.start("run-exit", pipeline, tmp_path / "run-exit")


@pytest.mark.asyncio
async def test_managed_connector_rejects_unknown_tool_allowlist(tmp_path: Path):
    manager = ConnectorManager()
    pipeline = _pipeline(tmp_path, allowed_tools=["missing_tool"])

    with pytest.raises(ValueError, match="allows unknown tools"):
        await manager.start("run-tools", pipeline, tmp_path / "run-tools")


def test_managed_connector_requires_run_scoped_port(tmp_path: Path):
    with pytest.raises(ValueError, match="run-scoped.*port"):
        PipelineSpec.model_validate(
            {
                "name": "fixed-managed-port",
                "working_dir": str(tmp_path),
                "connectors": [
                    {
                        "name": "bugdb",
                        "url": "http://127.0.0.1:4312/mcp",
                        "command": "python3",
                    }
                ],
                "nodes": [{"id": "hunt", "agent": "codex", "prompt": "hunt"}],
            }
        )


@pytest.mark.asyncio
async def test_stop_cleans_every_connector_and_secret_after_shutdown_error():
    class Process:
        def __init__(self, *, error: Exception | None = None):
            self.returncode = None
            self.error = error
            self.terminated = False
            self.waited = False

        def terminate(self):
            self.terminated = True
            if self.error is not None:
                raise self.error

        async def wait(self):
            self.waited = True
            self.returncode = 0
            return 0

        def kill(self):
            self.returncode = -9

    manager = ConnectorManager()
    spec = ConnectorSpec(
        name="bugdb",
        url="http://127.0.0.1:{port}/mcp",
        command="python3",
    )
    good_process = Process()
    bad_process = Process(error=RuntimeError("shutdown failed"))
    streams = [BytesIO() for _ in range(4)]
    manager._processes["run"] = [
        ConnectorProcess(spec, good_process, streams[0], streams[1], "run", "a", True),
        ConnectorProcess(spec, bad_process, streams[2], streams[3], "run", "b", True),
    ]
    manager._context_secrets["run"] = "secret"
    manager._control_tokens["run"] = "token"
    manager._connectors["run"] = {"bugdb": spec}
    manager._run_ports["run"] = [("127.0.0.1", 43210)]
    manager._allocated_ports.add(("127.0.0.1", 43210))

    with pytest.raises(RuntimeError, match="shutdown failed"):
        await manager.stop("run")

    assert good_process.terminated and good_process.waited
    assert all(stream.closed for stream in streams)
    assert "run" not in manager._context_secrets
    assert "run" not in manager._control_tokens
    assert "run" not in manager._connectors
    assert ("127.0.0.1", 43210) not in manager._allocated_ports
