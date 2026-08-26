"""Run-scoped connector process lifecycle and adapter bindings."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from urllib.parse import quote, urlparse, urlunparse

import httpx

from agentflow.specs import (
    ConnectorBindingSpec,
    ConnectorSpec,
    ConnectorToolSpec,
    NodeSpec,
    PipelineSpec,
)


@dataclass(slots=True)
class ConnectorProcess:
    spec: ConnectorSpec
    process: asyncio.subprocess.Process
    stdout: BinaryIO
    stderr: BinaryIO
    run_id: str
    nonce: str
    isolated_endpoint: bool


class ConnectorManager:
    """Start connector commands once per run and stop them at run completion."""

    def __init__(self) -> None:
        self._processes: dict[str, list[ConnectorProcess]] = {}
        self._context_secrets: dict[str, str] = {}
        self._control_tokens: dict[str, str] = {}
        self._connectors: dict[str, dict[str, ConnectorSpec]] = {}
        self._allocated_ports: set[tuple[str, int]] = set()
        self._run_ports: dict[str, list[tuple[str, int]]] = {}

    def _run_headers(self, run_id: str) -> dict[str, str]:
        secret = self._context_secrets[run_id]
        signature = hmac.new(
            secret.encode("utf-8"),
            run_id.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return {
            "x-agentflow-run-id": run_id,
            "x-agentflow-run-signature": signature,
        }

    def _tool_headers(self, run_id: str, tools: list[ConnectorToolSpec]) -> dict[str, str]:
        scope = ",".join(tool.name for tool in tools)
        signature = hmac.new(
            self._context_secrets[run_id].encode("utf-8"),
            f"{run_id}\0tools\0{scope}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return {
            "x-agentflow-tool-scope": scope,
            "x-agentflow-tool-signature": signature,
        }

    def inject_bindings(
        self,
        run_id: str,
        pipeline: PipelineSpec,
        connectors: dict[str, ConnectorSpec] | None = None,
    ) -> None:
        connectors = connectors or {
            connector.name: connector for connector in pipeline.connectors
        }
        connector_secret_env = {
            env_name
            for connector in connectors.values()
            for env_name in (
                *connector.env.keys(),
                *connector.env_from.keys(),
                *connector.env_from.values(),
            )
        }
        for node in pipeline.nodes:
            node.connector_secret_env = sorted(
                {*node.connector_secret_env, *connector_secret_env}
            )
            existing_bindings = {binding.name for binding in node.connector_bindings}
            for connector_name in node.connectors:
                connector = connectors[connector_name]
                allowed = getattr(node, "connector_tools", {}).get(connector_name)
                tools = connector.tools
                if allowed is not None:
                    available = {tool.name for tool in tools}
                    unknown = sorted(set(allowed) - available)
                    if unknown:
                        raise ValueError(
                            f"node {node.id!r} allows unknown tools for connector "
                            f"{connector_name!r}: {unknown}"
                        )
                    allowed_names = set(allowed)
                    tools = [tool for tool in tools if tool.name in allowed_names]
                headers = {
                    **connector.headers,
                    **self._run_headers(run_id),
                    **self._tool_headers(run_id, tools),
                }
                if connector.name not in existing_bindings:
                    node.connector_bindings.append(
                        ConnectorBindingSpec(
                            name=connector.name,
                            url=connector.url,
                            headers=headers,
                            tools=tools,
                        )
                    )
                    existing_bindings.add(connector.name)
                else:
                    binding = next(
                        item for item in node.connector_bindings if item.name == connector.name
                    )
                    binding.url = connector.url
                    binding.headers = headers
                    binding.tools = tools

    def _available_port(self, run_id: str, host: str) -> int:
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind((host, 0))
                port = int(listener.getsockname()[1])
            key = (host, port)
            if key not in self._allocated_ports:
                self._allocated_ports.add(key)
                self._run_ports.setdefault(run_id, []).append(key)
                return port

    def _resolve_connector(
        self,
        connector: ConnectorSpec,
        run_id: str,
    ) -> tuple[ConnectorSpec, bool]:
        if connector.command is None:
            args = [argument.replace("{run_id}", run_id) for argument in connector.args]
            return connector.model_copy(update={"args": args}, deep=True), False
        isolated = True
        parsed = urlparse(connector.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"connector {connector.name!r} requires an http(s) URL")
        port = self._available_port(run_id, parsed.hostname)

        def resolve(value: str) -> str:
            return value.replace("{run_id}", run_id).replace("{port}", str(port))

        return connector.model_copy(
            update={
                "url": resolve(connector.url),
                "control_url": resolve(connector.control_url) if connector.control_url else None,
                "args": [resolve(argument) for argument in connector.args],
                "env": {name: resolve(value) for name, value in connector.env.items()},
            },
            deep=True,
        ), True

    async def start(self, run_id: str, pipeline: PipelineSpec, run_dir: Path) -> None:
        self._context_secrets[run_id] = secrets.token_hex(32)
        self._control_tokens[run_id] = secrets.token_hex(32)
        self._run_ports[run_id] = []
        started: list[ConnectorProcess] = []
        self._processes[run_id] = started
        runtime_connectors: dict[str, ConnectorSpec] = {}
        self._connectors[run_id] = runtime_connectors
        try:
            for connector in pipeline.connectors:
                runtime_connector, isolated = self._resolve_connector(connector, run_id)
                nonce = secrets.token_hex(32)
                runtime_connectors[connector.name] = runtime_connector
                if runtime_connector.command is None:
                    continue
                log_dir = run_dir / "connectors" / runtime_connector.name
                log_dir.mkdir(parents=True, exist_ok=True)
                stdout = (log_dir / "stdout.log").open("ab")
                stderr = (log_dir / "stderr.log").open("ab")
                inherited_names = {
                    "HOME",
                    "LANG",
                    "LC_ALL",
                    "LOGNAME",
                    "PATH",
                    "PATHEXT",
                    "SYSTEMROOT",
                    "TMPDIR",
                    "USER",
                    "WINDIR",
                }
                env = {
                    name: value
                    for name, value in os.environ.items()
                    if name in inherited_names
                }
                env.update(runtime_connector.env)
                for target_name, source_name in runtime_connector.env_from.items():
                    if source_name not in os.environ:
                        stdout.close()
                        stderr.close()
                        raise ValueError(
                            f"connector {runtime_connector.name!r} requires environment variable {source_name!r}"
                        )
                    env[target_name] = os.environ[source_name]
                env["AGENTFLOW_RUN_ID"] = run_id
                env["AGENTFLOW_CONTEXT_SECRET"] = self._context_secrets[run_id]
                env["AGENTFLOW_CONTROL_TOKEN"] = self._control_tokens[run_id]
                env["AGENTFLOW_CONNECTOR_NONCE"] = nonce
                resolved_port = urlparse(runtime_connector.url).port
                if resolved_port is not None:
                    env["AGENTFLOW_CONNECTOR_PORT"] = str(resolved_port)
                args = runtime_connector.args
                cwd = runtime_connector.cwd
                if cwd is not None and not Path(cwd).expanduser().is_absolute():
                    cwd = str((pipeline.working_path / cwd).resolve())
                try:
                    process = await asyncio.create_subprocess_exec(
                        runtime_connector.command,
                        *args,
                        cwd=cwd or str(pipeline.working_path),
                        env=env,
                        stdout=stdout,
                        stderr=stderr,
                    )
                except Exception:
                    stdout.close()
                    stderr.close()
                    raise
                runtime = ConnectorProcess(
                    runtime_connector,
                    process,
                    stdout,
                    stderr,
                    run_id,
                    nonce,
                    isolated,
                )
                started.append(runtime)
                await self._wait_ready(runtime)
                if isolated and not runtime_connector.tools:
                    runtime_connector.tools = await self._discover_tools(runtime)
            self.inject_bindings(run_id, pipeline, runtime_connectors)
        except BaseException:
            try:
                await self.stop(run_id)
            except Exception:
                pass
            raise

    async def fetch_collection(
        self,
        run_id: str,
        connector_name: str,
        resource: str,
    ) -> object:
        """Read durable fan-out identifiers through a connector control endpoint."""

        connector = self._connectors.get(run_id, {}).get(connector_name)
        if connector is None or connector.control_url is None:
            raise ValueError(f"connector {connector_name!r} has no control endpoint")
        token = self._control_tokens.get(run_id)
        if token is None:
            raise RuntimeError(f"connector context for run {run_id!r} is not active")
        url = connector.control_url.rstrip("/") + "/" + quote(resource, safe="")
        async with httpx.AsyncClient(timeout=connector.startup_timeout_seconds) as client:
            response = await client.get(
                url,
                headers={"x-agentflow-control-token": token},
            )
            response.raise_for_status()
            return response.json()

    def bind_member(self, run_id: str, node: NodeSpec, item_id: str) -> None:
        """Inject a signed, non-agent-selected Hunt/Finding scope into connector calls."""

        secret = self._context_secrets.get(run_id)
        if secret is None:
            raise RuntimeError(f"connector context for run {run_id!r} is not active")
        signature = hmac.new(
            secret.encode("utf-8"),
            f"{run_id}\0{item_id}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        context_headers = {
            "x-agentflow-item-id": item_id,
            "x-agentflow-item-signature": signature,
        }
        for binding in node.connector_bindings:
            binding.headers = {**binding.headers, **context_headers}

    async def _wait_ready(self, runtime: ConnectorProcess) -> None:
        parsed = urlparse(runtime.spec.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(
                f"connector {runtime.spec.name!r} requires an http(s) streamable_http URL"
            )
        loop = asyncio.get_running_loop()
        deadline = loop.time() + runtime.spec.startup_timeout_seconds
        last_error: Exception | None = None
        while loop.time() < deadline:
            if runtime.process.returncode is not None:
                raise RuntimeError(
                    f"connector {runtime.spec.name!r} exited during startup with code "
                    f"{runtime.process.returncode}"
                )
            try:
                if runtime.isolated_endpoint:
                    health_url = urlunparse(
                        parsed._replace(path="/healthz", query="", fragment="")
                    )
                    async with httpx.AsyncClient(timeout=0.5) as client:
                        response = await client.get(
                            health_url,
                            headers={
                                "x-agentflow-control-token": self._control_tokens[runtime.run_id]
                            },
                        )
                    response.raise_for_status()
                    payload = response.json()
                    if (
                        not isinstance(payload, dict)
                        or payload.get("runId") != runtime.run_id
                        or payload.get("nonce") != runtime.nonce
                    ):
                        raise RuntimeError("connector health identity did not match this run")
                else:
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    _reader, writer = await asyncio.open_connection(parsed.hostname, port)
                    writer.close()
                    await writer.wait_closed()
                return
            except (OSError, httpx.HTTPError, ValueError, RuntimeError) as exc:
                last_error = exc
                await asyncio.sleep(0.05)
        raise TimeoutError(
            f"connector {runtime.spec.name!r} was not ready within "
            f"{runtime.spec.startup_timeout_seconds:g}s: {last_error}"
        )

    async def _discover_tools(self, runtime: ConnectorProcess) -> list[ConnectorToolSpec]:
        headers = {
            "accept": "application/json, text/event-stream",
            "content-type": "application/json",
            **self._run_headers(runtime.run_id),
            "x-agentflow-control-token": self._control_tokens[runtime.run_id],
        }
        async with httpx.AsyncClient(timeout=runtime.spec.startup_timeout_seconds) as client:
            initialized = await client.post(
                runtime.spec.url,
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "agentflow", "version": "0.1"},
                    },
                },
            )
            initialized.raise_for_status()
            initialize_payload = initialized.json()
            initialize_result = (
                initialize_payload.get("result")
                if isinstance(initialize_payload, dict)
                else None
            )
            protocol_version = (
                initialize_result.get("protocolVersion")
                if isinstance(initialize_result, dict)
                else None
            )
            if not isinstance(protocol_version, str):
                raise RuntimeError(
                    f"connector {runtime.spec.name!r} returned an invalid initialize result"
                )
            session_id = initialized.headers.get("mcp-session-id")
            if not session_id:
                raise RuntimeError(
                    f"connector {runtime.spec.name!r} did not return an MCP session ID"
                )
            session_headers = {
                **headers,
                "mcp-session-id": session_id,
                "mcp-protocol-version": protocol_version,
            }
            notified = await client.post(
                runtime.spec.url,
                headers=session_headers,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            )
            notified.raise_for_status()
            response = await client.post(
                runtime.spec.url,
                headers=session_headers,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise RuntimeError(
                    f"connector {runtime.spec.name!r} returned an invalid tools/list response"
                )
            if payload.get("error") is not None:
                raise RuntimeError(
                    f"connector {runtime.spec.name!r} tools/list failed: {payload['error']}"
                )
            result = payload.get("result")
            raw_tools = result.get("tools") if isinstance(result, dict) else None
            if not isinstance(raw_tools, list):
                raise RuntimeError(
                    f"connector {runtime.spec.name!r} returned an invalid tools/list result"
                )
            tools = [
                ConnectorToolSpec(
                    name=item["name"],
                    description=item.get("description") or item["name"],
                    input_schema=item.get("inputSchema") or {"type": "object"},
                )
                for item in raw_tools
                if isinstance(item, dict) and isinstance(item.get("name"), str)
            ]
            if len(tools) != len(raw_tools):
                raise RuntimeError(
                    f"connector {runtime.spec.name!r} returned an invalid tool entry"
                )
            names = [tool.name for tool in tools]
            if len(set(names)) != len(names):
                raise RuntimeError(
                    f"connector {runtime.spec.name!r} returned duplicate tool names"
                )
            return tools

    async def stop(self, run_id: str) -> None:
        processes = self._processes.pop(run_id, [])
        first_error: Exception | None = None
        try:
            for runtime in reversed(processes):
                try:
                    if runtime.process.returncode is None:
                        runtime.process.terminate()
                        try:
                            await asyncio.wait_for(
                                runtime.process.wait(),
                                timeout=runtime.spec.shutdown_timeout_seconds,
                            )
                        except asyncio.TimeoutError:
                            runtime.process.kill()
                            await runtime.process.wait()
                except ProcessLookupError:
                    pass
                except Exception as exc:  # noqa: BLE001 - stop every connector before reporting.
                    first_error = first_error or exc
                finally:
                    runtime.stdout.close()
                    runtime.stderr.close()
        finally:
            self._context_secrets.pop(run_id, None)
            self._control_tokens.pop(run_id, None)
            self._connectors.pop(run_id, None)
            for key in self._run_ports.pop(run_id, []):
                self._allocated_ports.discard(key)
        if first_error is not None:
            raise first_error
