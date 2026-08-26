"""Run-scoped connector process lifecycle and adapter bindings."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from urllib.parse import quote, urlparse

import httpx

from agentflow.specs import ConnectorBindingSpec, ConnectorSpec, NodeSpec, PipelineSpec


@dataclass(slots=True)
class ConnectorProcess:
    spec: ConnectorSpec
    process: asyncio.subprocess.Process
    stdout: BinaryIO
    stderr: BinaryIO


class ConnectorManager:
    """Start connector commands once per run and stop them at run completion."""

    def __init__(self) -> None:
        self._processes: dict[str, list[ConnectorProcess]] = {}
        self._context_secrets: dict[str, str] = {}
        self._control_tokens: dict[str, str] = {}

    @staticmethod
    def inject_bindings(pipeline: PipelineSpec) -> None:
        connectors = {connector.name: connector for connector in pipeline.connectors}
        connector_secret_env = {
            env_name
            for connector in pipeline.connectors
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
            existing_mcps = {mcp.name for mcp in node.mcps}
            existing_bindings = {binding.name for binding in node.connector_bindings}
            for connector_name in node.connectors:
                connector = connectors[connector_name]
                if connector.name not in existing_mcps:
                    node.mcps.append(connector.as_mcp_server())
                    existing_mcps.add(connector.name)
                if connector.name not in existing_bindings:
                    node.connector_bindings.append(
                        ConnectorBindingSpec(
                            name=connector.name,
                            url=connector.url,
                            headers=connector.headers,
                            tools=connector.tools,
                        )
                    )
                    existing_bindings.add(connector.name)

    async def start(self, run_id: str, pipeline: PipelineSpec, run_dir: Path) -> None:
        self._context_secrets[run_id] = secrets.token_hex(32)
        self._control_tokens[run_id] = secrets.token_hex(32)
        self.inject_bindings(pipeline)
        started: list[ConnectorProcess] = []
        self._processes[run_id] = started
        try:
            for connector in pipeline.connectors:
                if connector.command is None:
                    continue
                log_dir = run_dir / "connectors" / connector.name
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
                env.update(connector.env)
                for target_name, source_name in connector.env_from.items():
                    if source_name not in os.environ:
                        stdout.close()
                        stderr.close()
                        raise ValueError(
                            f"connector {connector.name!r} requires environment variable {source_name!r}"
                        )
                    env[target_name] = os.environ[source_name]
                env["AGENTFLOW_RUN_ID"] = run_id
                env["AGENTFLOW_CONTEXT_SECRET"] = self._context_secrets[run_id]
                env["AGENTFLOW_CONTROL_TOKEN"] = self._control_tokens[run_id]
                args = [argument.replace("{run_id}", run_id) for argument in connector.args]
                cwd = connector.cwd
                if cwd is not None and not Path(cwd).expanduser().is_absolute():
                    cwd = str((pipeline.working_path / cwd).resolve())
                process = await asyncio.create_subprocess_exec(
                    connector.command,
                    *args,
                    cwd=cwd or str(pipeline.working_path),
                    env=env,
                    stdout=stdout,
                    stderr=stderr,
                )
                runtime = ConnectorProcess(connector, process, stdout, stderr)
                started.append(runtime)
                await self._wait_ready(runtime)
        except Exception:
            await self.stop(run_id)
            raise

    async def fetch_collection(
        self,
        run_id: str,
        pipeline: PipelineSpec,
        connector_name: str,
        resource: str,
    ) -> object:
        """Read durable fan-out identifiers through a connector control endpoint."""

        connector = next(
            (item for item in pipeline.connectors if item.name == connector_name),
            None,
        )
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
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
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
                _reader, writer = await asyncio.open_connection(parsed.hostname, port)
                writer.close()
                await writer.wait_closed()
                return
            except OSError as exc:
                last_error = exc
                await asyncio.sleep(0.05)
        raise TimeoutError(
            f"connector {runtime.spec.name!r} was not ready within "
            f"{runtime.spec.startup_timeout_seconds:g}s: {last_error}"
        )

    async def stop(self, run_id: str) -> None:
        processes = self._processes.pop(run_id, [])
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
            finally:
                runtime.stdout.close()
                runtime.stderr.close()
        self._context_secrets.pop(run_id, None)
        self._control_tokens.pop(run_id, None)
