from __future__ import annotations

import json
from pathlib import Path

from agentflow.agents.base import AgentAdapter
from agentflow.env import merge_env_layers
from agentflow.prepared import ExecutionPaths, PreparedExecution
from agentflow.specs import NodeSpec, ProviderConfig, RepoInstructionsMode, ToolAccess


_PI_READ_ONLY_TOOLS = "read,grep,find,ls"
_PI_READ_WRITE_TOOLS = "read,bash,edit,write,grep,find,ls"
_PI_BLOCKED_SESSION_ERRORS = ("Request blocked: prompt injection patterns detected",)
_PI_OVERSIZED_SESSION_ERRORS = (
    "Upstream idle timeout exceeded",
    "Provider finish_reason: error",
)
_PI_SESSION_ERROR_SCAN_BYTES = 256 * 1024
_PI_SESSION_ROLLOVER_MIN_BYTES = 2 * 1024 * 1024


class PiAdapter(AgentAdapter):
    def prepare(self, node: NodeSpec, prompt: str, paths: ExecutionPaths) -> PreparedExecution:
        connector_names = {binding.name for binding in node.connector_bindings}
        unsupported_mcps = [mcp.name for mcp in node.mcps if mcp.name not in connector_names]
        if unsupported_mcps:
            raise ValueError(
                "pi adapter does not support `mcps`. Pi uses extensions, not MCP servers; "
                "pass `--extension <path>` via `extra_args` instead. Unsupported servers: "
                + ", ".join(unsupported_mcps)
            )

        provider = self.provider_config(node.provider, node.agent)
        executable = node.executable or "pi"
        env = merge_env_layers(getattr(provider, "env", None), node.env)
        repo_instructions_ignored = node.repo_instructions_mode == RepoInstructionsMode.IGNORE

        command: list[str] = [
            executable,
            "--print",
            "--mode",
            "json",
        ]
        if node.durable_goal is not None and node.durable_goal.mode == "supervised":
            # Keep each durable node's Pi history alongside its other runtime
            # state. If a provider rejects the latest transcript before
            # inference, or a large transcript repeatedly becomes
            # unserviceable upstream, retain it and continue in a numbered
            # recovery directory rather than resending the same context.
            session_dir = self._durable_session_dir(Path(paths.target_runtime_dir))
            command.extend([
                "--session-dir",
                str(session_dir),
                "--continue",
            ])
        else:
            command.append("--no-session")

        tools = _PI_READ_ONLY_TOOLS if node.tools == ToolAccess.READ_ONLY else _PI_READ_WRITE_TOOLS
        connector_tool_names = [
            f"{binding.name}_{tool.name}"
            for binding in node.connector_bindings
            for tool in binding.tools
        ]
        if connector_tool_names:
            tools += "," + ",".join(connector_tool_names)
        command.extend(["--tools", tools])

        runtime_files: dict[str, str] = {}
        if node.connector_bindings:
            extension_rel = self.relative_runtime_file("connectors", "agentflow-connector-bridge.ts")
            runtime_files[extension_rel] = self._render_connector_extension(node)
            command.extend(["--extension", str(Path(paths.target_runtime_dir) / extension_rel)])
        scoped_home_needed = bool(provider and (provider.base_url or provider.headers))

        if scoped_home_needed:
            pi_home_relative = Path("pi-home") / "agent"
            models_rel = self.relative_runtime_file(str(pi_home_relative), "models.json")
            settings_rel = self.relative_runtime_file(str(pi_home_relative), "settings.json")
            runtime_files[models_rel] = self._render_models_json(provider, node.model)
            runtime_files[settings_rel] = "{}\n"
            env["PI_CODING_AGENT_DIR"] = str(Path(paths.target_runtime_dir) / pi_home_relative)
        elif provider and provider.name and "/" not in (node.model or ""):
            command.extend(["--provider", provider.name])

        if provider and provider.api_key_env and provider.api_key_env not in env:
            # Surface the key into the subprocess env so Pi can read it by name.
            import os

            resolved = os.getenv(provider.api_key_env)
            if resolved is not None:
                env.setdefault(provider.api_key_env, resolved)

        if node.model:
            command.extend(["--model", node.model])

        if repo_instructions_ignored:
            command.extend([
                "--no-skills",
                "--no-extensions",
                "--no-prompt-templates",
                "--no-context-files",
            ])
            prompt = self.source_checkout_prompt(prompt, paths)

        command.extend(node.extra_args)

        # Pass the prompt via stdin so it is never parsed as a flag or `@file`
        # reference by Pi's positional-message argument handling.
        return PreparedExecution(
            command=command,
            env=env,
            cwd=paths.target_workdir,
            trace_kind="pi",
            runtime_files=runtime_files,
            stdin=prompt,
        )

    @classmethod
    def _durable_session_dir(cls, runtime_dir: Path) -> Path:
        base = runtime_dir / "pi-sessions"
        recovery_dirs = sorted(
            (
                path
                for path in runtime_dir.glob("pi-sessions-recovery-*")
                if path.is_dir() and path.name.removeprefix("pi-sessions-recovery-").isdigit()
            ),
            key=lambda path: int(path.name.removeprefix("pi-sessions-recovery-")),
        )
        current = recovery_dirs[-1] if recovery_dirs else base
        if not cls._session_rejected_before_inference(current):
            return current
        next_index = (
            int(current.name.removeprefix("pi-sessions-recovery-")) + 1
            if current != base
            else 1
        )
        return runtime_dir / f"pi-sessions-recovery-{next_index}"

    @staticmethod
    def _session_rejected_before_inference(session_dir: Path) -> bool:
        transcripts = list(session_dir.glob("*.jsonl")) if session_dir.is_dir() else []
        if not transcripts:
            return False
        latest = max(transcripts, key=lambda path: path.stat().st_mtime_ns)
        try:
            transcript_size = latest.stat().st_size
            with latest.open("rb") as handle:
                handle.seek(max(0, transcript_size - _PI_SESSION_ERROR_SCAN_BYTES))
                tail = handle.read().decode("utf-8", errors="replace")
        except OSError:
            return False
        latest_error = PiAdapter._latest_assistant_error(tail)
        if any(marker in latest_error for marker in _PI_BLOCKED_SESSION_ERRORS):
            return True
        return transcript_size >= _PI_SESSION_ROLLOVER_MIN_BYTES and any(
            marker in latest_error for marker in _PI_OVERSIZED_SESSION_ERRORS
        )

    @staticmethod
    def _latest_assistant_error(tail: str) -> str:
        for line in reversed(tail.splitlines()):
            try:
                payload = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                continue
            if payload.get("type") != "message":
                continue
            message = payload.get("message")
            if not isinstance(message, dict) or message.get("role") != "assistant":
                continue
            if message.get("stopReason") != "error":
                return ""
            error = message.get("errorMessage")
            return error if isinstance(error, str) else ""
        # Older Pi transcripts and imported sessions may contain only the
        # provider's plain-text terminal error.
        return tail

    def _render_connector_extension(self, node: NodeSpec) -> str:
        registrations: list[str] = []
        for binding in node.connector_bindings:
            for tool in binding.tools:
                tool_name = f"{binding.name}_{tool.name}"
                registrations.append(
                    "  pi.registerTool({\n"
                    f"    name: {json.dumps(tool_name)},\n"
                    f"    label: {json.dumps(binding.name + '.' + tool.name)},\n"
                    f"    description: {json.dumps(tool.description)},\n"
                    f"    parameters: {json.dumps(tool.input_schema, ensure_ascii=False)} as any,\n"
                    "    async execute(_toolCallId: string, params: unknown, signal: AbortSignal) {\n"
                    f"      const endpoint = new URL({json.dumps(binding.url)});\n"
                    "      endpoint.pathname = endpoint.pathname.replace(/\\/mcp\\/?$/, '') + '/tools/call';\n"
                    "      endpoint.search = '';\n"
                    "      const response = await fetch(endpoint, {\n"
                    "        method: 'POST',\n"
                    f"        headers: {{ 'content-type': 'application/json', ...{json.dumps(binding.headers, ensure_ascii=False)} }},\n"
                    f"        body: JSON.stringify({{ name: {json.dumps(tool.name)}, arguments: params }}),\n"
                    "        signal,\n"
                    "      });\n"
                    "      const payload = await response.json();\n"
                    "      if (!response.ok) throw new Error(payload.error || `connector returned ${response.status}`);\n"
                    "      if (payload && Array.isArray(payload.content)) return payload;\n"
                    "      return { content: [{ type: 'text', text: JSON.stringify(payload) }], details: payload };\n"
                    "    },\n"
                    "  });"
                )
        body = "\n".join(registrations)
        return (
            "// Generated by AgentFlow for this node. Database credentials remain in the connector process.\n"
            "export default function (pi: any) {\n"
            f"{body}\n"
            "}\n"
        )

    def _render_models_json(self, provider: ProviderConfig, model: str | None) -> str:
        """Render a scoped ``models.json`` containing only the declared provider.

        Pi resolves custom providers from its agent directory's ``models.json``. When the
        caller supplies a full ``ProviderConfig`` (with ``base_url``), we materialize a
        minimal ``models.json`` under a scoped ``PI_CODING_AGENT_DIR`` so the run does
        not depend on the user's ``~/.pi/agent/models.json``.
        """
        entry: dict[str, object] = {
            "baseUrl": provider.base_url,
            "api": provider.wire_api or "openai-completions",
        }
        if provider.api_key_env:
            entry["apiKey"] = provider.api_key_env
        if provider.headers:
            entry["headers"] = dict(provider.headers)
            entry["authHeader"] = True
        model_id = self._extract_model_id(model, provider.name)
        entry["models"] = [{"id": model_id}] if model_id else []

        payload = {"providers": {provider.name: entry}}
        return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"

    @staticmethod
    def _extract_model_id(model: str | None, provider_name: str) -> str | None:
        if not model:
            return None
        ident = model
        if "/" in ident:
            prefix, _, rest = ident.partition("/")
            if prefix == provider_name:
                ident = rest
        if ":" in ident:
            ident = ident.split(":", 1)[0]
        return ident or None
