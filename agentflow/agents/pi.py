from __future__ import annotations

import json
from pathlib import Path

from agentflow.agents.base import AgentAdapter
from agentflow.env import merge_env_layers
from agentflow.prepared import ExecutionPaths, PreparedExecution
from agentflow.specs import NodeSpec, ProviderConfig, RepoInstructionsMode, ToolAccess


_PI_READ_ONLY_TOOLS = "read,grep,find,ls"
_PI_READ_WRITE_TOOLS = "read,bash,edit,write,grep,find,ls"


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
            # state. --continue creates a session when none exists and resumes
            # the most recent one on retries or process-level recovery.
            command.extend([
                "--session-dir",
                str(Path(paths.target_runtime_dir) / "pi-sessions"),
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
        model_entry: dict[str, object] | None = None
        if model_id:
            model_entry = {"id": model_id}
            if provider.model_reasoning is not None:
                model_entry["reasoning"] = provider.model_reasoning
            if provider.model_context_window is not None:
                model_entry["contextWindow"] = provider.model_context_window
            if provider.model_max_tokens is not None:
                model_entry["maxTokens"] = provider.model_max_tokens
        entry["models"] = [model_entry] if model_entry else []

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
