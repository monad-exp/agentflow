"""Async pipeline orchestration for AgentFlow runs.

Each submitted run is driven in a background thread that owns an asyncio loop for
scheduling node tasks, persisting state transitions, and reacting to cancellation,
rerun, and periodic-control signals without blocking other runs.
"""

from __future__ import annotations

import asyncio
from copy import deepcopy
import json
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel, Field, ValidationError

from agentflow.agents.registry import AdapterRegistry, default_adapter_registry
from agentflow.connectors import ConnectorManager
from agentflow.contracts import parse_json_output, select_json_path
from agentflow.context import render_node_prompt
from agentflow.graph_optimizer import (
    GRAPH_OPTIMIZER_MAX_ATTEMPTS,
    GENERATED_PIPELINE_EDITED_FILENAME,
    GENERATED_PIPELINE_FILENAME,
    GENERATED_PIPELINE_ORIGINAL_FILENAME,
    GRAPH_REPORT_FILENAME,
    OPTIMIZER_PROMPT_FILENAME,
    OPTIMIZER_RESULT_FILENAME,
    OPTIMIZER_VALIDATION_FILENAME,
    build_graph_report,
    copy_run_traces,
    render_graph_optimizer_prompt,
    write_editable_pipeline_python,
    write_optimizer_result,
    write_validation_result,
)
from agentflow.loader import load_pipeline_from_path
from agentflow.output_capture import (
    BoundedLineBuffer,
    OUTPUT_TRUNCATION_MARKER,
    STREAM_ARTIFACT_MAX_BYTES,
    TRACE_ARTIFACT_MAX_BYTES,
    TRACE_ARTIFACT_TRUNCATION_MARKER,
)
from agentflow.prepared import ExecutionPaths, PreparedExecution, build_execution_paths
from agentflow.runners.registry import RunnerRegistry, default_runner_registry
from agentflow.specs import (
    AgentKind,
    NodeAttempt,
    MCPServerSpec,
    NodeResult,
    NodeSpec,
    NodeStatus,
    PeriodicActuationMode,
    PipelineSpec,
    ProviderConfig,
    RunEvent,
    RunRecord,
    RunStatus,
    SourceSnapshotSpec,
    builtin_agent_kind,
    expand_runtime_fanout_node,
)
from agentflow.store import RunStore
from agentflow.success import evaluate_success
from agentflow.tuned_agents import _parse_agent_output, _run_optimizer, resolve_node_for_execution
from agentflow.traces import create_trace_parser
from agentflow.utils import ensure_dir, looks_sensitive_key, redact_sensitive_shell_value, utcnow_iso


_TERMINAL_NODE_STATUSES = {
    NodeStatus.COMPLETED,
    NodeStatus.FAILED,
    NodeStatus.TIMED_OUT,
    NodeStatus.SKIPPED,
    NodeStatus.CANCELLED,
}

_TRANSIENT_TRACE_KINDS = {
    "assistant_delta",
    "reasoning_delta",
    "command_output",
    "stdout",
    "stderr",
}


def _materialize_connector_mcps(node: Any) -> Any:
    """Create the adapter-only MCP view of run-scoped connector bindings."""

    execution = deepcopy(node)
    servers = {mcp.name: mcp for mcp in execution.mcps}
    for binding in execution.connector_bindings:
        server = servers.get(binding.name)
        if server is None:
            execution.mcps.append(
                MCPServerSpec(
                    name=binding.name,
                    transport="streamable_http",
                    url=binding.url,
                )
            )
        else:
            server.url = binding.url
    return execution


class _PeriodicAction(BaseModel):
    kind: str
    node_ids: list[str] = Field(default_factory=list)
    reason: str | None = None


class _PeriodicActionEnvelope(BaseModel):
    analysis: str | None = None
    actions: list[_PeriodicAction] = Field(default_factory=list)


@dataclass(slots=True)
class _NodeExecutionOutcome:
    node_id: str
    periodic_tick_number: int | None = None
    periodic_actions: _PeriodicActionEnvelope | None = None
    periodic_action_parse_error: str | None = None


@dataclass(slots=True)
class _PeriodicNodeRuntimeState:
    tick_count: int = 0
    next_tick_at: float | None = None
    last_tick_started_at: str | None = None
    last_tick_started_mono: float | None = None
    waiting_for_actuation: bool = False


@dataclass(slots=True)
class Orchestrator:
    """Coordinate pipeline run lifecycles against the persistent run store.

    The orchestrator accepts submissions, starts bounded background workers, and
    advances each run by scheduling ready nodes until the run completes, fails, or
    is cancelled.
    """

    store: RunStore
    adapters: AdapterRegistry = default_adapter_registry
    runners: RunnerRegistry = default_runner_registry
    max_concurrent_runs: int = 2
    _run_slots: threading.Semaphore = field(init=False, repr=False)
    _cancel_flags: dict[str, threading.Event] = field(default_factory=dict, init=False, repr=False)
    _run_finished: dict[str, threading.Event] = field(default_factory=dict, init=False, repr=False)
    _node_cancel_flags: dict[str, set[str]] = field(default_factory=dict, init=False, repr=False)
    _pending_node_reruns: dict[str, set[str]] = field(default_factory=dict, init=False, repr=False)
    _scratchboards: dict[str, "Scratchboard"] = field(default_factory=dict, init=False, repr=False)
    _connector_manager: ConnectorManager = field(default_factory=ConnectorManager, init=False, repr=False)

    def __post_init__(self) -> None:
        self._run_slots = threading.Semaphore(self.max_concurrent_runs)
        self._inject_shared_resource_manager()

    def _inject_shared_resource_manager(self) -> None:
        """Give EC2 and ECS runners a shared resource manager."""
        from agentflow.cloud.shared import SharedResourceManager

        manager = SharedResourceManager()
        for kind in ("ec2", "ecs"):
            try:
                runner = self.runners.get(kind)
                runner._shared_manager = manager
            except KeyError:
                pass

    @staticmethod
    def _reset_node_for_cycle(record: "RunRecord", node_id: str, remaining: set[str]) -> None:
        """Reset a node to PENDING so it can be re-executed in a cycle."""
        node_result = record.nodes.get(node_id)
        if node_result is None:
            return
        node_result.status = NodeStatus.PENDING
        node_result.finished_at = None
        node_result.output = None
        node_result.structured_output = None
        node_result.exit_code = None
        node_result.success = None
        node_result.success_details = []
        remaining.add(node_id)

    @staticmethod
    def _nodes_between(node_map: dict[str, "NodeSpec"], start_id: str, end_id: str) -> list[str]:
        """Find node IDs on the path from start to end (exclusive of both endpoints)."""
        # BFS forward from start following depends_on edges in reverse
        reverse_deps: dict[str, list[str]] = {}
        for nid, node in node_map.items():
            for dep in node.depends_on:
                reverse_deps.setdefault(dep, []).append(nid)

        visited: set[str] = set()
        queue = [start_id]
        while queue:
            current = queue.pop(0)
            for downstream in reverse_deps.get(current, []):
                if downstream == end_id:
                    continue
                if downstream not in visited:
                    visited.add(downstream)
                    queue.append(downstream)
        return [nid for nid in visited if nid != start_id]

    def _register_shared_resources(self, pipeline: "PipelineSpec") -> None:
        """Scan nodes for shared targets and pre-register expected ref counts."""
        from collections import Counter

        shared_counts: Counter[str] = Counter()
        for node in pipeline.nodes:
            shared_id = getattr(node.target, "shared", None)
            if shared_id:
                shared_counts[shared_id] += 1

        if shared_counts:
            for kind in ("ec2", "ecs"):
                try:
                    runner = self.runners.get(kind)
                    mgr = getattr(runner, "_shared_manager", None)
                    if mgr:
                        for sid, count in shared_counts.items():
                            mgr.register_expected(sid, count)
                except KeyError:
                    pass

    async def _prepare_inference_service(self, run_id: str, record: RunRecord) -> None:
        setup = record.pipeline.inference
        if setup is None:
            return

        target_nodes = [
            node
            for node in record.pipeline.nodes
            if builtin_agent_kind(node.agent) == AgentKind.PI and node.provider is None
        ]
        if not target_nodes:
            await self._publish(
                run_id,
                "inference_skipped",
                reason="no_pi_nodes_without_provider",
            )
            return

        from agentflow import inference as inference_module

        request = inference_module.SkyInferenceServiceRequest(
            model_id=setup.model,
            gpu=inference_module.parse_gpu_selector(setup.gpu),
            engine=setup.engine,
            use_spot=setup.use_spot,
            max_hourly_cost=setup.max_hourly_cost,
            image_id=setup.image_id,
            name=setup.name,
            cluster_name=setup.cluster_name,
            api_key=setup.api_key,
            port=setup.port,
            idle_minutes_to_autostop=setup.idle_minutes_to_autostop,
            retry_until_up=setup.retry_until_up,
            endpoint_timeout_seconds=setup.endpoint_timeout_seconds,
        )
        await self._publish(
            run_id,
            "inference_starting",
            model=setup.model,
            gpu=setup.gpu,
            engine=setup.engine,
            use_spot=setup.use_spot,
            target_nodes=[node.id for node in target_nodes],
        )
        service = await asyncio.to_thread(inference_module.launch_sky_inference_service, request)
        provider = ProviderConfig.model_validate(service.provider)
        default_model = f"{provider.name}/{setup.model}" if provider.name else setup.model

        injected_nodes: list[str] = []
        for node in target_nodes:
            node.provider = provider
            if node.model is None:
                node.model = default_model
            injected_nodes.append(node.id)

        pi_defaults = record.pipeline.agent_defaults.setdefault(AgentKind.PI, {})
        pi_defaults.setdefault("provider", provider.model_dump(mode="json"))
        pi_defaults.setdefault("model", default_model)

        await self._publish(
            run_id,
            "inference_ready",
            name=service.name,
            cluster_name=service.cluster_name,
            base_url=service.base_url,
            model=setup.model,
            provider=self._sanitize_launch_value("provider", provider.model_dump(mode="json")),
            injected_nodes=injected_nodes,
        )
        await self.store.persist_run(run_id)

    async def _fail_setup(
        self,
        run_id: str,
        exc: Exception,
        *,
        skip_reason: str,
        event_type: str,
    ) -> RunRecord:
        record = self.store.get_run(run_id)
        finished_at = utcnow_iso()
        record.status = RunStatus.FAILED
        record.finished_at = finished_at
        for node_id, result in record.nodes.items():
            if result.status in {NodeStatus.PENDING, NodeStatus.QUEUED, NodeStatus.READY}:
                result.status = NodeStatus.SKIPPED
                result.finished_at = finished_at
                await self._publish(run_id, "node_skipped", node_id=node_id, reason=skip_reason)
        await self._publish(run_id, event_type, error=str(exc))
        await self._publish(run_id, "run_completed", status=record.status.value)
        await self.store.clear_cancel_request(run_id)
        await self.store.persist_run(run_id)
        self._node_cancel_flags.pop(run_id, None)
        self._pending_node_reruns.pop(run_id, None)
        return record

    async def _prepare_connectors(self, run_id: str, record: RunRecord) -> None:
        if not record.pipeline.connectors:
            return
        await self._publish(
            run_id,
            "connectors_starting",
            connectors=[connector.name for connector in record.pipeline.connectors],
        )
        await self._connector_manager.start(
            run_id,
            record.pipeline,
            self.store.run_dir(run_id),
        )
        await self._publish(
            run_id,
            "connectors_ready",
            connectors=[connector.name for connector in record.pipeline.connectors],
        )
        await self.store.persist_run(run_id)

    async def _prepare_source_snapshot(self, run_id: str, record: RunRecord) -> None:
        source = record.pipeline.source_snapshot
        if source is None:
            return

        from agentflow.worktree import create_pinned_worktree, remove_worktree, repository_root, resolve_commit

        requested_workdir = record.pipeline.working_path
        repo_dir = await asyncio.to_thread(repository_root, requested_workdir)
        relative_workdir = requested_workdir.relative_to(repo_dir)
        commit_sha = await asyncio.to_thread(resolve_commit, repo_dir, source.input_ref)
        worktree_dir = await asyncio.to_thread(create_pinned_worktree, repo_dir, run_id, commit_sha)
        try:
            record.pipeline.working_dir = str(worktree_dir / relative_workdir)
            record.source_snapshot = SourceSnapshotSpec(
                repositoryUrl=source.repository_url,
                inputRef=source.input_ref,
                commitSha=commit_sha,
            )
            payload = record.source_snapshot.model_dump(mode="json", by_alias=True)
            await self.store.write_run_artifact_json(run_id, "source-snapshot.json", payload)
            await self._publish(run_id, "source_snapshot_persisted", source_snapshot=payload)
            await self.store.persist_run(run_id)
        except Exception:
            await asyncio.to_thread(remove_worktree, repo_dir, worktree_dir)
            raise

    async def _remove_source_worktree(self, run_id: str, record: RunRecord) -> None:
        source = record.source_snapshot
        declared = record.declared_pipeline or record.pipeline
        if source is None or declared.source_snapshot is None:
            return
        from agentflow.worktree import remove_worktree, repository_root

        repo_dir = await asyncio.to_thread(repository_root, declared.working_path)
        worktree_dir = repo_dir / ".agentflow" / "worktrees" / run_id / "source"
        await asyncio.to_thread(remove_worktree, repo_dir, worktree_dir)

    def _initialize_run_tracking(self, run_id: str, *, cancel_flag: threading.Event | None = None) -> None:
        self._cancel_flags[run_id] = cancel_flag or threading.Event()
        self._run_finished[run_id] = threading.Event()
        self._node_cancel_flags[run_id] = set()
        self._pending_node_reruns[run_id] = set()

    async def _create_queued_run(
        self,
        pipeline: PipelineSpec,
        *,
        cancel_flag: threading.Event | None = None,
        optimization_parent_run_id: str | None = None,
        optimization_round: int | None = None,
        optimization_session: dict[str, Any] | None = None,
    ) -> RunRecord:
        run_id = self.store.new_run_id()
        self._initialize_run_tracking(run_id, cancel_flag=cancel_flag)
        declared_pipeline = pipeline.model_copy(deep=True)
        execution_pipeline = declared_pipeline.model_copy(deep=True)
        run = RunRecord(
            id=run_id,
            status=RunStatus.QUEUED,
            pipeline=execution_pipeline,
            declared_pipeline=declared_pipeline,
            optimization_parent_run_id=optimization_parent_run_id,
            optimization_round=optimization_round,
            optimization_session=deepcopy(optimization_session),
            nodes={
                node.id: NodeResult(node_id=node.id, status=NodeStatus.PENDING)
                for node in execution_pipeline.nodes
            },
        )
        await self.store.create_run(run)
        await self._publish(run_id, "run_queued", pipeline=execution_pipeline.model_dump(mode="json"))
        return run

    def _start_background(self, run_id: str, entrypoint: Callable[[], Any]) -> None:
        async def _guarded_entrypoint() -> None:
            try:
                await entrypoint()
            except Exception as exc:  # noqa: BLE001 - finalize the persisted run after scheduler crashes.
                await self._fail_unhandled_run(run_id, exc)

        def _background() -> None:
            acquired = False
            try:
                while not acquired:
                    if self._should_cancel(run_id):
                        asyncio.run(self._finalize_cancelled_queue_run(run_id))
                        return
                    acquired = self._run_slots.acquire(timeout=0.1)
                asyncio.run(_guarded_entrypoint())
            finally:
                if acquired:
                    self._run_slots.release()
                self._run_finished[run_id].set()

        threading.Thread(target=_background, name=f"agentflow-{run_id}", daemon=True).start()

    async def _cleanup_run_resources(self, run_id: str) -> None:
        record = self.store.get_run(run_id)
        if record.pipeline.connectors:
            try:
                await self._connector_manager.stop(run_id)
                if not any(event.type == "connectors_stopped" for event in self.store.get_events(run_id)):
                    await self._publish(
                        run_id,
                        "connectors_stopped",
                        connectors=[connector.name for connector in record.pipeline.connectors],
                    )
            except Exception as exc:  # noqa: BLE001 - cleanup remains best effort.
                await self._publish(run_id, "connectors_stop_failed", error=str(exc))
        try:
            await self._remove_source_worktree(run_id, record)
        except Exception as exc:  # noqa: BLE001 - cleanup remains best effort.
            await self._publish(run_id, "source_worktree_cleanup_failed", error=str(exc))

    async def _fail_unhandled_run(self, run_id: str, exc: Exception) -> None:
        record = self.store.get_run(run_id)
        if record.status in {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED}:
            return
        finished_at = utcnow_iso()
        record.status = RunStatus.FAILED
        record.finished_at = finished_at
        for result in record.nodes.values():
            if result.status not in _TERMINAL_NODE_STATUSES:
                result.status = NodeStatus.SKIPPED
                result.finished_at = finished_at
        await self._publish(run_id, "scheduler_failed", error=str(exc))
        await self._publish(run_id, "run_completed", status=record.status.value)
        await self.store.clear_cancel_request(run_id)
        await self.store.persist_run(run_id)

    def _graph_optimization_round_dir(self, parent_run_id: str, round_number: int) -> Path:
        return ensure_dir(self.store.run_dir(parent_run_id) / "optimization" / f"round-{round_number:03d}")

    async def _fail_graph_optimization_session(
        self,
        parent_run_id: str,
        *,
        error: str,
        round_number: int,
        round_dir: Path,
    ) -> RunRecord:
        record = self.store.get_run(parent_run_id)
        record.status = RunStatus.FAILED
        record.finished_at = utcnow_iso()
        write_validation_result(round_dir / OPTIMIZER_VALIDATION_FILENAME, ok=False, error=error)
        await self._publish(
            parent_run_id,
            "optimization_failed",
            round_number=round_number,
            error=error,
            round_dir=str(round_dir),
        )
        await self._publish(parent_run_id, "run_completed", status=record.status.value)
        await self.store.clear_cancel_request(parent_run_id)
        await self.store.persist_run(parent_run_id)
        self._node_cancel_flags.pop(parent_run_id, None)
        self._pending_node_reruns.pop(parent_run_id, None)
        return record

    async def _run_graph_optimization_session(self, parent_run_id: str) -> RunRecord:
        parent = self.store.get_run(parent_run_id)
        optimizer_name = parent.pipeline.optimizer or ""
        optimizer_kind = builtin_agent_kind(optimizer_name)
        if optimizer_kind is None:
            return await self._fail_graph_optimization_session(
                parent_run_id,
                error=f"invalid optimizer `{optimizer_name}`",
                round_number=0,
                round_dir=self.store.run_dir(parent_run_id),
            )

        parent.status = RunStatus.RUNNING
        parent.started_at = utcnow_iso()
        await self._publish(parent_run_id, "run_started", pipeline=parent.pipeline.model_dump(mode="json"))
        await self.store.persist_run(parent_run_id)

        optimization_session = dict(parent.optimization_session or {})
        optimization_session.setdefault("kind", "graph")
        optimization_session.setdefault("optimizer", optimizer_name)
        optimization_session.setdefault("total_rounds", parent.pipeline.n_run)
        optimization_session.setdefault("current_round", 0)
        optimization_session.setdefault("child_run_ids", [])
        optimization_session.setdefault("latest_pipeline_path", None)
        parent.optimization_session = optimization_session

        current_pipeline = parent.pipeline
        final_child: RunRecord | None = None

        def _optimizer_failure_summary(
            label: str,
            *,
            exit_code: int | None = None,
            stdout: str | None = None,
            stderr: str | None = None,
            error: str | None = None,
        ) -> str:
            if error is not None:
                pieces = [error]
            else:
                suffix = f" exited with code {exit_code}" if exit_code is not None else " failed"
                pieces = [f"{label}{suffix}."]
            normalized_stdout = (stdout or "").strip()
            normalized_stderr = (stderr or "").strip()
            if normalized_stdout:
                pieces.append(f"stdout:\n{normalized_stdout}")
            if normalized_stderr:
                pieces.append(f"stderr:\n{normalized_stderr}")
            return "\n\n".join(pieces)

        for round_number in range(1, current_pipeline.n_run + 1):
            if self._should_cancel(parent_run_id):
                break

            round_dir = self._graph_optimization_round_dir(parent_run_id, round_number)
            pipeline_path = round_dir / GENERATED_PIPELINE_FILENAME
            write_editable_pipeline_python(pipeline_path, current_pipeline)
            write_editable_pipeline_python(round_dir / GENERATED_PIPELINE_ORIGINAL_FILENAME, current_pipeline)

            optimization_session["current_round"] = round_number
            optimization_session["latest_pipeline_path"] = str(pipeline_path)
            parent.optimization_session = optimization_session
            parent.pipeline = current_pipeline
            await self._publish(
                parent_run_id,
                "optimization_round_started",
                round_number=round_number,
                total_rounds=current_pipeline.n_run,
                round_dir=str(round_dir),
            )
            await self.store.persist_run(parent_run_id)

            child_pipeline = current_pipeline.model_copy(update={"optimizer": None, "n_run": 1})
            child = await self._create_queued_run(
                child_pipeline,
                cancel_flag=self._cancel_flags[parent_run_id],
                optimization_parent_run_id=parent_run_id,
                optimization_round=round_number,
            )
            optimization_session["child_run_ids"].append(child.id)
            parent.optimization_session = optimization_session
            await self._publish(
                parent_run_id,
                "optimization_child_run_created",
                round_number=round_number,
                child_run_id=child.id,
            )
            await self.store.persist_run(parent_run_id)

            try:
                final_child = await self.run(child.id)
            except Exception as exc:  # noqa: BLE001 - persist a terminal child before optimizing.
                await self._fail_unhandled_run(child.id, exc)
                final_child = self.store.get_run(child.id)
            finally:
                self._run_finished[child.id].set()

            parent.nodes = deepcopy(final_child.nodes)
            parent.pipeline = current_pipeline
            await self._publish(
                parent_run_id,
                "optimization_round_completed",
                round_number=round_number,
                child_run_id=final_child.id,
                child_status=final_child.status.value,
            )

            traces_dir = ensure_dir(round_dir / "traces")
            copied_traces = copy_run_traces(final_child, self.store, traces_dir)
            graph_report = build_graph_report(
                parent_run_id=parent_run_id,
                round_number=round_number,
                total_rounds=current_pipeline.n_run,
                run=final_child,
                store=self.store,
                copied_traces=copied_traces,
            )
            (round_dir / GRAPH_REPORT_FILENAME).write_text(json.dumps(graph_report, ensure_ascii=False, indent=2), encoding="utf-8")
            await self.store.persist_run(parent_run_id)

            if round_number >= current_pipeline.n_run or self._should_cancel(parent_run_id):
                continue

            failure_summary: str | None = None
            loaded_pipeline: PipelineSpec | None = None
            for attempt_number in range(1, GRAPH_OPTIMIZER_MAX_ATTEMPTS + 1):
                attempt_dir = ensure_dir(round_dir / "attempts" / f"attempt-{attempt_number:03d}")
                prompt = render_graph_optimizer_prompt(
                    optimizer=optimizer_name,
                    pipeline_path=pipeline_path,
                    graph_report_path=round_dir / GRAPH_REPORT_FILENAME,
                    traces_dir=traces_dir,
                    round_number=round_number,
                    total_rounds=current_pipeline.n_run,
                    attempt_number=attempt_number,
                    max_attempts=GRAPH_OPTIMIZER_MAX_ATTEMPTS,
                    previous_failure=failure_summary,
                )
                (attempt_dir / OPTIMIZER_PROMPT_FILENAME).write_text(prompt, encoding="utf-8")
                (round_dir / OPTIMIZER_PROMPT_FILENAME).write_text(prompt, encoding="utf-8")
                await self._publish(
                    parent_run_id,
                    "optimization_optimizer_started",
                    round_number=round_number,
                    optimizer=optimizer_name,
                    attempt_number=attempt_number,
                    max_attempts=GRAPH_OPTIMIZER_MAX_ATTEMPTS,
                )
                optimizer_result = _run_optimizer(
                    optimizer_kind,
                    prompt=prompt,
                    repo_dir=round_dir,
                    runtime_dir=attempt_dir / "optimizer-runtime",
                    env={},
                )
                write_optimizer_result(
                    attempt_dir / OPTIMIZER_RESULT_FILENAME,
                    command=optimizer_result.command,
                    exit_code=optimizer_result.exit_code,
                    stdout=optimizer_result.stdout,
                    stderr=optimizer_result.stderr,
                )
                write_optimizer_result(
                    round_dir / OPTIMIZER_RESULT_FILENAME,
                    command=optimizer_result.command,
                    exit_code=optimizer_result.exit_code,
                    stdout=optimizer_result.stdout,
                    stderr=optimizer_result.stderr,
                )
                if pipeline_path.exists():
                    edited_text = pipeline_path.read_text(encoding="utf-8")
                    (attempt_dir / GENERATED_PIPELINE_EDITED_FILENAME).write_text(edited_text, encoding="utf-8")
                    (round_dir / GENERATED_PIPELINE_EDITED_FILENAME).write_text(edited_text, encoding="utf-8")
                if optimizer_result.exit_code != 0:
                    failure_summary = _optimizer_failure_summary(
                        "Optimizer",
                        exit_code=optimizer_result.exit_code,
                        stdout=optimizer_result.stdout,
                        stderr=optimizer_result.stderr,
                    )
                    write_validation_result(attempt_dir / OPTIMIZER_VALIDATION_FILENAME, ok=False, error=failure_summary)
                    write_validation_result(round_dir / OPTIMIZER_VALIDATION_FILENAME, ok=False, error=failure_summary)
                else:
                    try:
                        loaded_pipeline = load_pipeline_from_path(pipeline_path)
                    except Exception as exc:
                        failure_summary = _optimizer_failure_summary(
                            "Optimized pipeline",
                            error=f"optimized pipeline failed to load: {exc}",
                        )
                        write_validation_result(
                            attempt_dir / OPTIMIZER_VALIDATION_FILENAME,
                            ok=False,
                            error=failure_summary,
                        )
                        write_validation_result(
                            round_dir / OPTIMIZER_VALIDATION_FILENAME,
                            ok=False,
                            error=failure_summary,
                        )
                    else:
                        write_validation_result(attempt_dir / OPTIMIZER_VALIDATION_FILENAME, ok=True)
                        write_validation_result(round_dir / OPTIMIZER_VALIDATION_FILENAME, ok=True)
                        break

                if attempt_number < GRAPH_OPTIMIZER_MAX_ATTEMPTS:
                    await self._publish(
                        parent_run_id,
                        "optimization_optimizer_retrying",
                        round_number=round_number,
                        attempt_number=attempt_number,
                        error=failure_summary,
                    )

            if loaded_pipeline is None:
                return await self._fail_graph_optimization_session(
                    parent_run_id,
                    error=failure_summary or "optimizer failed to produce a valid pipeline",
                    round_number=round_number,
                    round_dir=round_dir,
                )

            current_pipeline = loaded_pipeline.model_copy(
                update={"optimizer": optimizer_name, "n_run": parent.pipeline.n_run}
            )
            parent.pipeline = current_pipeline
            await self._publish(
                parent_run_id,
                "optimization_pipeline_accepted",
                round_number=round_number,
                attempt_number=attempt_number,
                optimizer_output=_parse_agent_output(
                    optimizer_kind,
                    f"graph_optimizer_{parent_run_id}_{round_number}",
                    optimizer_result.stdout,
                ),
            )
            await self.store.persist_run(parent_run_id)

        if self._should_cancel(parent_run_id):
            parent.status = RunStatus.CANCELLED
        elif final_child is None:
            parent.status = RunStatus.FAILED
        elif final_child.status == RunStatus.CANCELLED:
            parent.status = RunStatus.CANCELLED
        elif final_child.status == RunStatus.FAILED:
            parent.status = RunStatus.FAILED
        else:
            parent.status = RunStatus.COMPLETED

        parent.finished_at = utcnow_iso()
        await self._publish(parent_run_id, "run_completed", status=parent.status.value)
        await self.store.clear_cancel_request(parent_run_id)
        await self.store.persist_run(parent_run_id)
        self._node_cancel_flags.pop(parent_run_id, None)
        self._pending_node_reruns.pop(parent_run_id, None)
        return parent

    async def submit(self, pipeline: PipelineSpec) -> RunRecord:
        """Create a queued run and start its background scheduler when a slot opens.

        Returns the newly created `RunRecord` with all nodes initialized as pending.
        """
        optimization_session = None
        if pipeline.uses_graph_optimizer:
            optimization_session = {
                "kind": "graph",
                "optimizer": pipeline.optimizer,
                "total_rounds": pipeline.n_run,
                "current_round": 0,
                "child_run_ids": [],
                "latest_pipeline_path": None,
            }
        run = await self._create_queued_run(pipeline, optimization_session=optimization_session)
        if pipeline.uses_graph_optimizer:
            self._start_background(run.id, lambda: self._run_graph_optimization_session(run.id))
        else:
            self._start_background(run.id, lambda: self.run(run.id))
        return run

    async def wait(self, run_id: str, timeout: float | None = None) -> RunRecord:
        terminal = {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED}

        async def _poll() -> RunRecord:
            while True:
                record = self.store.get_run(run_id)
                if record.status in terminal:
                    finished = self._run_finished.get(run_id)
                    if finished is None or finished.is_set():
                        return record
                await asyncio.sleep(0.05)

        if timeout is None:
            return await _poll()
        return await asyncio.wait_for(_poll(), timeout=timeout)

    async def cancel(self, run_id: str) -> RunRecord:
        """Request cancellation for a run.

        Queued runs are finalized immediately; active runs are marked cancelling and
        observed cooperatively by the run loop and executing nodes.
        """

        record = self.store.get_run(run_id)
        flag = self._cancel_flags.setdefault(run_id, threading.Event())
        flag.set()
        await self.store.request_cancel(run_id)
        if record.status == RunStatus.QUEUED:
            await self._finalize_cancelled_queue_run(run_id)
            return self.store.get_run(run_id)
        if record.status in {RunStatus.RUNNING, RunStatus.PENDING}:
            record.status = RunStatus.CANCELLING
            await self._publish(run_id, "run_cancelling")
            await self.store.persist_run(run_id)
        return record

    async def rerun(self, run_id: str) -> RunRecord:
        """Submit a fresh run using the stored pipeline from an existing run.

        Returns the new queued `RunRecord`; prior run state is left unchanged.
        """

        record = self.store.get_run(run_id)
        return await self.submit(record.declared_pipeline or record.pipeline)

    async def resume(self, run_id: str) -> RunRecord:
        """Resume a failed/cancelled run, preserving completed node results.

        Creates a new run that copies completed node outputs and scratchboard
        from the original run. Failed/cancelled/skipped nodes are reset to
        pending so the pipeline continues from the point of failure.

        Returns the new queued ``RunRecord``.
        """
        import shutil

        old_record = self.store.get_run(run_id)
        if old_record.status not in {RunStatus.FAILED, RunStatus.CANCELLED}:
            raise ValueError(
                f"Can only resume failed or cancelled runs, but run `{run_id}` has status `{old_record.status.value}`"
            )

        pipeline = (old_record.declared_pipeline or old_record.pipeline).model_copy(deep=True)
        if pipeline.source_snapshot is not None:
            raise ValueError(
                "resume is not supported for source-pinned runs; use rerun to resolve one fresh snapshot"
            )
        if any(
            node.fanout_from is not None and node.fanout_from.connector is not None
            for node in pipeline.nodes
        ):
            raise ValueError(
                "resume is not supported for connector-backed runtime fan-out; use rerun to start a fresh run"
            )
        new_run_id = self.store.new_run_id()

        # Build node results: completed nodes keep their results; others reset to pending
        nodes: dict[str, NodeResult] = {}
        for node in pipeline.nodes:
            old_node = old_record.nodes.get(node.id)
            if old_node is not None and old_node.status == NodeStatus.COMPLETED:
                # Preserve the completed node result as-is
                nodes[node.id] = old_node.model_copy()
            else:
                nodes[node.id] = NodeResult(node_id=node.id, status=NodeStatus.PENDING)

        new_run = RunRecord(
            id=new_run_id,
            status=RunStatus.QUEUED,
            pipeline=pipeline.model_copy(deep=True),
            declared_pipeline=pipeline.model_copy(deep=True),
            nodes=nodes,
        )

        self._cancel_flags[new_run_id] = threading.Event()
        self._run_finished[new_run_id] = threading.Event()
        self._node_cancel_flags[new_run_id] = set()
        self._pending_node_reruns[new_run_id] = set()
        await self.store.create_run(new_run)

        # Copy scratchboard from old run if it exists
        old_run_dir = self.store.run_dir(run_id)
        new_run_dir = self.store.run_dir(new_run_id)
        from agentflow.scratchboard import SCRATCHBOARD_FILENAME
        old_sb = old_run_dir / SCRATCHBOARD_FILENAME
        if old_sb.exists():
            shutil.copy2(str(old_sb), str(new_run_dir / SCRATCHBOARD_FILENAME))

        # Copy artifacts for completed nodes
        old_artifacts = old_run_dir / "artifacts"
        new_artifacts = new_run_dir / "artifacts"
        for node_id, node_result in nodes.items():
            if node_result.status == NodeStatus.COMPLETED:
                src = old_artifacts / node_id
                if src.is_dir():
                    dst = new_artifacts / node_id
                    dst.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(str(src), str(dst), dirs_exist_ok=True)

        await self._publish(new_run_id, "run_queued", pipeline=pipeline.model_dump(mode="json"),
                            resumed_from=run_id)

        self._start_background(new_run_id, lambda: self.run(new_run_id))
        return new_run

    async def _validate_recovery_source(self, run_id: str, record: RunRecord) -> None:
        declared = record.declared_pipeline or record.pipeline
        requested_source = declared.source_snapshot
        if requested_source is None:
            return
        source = record.source_snapshot
        if source is None or source.commit_sha is None:
            raise ValueError(
                f"run `{run_id}` has no persisted source commit and cannot be recovered in place"
            )

        from agentflow.worktree import repository_root

        repo_dir = await asyncio.to_thread(repository_root, declared.working_path)
        relative_workdir = declared.working_path.relative_to(repo_dir)
        worktree_dir = repo_dir / ".agentflow" / "worktrees" / run_id / "source"
        expected_workdir = (worktree_dir / relative_workdir).resolve()
        if record.pipeline.working_path.resolve() != expected_workdir:
            raise ValueError(
                f"run `{run_id}` does not reference its persisted source worktree"
            )
        if not worktree_dir.is_dir():
            raise ValueError(
                f"run `{run_id}` source worktree is missing: {worktree_dir}"
            )

        def inspect_worktree() -> tuple[str, str]:
            head = subprocess.run(
                ["git", "-C", str(worktree_dir), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            status = subprocess.run(
                ["git", "-C", str(worktree_dir), "status", "--porcelain=v1", "--untracked-files=all"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            return head, status

        try:
            head, status = await asyncio.to_thread(inspect_worktree)
        except (OSError, subprocess.CalledProcessError) as exc:
            raise ValueError(
                f"run `{run_id}` source worktree could not be verified"
            ) from exc
        if head != source.commit_sha:
            raise ValueError(
                f"run `{run_id}` source worktree is at {head}, expected {source.commit_sha}"
            )
        if status:
            raise ValueError(f"run `{run_id}` source worktree has local changes")

        snapshot_path = self.store.run_artifact_dir(run_id) / "source-snapshot.json"
        try:
            artifact = SourceSnapshotSpec.model_validate_json(
                snapshot_path.read_text(encoding="utf-8")
            )
        except (OSError, ValidationError) as exc:
            raise ValueError(
                f"run `{run_id}` source snapshot artifact is missing or invalid"
            ) from exc
        if artifact != source:
            raise ValueError(
                f"run `{run_id}` source snapshot artifact does not match persisted run state"
            )
        if (
            source.repository_url != requested_source.repository_url
            or source.input_ref != requested_source.input_ref
        ):
            raise ValueError(
                f"run `{run_id}` source snapshot does not match its declared source"
            )

    async def recover(
        self,
        run_id: str,
        *,
        completed_nodes: set[str] | None = None,
    ) -> RunRecord:
        """Continue an interrupted run in place after validating durable state.

        Unlike :meth:`resume`, recovery preserves the run ID, resolved pipeline,
        source snapshot, runtime fan-out, events, attempts, and artifacts. The
        caller must ensure no other scheduler is driving the run.
        """

        record = self.store.get_run(run_id)
        if record.status == RunStatus.COMPLETED:
            raise ValueError(f"run `{run_id}` is already completed")
        active = self._run_finished.get(run_id)
        if active is not None and not active.is_set():
            raise ValueError(f"run `{run_id}` already has an active scheduler")

        promoted = set(completed_nodes or set())
        unknown = sorted(promoted - set(record.nodes))
        if unknown:
            raise ValueError(f"unknown recovery node IDs: {unknown}")
        await self._validate_recovery_source(run_id, record)

        recovered_at = utcnow_iso()
        preserved: list[str] = []
        reset: list[str] = []
        for node_id, result in record.nodes.items():
            if result.status == NodeStatus.COMPLETED:
                preserved.append(node_id)
                continue
            for attempt in result.attempts:
                if attempt.status in {
                    NodeStatus.RUNNING,
                    NodeStatus.QUEUED,
                    NodeStatus.READY,
                    NodeStatus.RETRYING,
                }:
                    attempt.status = NodeStatus.CANCELLED
                    attempt.finished_at = attempt.finished_at or recovered_at
            if node_id in promoted:
                result.status = NodeStatus.COMPLETED
                result.success = True
                result.finished_at = recovered_at
                result.current_attempt = len(result.attempts)
                result.next_scheduled_at = None
                result.success_details = [
                    *result.success_details,
                    "externally verified durable completion during in-place recovery",
                ]
                await self._publish(
                    run_id,
                    "node_recovery_completed",
                    node_id=node_id,
                    externally_verified=True,
                )
                await self.store.write_artifact_json(
                    run_id,
                    node_id,
                    "result.json",
                    result.model_dump(mode="json"),
                )
                continue
            result.status = NodeStatus.PENDING
            result.finished_at = None
            result.current_attempt = len(result.attempts)
            result.next_scheduled_at = None
            result.success = None
            result.exit_code = None
            reset.append(node_id)

        record.status = RunStatus.QUEUED
        record.finished_at = None
        self._initialize_run_tracking(run_id)
        await self.store.clear_cancel_request(run_id)
        await self._publish(
            run_id,
            "run_recovery_queued",
            preserved_nodes=preserved,
            promoted_nodes=sorted(promoted),
            reset_nodes=reset,
        )
        await self.store.persist_run(run_id)
        self._start_background(run_id, lambda: self.run(run_id, recovering=True))
        return record

    def _should_cancel(self, run_id: str) -> bool:
        if self._cancel_flags.get(run_id, threading.Event()).is_set():
            return True
        return self.store.cancel_requested(run_id)

    def _should_cancel_node(self, run_id: str, node_id: str) -> bool:
        return node_id in self._node_cancel_flags.get(run_id, set())

    async def _finalize_cancelled_queue_run(self, run_id: str) -> None:
        record = self.store.get_run(run_id)
        record.status = RunStatus.CANCELLED
        record.finished_at = utcnow_iso()
        for node in record.nodes.values():
            if node.status in {NodeStatus.PENDING, NodeStatus.QUEUED, NodeStatus.READY}:
                node.status = NodeStatus.CANCELLED
                node.finished_at = record.finished_at
        await self._publish(run_id, "run_completed", status=record.status.value)
        await self.store.clear_cancel_request(run_id)
        await self.store.persist_run(run_id)

    def _build_paths(self, pipeline: PipelineSpec, run_id: str, node_id: str, node_target: Any) -> ExecutionPaths:
        return build_execution_paths(
            base_dir=self.store.base_dir,
            pipeline_workdir=pipeline.working_path,
            run_id=run_id,
            node_id=node_id,
            node_target=node_target,
        )

    async def _publish(self, run_id: str, event_type: str, *, node_id: str | None = None, **data: Any) -> None:
        await self.store.append_event(run_id, RunEvent(run_id=run_id, type=event_type, node_id=node_id, data=data))

    async def _publish_trace(self, run_id: str, node_id: str, event) -> None:
        await self.store.append_artifact_text_bounded(
            run_id,
            node_id,
            "trace.jsonl",
            event.model_dump_json() + "\n",
            max_bytes=TRACE_ARTIFACT_MAX_BYTES,
            truncation_marker=TRACE_ARTIFACT_TRUNCATION_MARKER,
        )
        run_event = RunEvent(
            run_id=run_id,
            type="node_trace",
            node_id=node_id,
            data={"trace": event.model_dump(mode="json")},
        )
        if event.kind in _TRANSIENT_TRACE_KINDS:
            await self.store.publish_transient_event(run_id, run_event)
        else:
            await self.store.append_event(run_id, run_event)

    def _is_sensitive_launch_key(self, key: str) -> bool:
        return looks_sensitive_key(key)

    def _sanitize_launch_value(self, key: str | None, value: Any) -> Any:
        if key and self._is_sensitive_launch_key(key) and value is not None:
            return "<redacted>"
        if isinstance(value, dict):
            if key == "runtime_files":
                return sorted(value)
            return {inner_key: self._sanitize_launch_value(inner_key, inner_value) for inner_key, inner_value in value.items()}
        if isinstance(value, list):
            return [self._sanitize_launch_value(None, item) for item in value]
        return value

    def _launch_artifact_payload(self, attempt_number: int, plan: Any) -> dict[str, Any]:
        return {
            "attempt": attempt_number,
            "kind": plan.kind,
            "command": redact_sensitive_shell_value(list(plan.command)) if plan.command is not None else None,
            "env": self._sanitize_launch_value("env", plan.env),
            "cwd": plan.cwd,
            "stdin": plan.stdin,
            "runtime_files": list(plan.runtime_files),
            "payload": self._sanitize_launch_value("payload", plan.payload),
        }

    async def _write_launch_artifacts(self, run_id: str, node_id: str, attempt_number: int, plan: Any) -> None:
        payload = self._launch_artifact_payload(attempt_number, plan)
        await self.store.write_artifact_json(run_id, node_id, "launch.json", payload)
        await self.store.write_artifact_json(run_id, node_id, f"launch-attempt-{attempt_number}.json", payload)

    async def _mark_node_cancelled(self, run_id: str, node_id: str, reason: str) -> None:
        record = self.store.get_run(run_id)
        result = record.nodes[node_id]
        result.status = NodeStatus.CANCELLED
        result.finished_at = utcnow_iso()
        if reason == "run_cancelled":
            await self.store.append_artifact_text(run_id, node_id, "stderr.log", "Cancelled by user\n")
        await self._publish(run_id, "node_cancelled", node_id=node_id, reason=reason)

    def _normalize_periodic_output_text(self, text: str | None) -> str:
        normalized = str(text or "").strip()
        if normalized.startswith("```"):
            lines = normalized.splitlines()
            if len(lines) >= 3 and lines[-1].strip() == "```":
                normalized = "\n".join(lines[1:-1]).strip()
                if normalized.lower().startswith("json\n"):
                    normalized = normalized[5:].strip()
        return normalized

    def _parse_periodic_actions(
        self,
        text: str | None,
    ) -> tuple[_PeriodicActionEnvelope | None, str | None]:
        normalized = self._normalize_periodic_output_text(text)
        if not normalized:
            return _PeriodicActionEnvelope(), None
        try:
            payload = json.loads(normalized)
        except json.JSONDecodeError as exc:
            return None, f"invalid JSON control envelope: {exc}"
        try:
            return _PeriodicActionEnvelope.model_validate(payload), None
        except ValidationError as exc:  # pragma: no cover - pydantic error details vary
            return None, f"invalid control envelope: {exc}"

    def _fanout_group_settled(self, pipeline: PipelineSpec, results: dict[str, NodeResult], group_id: str) -> bool:
        member_ids = pipeline.fanouts.get(group_id, [])
        if not member_ids:
            return True
        return all(results[member_id].status in _TERMINAL_NODE_STATUSES for member_id in member_ids)

    async def _finalize_periodic_node(self, run_id: str, node_id: str, *, reason: str) -> None:
        record = self.store.get_run(run_id)
        result = record.nodes[node_id]
        if result.status == NodeStatus.COMPLETED:
            return
        result.status = NodeStatus.COMPLETED
        result.success = True if result.success is None else result.success
        result.next_scheduled_at = None
        result.finished_at = result.finished_at or utcnow_iso()
        await self._publish(
            run_id,
            "node_completed",
            node_id=node_id,
            tick_count=result.tick_count,
            reason=reason,
            output=result.output,
            final_response=result.final_response,
            success=result.success,
            success_details=result.success_details,
        )
        await self.store.write_artifact_text(run_id, node_id, "output.txt", result.output or "")
        await self.store.write_artifact_json(run_id, node_id, "result.json", result.model_dump(mode="json"))
        await self.store.persist_run(run_id)

    async def _apply_periodic_actions(
        self,
        run_id: str,
        controller_node_id: str,
        *,
        watched_group: str,
        actions: _PeriodicActionEnvelope,
        remaining: set[str],
        in_progress: dict[str, asyncio.Task["_NodeExecutionOutcome"]],
    ) -> None:
        """Apply controller actions emitted by a periodic node to its watched fanout.

        Cancel actions mark running nodes for cooperative stop, while rerun actions
        either requeue finished nodes immediately or defer rerun until in-flight work
        reaches a terminal state.
        """

        if not actions.actions:
            return

        record = self.store.get_run(run_id)
        allowed_node_ids = set(record.pipeline.fanouts.get(watched_group, []))

        ordered_actions = sorted(actions.actions, key=lambda item: 0 if item.kind == "cancel" else 1)
        applied: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []

        for action in ordered_actions:
            kind = action.kind.strip().lower()
            if kind not in {"cancel", "rerun"}:
                rejected.append({"kind": action.kind, "node_ids": list(action.node_ids), "reason": "unsupported_action"})
                continue
            for target_node_id in action.node_ids:
                if target_node_id not in allowed_node_ids:
                    rejected.append({"kind": kind, "node_id": target_node_id, "reason": "outside_watched_fanout"})
                    continue
                target_result = record.nodes[target_node_id]
                if kind == "cancel":
                    if target_result.status not in {NodeStatus.QUEUED, NodeStatus.RUNNING, NodeStatus.RETRYING}:
                        rejected.append({"kind": kind, "node_id": target_node_id, "reason": "node_not_running"})
                        continue
                    self._node_cancel_flags.setdefault(run_id, set()).add(target_node_id)
                    applied.append({"kind": kind, "node_id": target_node_id, "reason": action.reason})
                    continue

                if target_result.status in {NodeStatus.PENDING, NodeStatus.READY}:
                    rejected.append({"kind": kind, "node_id": target_node_id, "reason": "node_not_started"})
                    continue
                self._pending_node_reruns.setdefault(run_id, set()).add(target_node_id)
                if target_result.status in _TERMINAL_NODE_STATUSES and target_node_id not in in_progress:
                    target_result.status = NodeStatus.PENDING
                    target_result.next_scheduled_at = None
                    remaining.add(target_node_id)
                applied.append({"kind": kind, "node_id": target_node_id, "reason": action.reason})

        if applied:
            await self._publish(
                run_id,
                "node_control_actions_applied",
                node_id=controller_node_id,
                watched_group=watched_group,
                actions=applied,
            )
        if rejected:
            await self._publish(
                run_id,
                "node_control_actions_rejected",
                node_id=controller_node_id,
                watched_group=watched_group,
                actions=rejected,
            )

    async def _execute_node(
        self,
        run_id: str,
        node_id: str,
        *,
        periodic_tick_number: int | None = None,
        periodic_tick_started_at: str | None = None,
    ) -> _NodeExecutionOutcome:
        """Execute one node from prompt preparation through final persisted result.

        The method renders the prompt, launches the adapter/runner pair, streams
        traces and artifacts, evaluates success, retries with backoff when needed,
        and honors run or node cancellation. Periodic ticks also parse optional
        control actions and return them to the scheduler.
        """

        record = self.store.get_run(run_id)
        pipeline = record.pipeline
        node = pipeline.node_map[node_id]
        result = record.nodes[node_id]
        result.started_at = result.started_at or (periodic_tick_started_at or utcnow_iso())
        if periodic_tick_number is not None:
            result.tick_count = max(result.tick_count, periodic_tick_number)
            result.last_tick_started_at = periodic_tick_started_at
        result.status = NodeStatus.RUNNING
        await self._publish(run_id, "node_started", node_id=node_id)
        if periodic_tick_number is not None:
            await self._publish(
                run_id,
                "node_tick_started",
                node_id=node_id,
                tick_number=periodic_tick_number,
                tick_started_at=periodic_tick_started_at,
            )

        prompt = render_node_prompt(
            pipeline,
            node,
            record.nodes,
            run_id=run_id,
            artifacts_base_dir=self.store.base_dir,
            current_tick_number=periodic_tick_number,
            current_tick_started_at=periodic_tick_started_at,
        )
        contract_input = node.input
        if contract_input is not None:
            prompt += (
                "\n\nAgentFlow structured input (JSON):\n```json\n"
                + json.dumps(contract_input, ensure_ascii=False, indent=2)
                + "\n```"
            )
        execution_resolution = resolve_node_for_execution(node, pipeline.working_path)
        execution_node = execution_resolution.node
        runtime_agent = execution_resolution.runtime_agent
        # Create git worktree if enabled (local nodes only get a worktree directory)
        worktree_dir = None
        if pipeline.use_worktree and execution_node.target.kind == "local":
            from agentflow.worktree import create_worktree, is_git_repo
            if is_git_repo(pipeline.working_path):
                try:
                    worktree_dir = create_worktree(pipeline.working_path, node_id, run_id)
                    from types import SimpleNamespace
                    wt_target = SimpleNamespace(**{k: getattr(execution_node.target, k) for k in execution_node.target.model_fields})
                    wt_target.cwd = str(worktree_dir)
                    execution_node = SimpleNamespace(
                        id=execution_node.id, agent=execution_node.agent, prompt=execution_node.prompt,
                        target=wt_target, timeout_seconds=execution_node.timeout_seconds,
                        retries=execution_node.retries, retry_backoff_seconds=execution_node.retry_backoff_seconds,
                        retry_backoff_max_seconds=execution_node.retry_backoff_max_seconds,
                        retry_backoff_strategy=execution_node.retry_backoff_strategy,
                        success_criteria=execution_node.success_criteria, tools=execution_node.tools,
                        model=execution_node.model, capture=execution_node.capture, env=execution_node.env,
                        extra_args=execution_node.extra_args, provider=execution_node.provider,
                        mcps=execution_node.mcps, skills=execution_node.skills, schedule=execution_node.schedule,
                        connectors=execution_node.connectors,
                        connector_tools=execution_node.connector_tools,
                        connector_bindings=execution_node.connector_bindings,
                        connector_secret_env=execution_node.connector_secret_env,
                        input=execution_node.input,
                        output_artifact=execution_node.output_artifact,
                        concurrency_pool=execution_node.concurrency_pool,
                        durable_goal=execution_node.durable_goal,
                        fanout_from=execution_node.fanout_from,
                        fanout_group=execution_node.fanout_group, fanout_member=execution_node.fanout_member,
                        on_failure_restart=execution_node.on_failure_restart,
                        fanout_dependencies=getattr(execution_node, 'fanout_dependencies', {}),
                        executable=execution_node.executable,
                        description=execution_node.description,
                        repo_instructions_mode=execution_node.repo_instructions_mode,
                    )
                except Exception as exc:
                    await self._publish(run_id, "node_trace", node_id=node_id,
                        trace={"kind": "warning", "title": f"Worktree failed: {exc}"})

        paths = self._build_paths(pipeline, run_id, node_id, execution_node.target)

        # Inject scratchboard file location into prompt
        scratchboard = self._scratchboards.get(run_id)
        if scratchboard is not None:
            from agentflow.scratchboard import SCRATCHBOARD_FILENAME, SCRATCHBOARD_PROMPT_SUFFIX
            if execution_node.target.kind == "local":
                sb_path = str(scratchboard.path)
            else:
                sb_path = f"{paths.target_runtime_dir}/{SCRATCHBOARD_FILENAME}"
            prompt += SCRATCHBOARD_PROMPT_SUFFIX.format(scratchboard_path=sb_path)
        adapter = self.adapters.get(runtime_agent)
        if execution_node.durable_goal is not None and execution_node.durable_goal.mode == "native":
            raise ValueError(
                f"agent {runtime_agent.value!r} has no tested native durable-goal integration; use supervised mode"
            )
        runner = self.runners.get(execution_node.target.kind)
        adapter_node = _materialize_connector_mcps(execution_node)
        parser = create_trace_parser(runtime_agent, node.id)
        periodic_actions: _PeriodicActionEnvelope | None = None
        periodic_action_parse_error: str | None = None

        first_attempt_number = len(result.attempts) + 1
        for retry_index in range(node.retries + 1):
            attempt_number = first_attempt_number + retry_index
            if self._should_cancel(run_id) or self._should_cancel_node(run_id, node_id):
                reason = "run_cancelled" if self._should_cancel(run_id) else "node_cancelled"
                await self._mark_node_cancelled(run_id, node_id, reason)
                return _NodeExecutionOutcome(node_id=node_id, periodic_tick_number=periodic_tick_number)

            attempt = NodeAttempt(number=attempt_number, status=NodeStatus.RUNNING, started_at=utcnow_iso())
            attempt_stdout_lines = BoundedLineBuffer()
            attempt_stderr_lines = BoundedLineBuffer()
            result.current_attempt = attempt_number
            result.attempts.append(attempt)
            parser.start_attempt(attempt_number)
            attempt_prompt = prompt
            if (
                execution_node.durable_goal is not None
                and execution_node.durable_goal.mode == "supervised"
                and attempt_number > 1
            ):
                attempt_prompt += (
                    "\n\nAgentFlow supervised durable-goal resume: re-read durable connector state "
                    "and reuse the same idempotency keys."
                )
            prepared = adapter.prepare(adapter_node, attempt_prompt, paths)
            # Forward local credentials to remote targets when enabled
            # EC2/ECS: always forward (ephemeral, no pre-existing config)
            # SSH: only if forward_credentials=True (remote has its own identity)
            should_forward = (
                execution_node.target.kind in ("ec2", "ecs")
                or (execution_node.target.kind == "ssh" and getattr(execution_node.target, "forward_credentials", False))
            )
            if should_forward:
                from agentflow.cloud.aws import collect_local_credentials
                local_creds = collect_local_credentials(runtime_agent.value)
                merged = {**local_creds, **prepared.env}
                prepared = PreparedExecution(
                    command=prepared.command, env=merged, cwd=prepared.cwd,
                    trace_kind=prepared.trace_kind, runtime_files=prepared.runtime_files,
                    stdin=prepared.stdin,
                )
            # Inject scratchboard file into runtime_files for remote targets
            if scratchboard is not None and execution_node.target.kind not in ("local",):
                from agentflow.scratchboard import SCRATCHBOARD_FILENAME
                prepared.runtime_files[SCRATCHBOARD_FILENAME] = scratchboard.read()
            plan = runner.plan_execution(execution_node, prepared, paths)
            await self._write_launch_artifacts(run_id, node_id, attempt_number, plan)
            await self.store.append_artifact_text_bounded(
                run_id,
                node_id,
                "stdout.log",
                f"\n=== attempt {attempt_number} started {attempt.started_at} ===\n",
                max_bytes=STREAM_ARTIFACT_MAX_BYTES,
                truncation_marker=OUTPUT_TRUNCATION_MARKER,
            )
            await self.store.append_artifact_text_bounded(
                run_id,
                node_id,
                "stderr.log",
                f"\n=== attempt {attempt_number} started {attempt.started_at} ===\n",
                max_bytes=STREAM_ARTIFACT_MAX_BYTES,
                truncation_marker=OUTPUT_TRUNCATION_MARKER,
            )
            if attempt_number > 1:
                result.status = NodeStatus.RETRYING
                await self._publish(
                    run_id,
                    "node_retrying",
                    node_id=node_id,
                    attempt=attempt_number,
                    max_attempts=first_attempt_number + node.retries,
                )
                result.status = NodeStatus.RUNNING

            async def on_output(stream_name: str, line: str) -> None:
                if stream_name == "stdout":
                    await self.store.append_artifact_text_bounded(
                        run_id,
                        node_id,
                        "stdout.log",
                        line + "\n",
                        max_bytes=STREAM_ARTIFACT_MAX_BYTES,
                        truncation_marker=OUTPUT_TRUNCATION_MARKER,
                    )
                    parsed_events = parser.feed(line)
                    if parser.supports_raw_stdout_fallback():
                        attempt_stdout_lines.append(line)
                    for event in parsed_events:
                        result.append_trace_event(event)
                        await self._publish_trace(run_id, node_id, event)
                else:
                    attempt_stderr_lines.append(line)
                    await self.store.append_artifact_text_bounded(
                        run_id,
                        node_id,
                        "stderr.log",
                        line + "\n",
                        max_bytes=STREAM_ARTIFACT_MAX_BYTES,
                        truncation_marker=OUTPUT_TRUNCATION_MARKER,
                    )
                    event = parser.emit("stderr", "stderr", line, line, source="stderr")
                    result.append_trace_event(event)
                    await self._publish_trace(run_id, node_id, event)

            raw = await runner.execute(
                execution_node,
                prepared,
                paths,
                on_output,
                lambda: self._should_cancel(run_id) or self._should_cancel_node(run_id, node_id),
            )
            result.exit_code = raw.exit_code
            result.stdout_lines = attempt_stdout_lines.as_list()
            result.stderr_lines = attempt_stderr_lines.as_list()
            result.final_response = parser.finalize()
            if not result.final_response and parser.supports_raw_stdout_fallback():
                result.final_response = "\n".join(attempt_stdout_lines.as_list()).strip()
            result.output = (
                result.final_response
                if execution_node.capture.value == "final" or not parser.supports_raw_stdout_fallback()
                else "\n".join(attempt_stdout_lines.as_list())
            )
            result.structured_output = None
            structured_output, structured_error = parse_json_output(result.output or result.final_response)
            if structured_error is None:
                result.structured_output = structured_output
            success_ok, success_details = evaluate_success(execution_node, result, paths.host_workdir)
            result.success = success_ok
            result.success_details = success_details
            attempt.finished_at = utcnow_iso()
            attempt.exit_code = raw.exit_code
            attempt.final_response = result.final_response
            attempt.output = result.output
            attempt.success = success_ok
            attempt.success_details = success_details

            if (raw.cancelled or self._should_cancel(run_id)) and not raw.timed_out:
                attempt.status = NodeStatus.CANCELLED
                result.status = NodeStatus.CANCELLED
                result.finished_at = attempt.finished_at
                await self._publish(
                    run_id,
                    "node_cancelled",
                    node_id=node_id,
                    attempt=attempt_number,
                    exit_code=raw.exit_code,
                )
                break

            if raw.exit_code == 0 and success_ok:
                attempt.status = NodeStatus.COMPLETED
                result.status = NodeStatus.READY if periodic_tick_number is not None else NodeStatus.COMPLETED
                result.finished_at = attempt.finished_at
                if periodic_tick_number is not None:
                    if execution_node.schedule and execution_node.schedule.actuation == PeriodicActuationMode.OUTPUT_JSON:
                        periodic_actions, periodic_action_parse_error = self._parse_periodic_actions(result.final_response)
                        if periodic_actions is not None and periodic_actions.analysis is not None:
                            result.output = periodic_actions.analysis
                            attempt.output = result.output
                    await self._publish(
                        run_id,
                        "node_tick_completed",
                        node_id=node_id,
                        tick_number=periodic_tick_number,
                        attempt=attempt_number,
                        exit_code=result.exit_code,
                        success=result.success,
                        output=result.output,
                        final_response=result.final_response,
                        success_details=result.success_details,
                    )
                else:
                    await self._publish(
                        run_id,
                        "node_completed",
                        node_id=node_id,
                        attempt=attempt_number,
                        exit_code=result.exit_code,
                        success=result.success,
                        output=result.output,
                        final_response=result.final_response,
                        success_details=result.success_details,
                    )
                break

            terminal_failure_status = (
                NodeStatus.TIMED_OUT if raw.timed_out else NodeStatus.FAILED
            )
            will_retry = retry_index < node.retries
            attempt.status = terminal_failure_status
            # Keep the aggregate node non-terminal while another attempt is
            # pending. The scheduler runs concurrently with retry backoff and
            # uses this status to settle fan-outs and block downstream nodes.
            # The attempt itself remains terminal so its failure evidence is
            # preserved without exposing a false final node outcome.
            result.status = NodeStatus.RETRYING if will_retry else terminal_failure_status
            result.finished_at = None if will_retry else attempt.finished_at
            await self._publish(
                run_id,
                "node_timed_out" if raw.timed_out else "node_failed",
                node_id=node_id,
                attempt=attempt_number,
                exit_code=result.exit_code,
                success=result.success,
                output=result.output,
                final_response=result.final_response,
                success_details=result.success_details,
            )
            if will_retry:
                if getattr(node, "retry_backoff_strategy", "exponential") == "exponential":
                    delay = min(
                        node.retry_backoff_seconds * (2 ** retry_index),
                        getattr(node, "retry_backoff_max_seconds", 300.0),
                    )
                else:
                    delay = node.retry_backoff_seconds * (retry_index + 1)
                retry_at = asyncio.get_running_loop().time() + max(delay, 0.0)
                while (
                    asyncio.get_running_loop().time() < retry_at
                    and not self._should_cancel(run_id)
                    and not self._should_cancel_node(run_id, node_id)
                ):
                    await asyncio.sleep(
                        min(0.1, retry_at - asyncio.get_running_loop().time())
                    )
                continue
            break

        result.compact_trace_events()
        await self.store.write_artifact_text(run_id, node_id, "output.txt", result.output or "")
        if (
            execution_node.output_artifact is not None
            and result.status in {NodeStatus.COMPLETED, NodeStatus.READY}
        ):
            await self.store.write_artifact_text(
                run_id,
                node_id,
                execution_node.output_artifact,
                result.output or "",
            )
        await self.store.write_artifact_json(run_id, node_id, "result.json", result.model_dump(mode="json"))

        # Merge scratchboard writes from node output
        scratchboard = self._scratchboards.get(run_id)
        if scratchboard is not None and result.output:
            for line in result.output.splitlines():
                stripped = line.strip()
                if stripped.startswith("SCRATCHBOARD:"):
                    content = stripped.removeprefix("SCRATCHBOARD:").strip()
                    await scratchboard.append(node_id, content)

        # Capture diff from worktree (local) or remote (SSH/EC2/ECS)
        if pipeline.use_worktree:
            diff = ""
            if worktree_dir is not None:
                # Local: diff from worktree
                from agentflow.worktree import get_worktree_diff, remove_worktree
                try:
                    diff = get_worktree_diff(worktree_dir)
                except Exception:
                    pass
            # For remote nodes (SSH/EC2/ECS), diff is captured from the node output
            # if the node prompt asks for `git diff`. No automatic remote diff capture.
            if diff:
                await self.store.write_artifact_text(run_id, node_id, "diff.patch", diff)
            result.diff = diff

            # Clean up worktree
            if worktree_dir is not None:
                from agentflow.worktree import remove_worktree
                try:
                    remove_worktree(pipeline.working_path, worktree_dir)
                except Exception:
                    pass

        await self.store.persist_run(run_id)
        if periodic_tick_number is not None:
            return _NodeExecutionOutcome(
                node_id=node_id,
                periodic_tick_number=periodic_tick_number,
                periodic_actions=periodic_actions,
                periodic_action_parse_error=periodic_action_parse_error,
            )
        return _NodeExecutionOutcome(node_id=node_id)

    async def _expand_runtime_fanout(
        self,
        run_id: str,
        template: NodeSpec,
        *,
        node_map: dict[str, NodeSpec],
        remaining: set[str],
    ) -> None:
        record = self.store.get_run(run_id)
        fanout = template.fanout_from
        if fanout is None:  # pragma: no cover - guarded by the scheduler
            raise ValueError(f"node {template.id!r} has no runtime fan-out specification")
        source = record.nodes[fanout.from_]
        if fanout.connector is not None and fanout.resource is not None:
            structured = await self._connector_manager.fetch_collection(
                run_id,
                fanout.connector,
                fanout.resource,
            )
        else:
            structured = source.structured_output
            if structured is None:
                structured, parse_error = parse_json_output(source.output or source.final_response)
                if parse_error is not None:
                    raise ValueError(
                        f"runtime fan-out {template.id!r} could not parse source "
                        f"{fanout.from_!r}: {parse_error}"
                    )
                source.structured_output = structured
        try:
            values = select_json_path(structured, fanout.path)
        except KeyError as exc:
            raise ValueError(
                f"runtime fan-out {template.id!r} path {fanout.path!r} "
                f"was not found in source {fanout.from_!r}"
            ) from exc
        if not isinstance(values, list):
            raise ValueError(
                f"runtime fan-out {template.id!r} expected a collection at "
                f"{fanout.path!r}, got {type(values).__name__}"
            )
        if fanout.connector is not None and any(
            not isinstance(value, str) or not value for value in values
        ):
            raise ValueError(
                f"connector-backed runtime fan-out {template.id!r} must return only stable string IDs"
            )
        if fanout.connector is not None and len(values) != len(set(values)):
            raise ValueError(
                f"connector-backed runtime fan-out {template.id!r} returned duplicate stable IDs"
            )

        members, member_ids = expand_runtime_fanout_node(template, values)
        collisions = sorted(set(member_ids) & set(node_map))
        if collisions:
            raise ValueError(
                f"runtime fan-out {template.id!r} produced node ids that already exist: {collisions}"
            )
        record.pipeline.fanouts[template.id] = member_ids
        template_result = record.nodes[template.id]
        template_result.status = NodeStatus.RUNNING
        template_result.started_at = template_result.started_at or utcnow_iso()
        template_result.structured_output = values
        await self._publish(
            run_id,
            "runtime_fanout_expanded",
            node_id=template.id,
            source_node_id=fanout.from_,
            connector=fanout.connector,
            resource=fanout.resource,
            members=member_ids,
        )
        for index, member in enumerate(members):
            if fanout.connector is not None:
                self._connector_manager.bind_member(run_id, member, values[index])
            record.pipeline.nodes.append(member)
            node_map[member.id] = member
            record.nodes[member.id] = NodeResult(node_id=member.id, status=NodeStatus.PENDING)
            remaining.add(member.id)
        await self.store.persist_run(run_id)

    async def _settle_runtime_fanout(self, run_id: str, template: NodeSpec) -> bool:
        record = self.store.get_run(run_id)
        if template.id not in record.pipeline.fanouts:
            return False
        member_ids = record.pipeline.fanouts[template.id]
        if any(record.nodes[member_id].status not in _TERMINAL_NODE_STATUSES for member_id in member_ids):
            return False
        result = record.nodes[template.id]
        if result.status == NodeStatus.COMPLETED:
            return True
        result.status = NodeStatus.COMPLETED
        result.success = True
        result.finished_at = utcnow_iso()
        result.output = json.dumps(
            {
                "members": member_ids,
                "statuses": {member_id: record.nodes[member_id].status.value for member_id in member_ids},
            },
            ensure_ascii=False,
        )
        await self._publish(
            run_id,
            "runtime_fanout_settled",
            node_id=template.id,
            members=member_ids,
        )
        await self.store.write_artifact_text(run_id, template.id, "output.txt", result.output)
        await self.store.write_artifact_json(run_id, template.id, "result.json", result.model_dump(mode="json"))
        await self.store.persist_run(run_id)
        return True

    async def run(self, run_id: str, *, recovering: bool = False) -> RunRecord:
        """Execute one run and always release its run-scoped resources."""

        try:
            return await self._drive_run(run_id, recovering=recovering)
        finally:
            await self._cleanup_run_resources(run_id)

    async def _restore_connector_fanout_bindings(
        self,
        run_id: str,
        record: RunRecord,
    ) -> None:
        node_map = record.pipeline.node_map
        for template_id, member_ids in record.pipeline.fanouts.items():
            template = node_map.get(template_id)
            if (
                template is None
                or template.fanout_from is None
                or template.fanout_from.connector is None
            ):
                continue
            for member_id in member_ids:
                member = node_map.get(member_id)
                item_id = (
                    member.fanout_member.get("value")
                    if member is not None and member.fanout_member is not None
                    else None
                )
                if member is None or not isinstance(item_id, str) or not item_id:
                    raise ValueError(
                        f"connector fan-out {template_id!r} has invalid persisted member {member_id!r}"
                    )
                self._connector_manager.bind_member(run_id, member, item_id)

    async def _drive_run(self, run_id: str, *, recovering: bool = False) -> RunRecord:
        """Drive a run until all nodes reach terminal outcomes.

        The loop skips nodes blocked by upstream failure, queues nodes whose
        dependencies are satisfied, and bounds concurrent execution with a
        semaphore. `_execute_node()` handles per-node retry attempts; this loop
        handles scheduling, completion collection, and explicit reruns. Periodic
        nodes execute as repeated ticks, can emit cancel/rerun actions for a watched
        fanout, reschedule on `every_seconds`, and finalize once that fanout group
        has fully settled.
        """

        record = self.store.get_run(run_id)
        pipeline = record.pipeline
        loop = asyncio.get_running_loop()
        record.status = RunStatus.RUNNING
        if recovering:
            await self._publish(
                run_id,
                "run_recovery_started",
                source_snapshot=(
                    record.source_snapshot.model_dump(mode="json", by_alias=True)
                    if record.source_snapshot is not None
                    else None
                ),
            )
        else:
            record.started_at = utcnow_iso()
            await self._publish(run_id, "run_started", pipeline=pipeline.model_dump(mode="json"))
        await self.store.persist_run(run_id)
        setup_steps = [
            (
                lambda: self._prepare_inference_service(run_id, record),
                "inference_setup_failed",
                "inference_failed",
            ),
            (
                lambda: self._prepare_connectors(run_id, record),
                "connector_setup_failed",
                "connectors_failed",
            ),
        ]
        if not recovering:
            setup_steps.insert(
                0,
                (
                    lambda: self._prepare_source_snapshot(run_id, record),
                    "source_setup_failed",
                    "source_snapshot_failed",
                ),
            )
        for operation, skip_reason, event_type in setup_steps:
            if self._should_cancel(run_id):
                break
            try:
                await operation()
            except Exception as exc:  # noqa: BLE001 - fail before scheduling nodes.
                return await self._fail_setup(
                    run_id,
                    exc,
                    skip_reason=skip_reason,
                    event_type=event_type,
                )
            pipeline = record.pipeline
        if recovering:
            try:
                await self._restore_connector_fanout_bindings(run_id, record)
            except Exception as exc:  # noqa: BLE001 - fail before scheduling nodes.
                return await self._fail_setup(
                    run_id,
                    exc,
                    skip_reason="connector_rebind_failed",
                    event_type="connector_rebind_failed",
                )

        # Setup phases own their specific timeouts. The workflow deadline starts
        # only after setup so an uninterruptible thread-backed Git or cloud launch
        # is never abandoned in the background.
        run_deadline = (
            loop.time() + pipeline.deadline_seconds
            if pipeline.deadline_seconds is not None
            else None
        )

        node_map = pipeline.node_map
        iteration_counts: dict[tuple[str, str], int] = {}

        # Create scratchboard if enabled
        if pipeline.scratchboard:
            from agentflow.scratchboard import Scratchboard, SCRATCHBOARD_FILENAME
            sb_path = self.store.base_dir / run_id / SCRATCHBOARD_FILENAME
            self._scratchboards[run_id] = Scratchboard(sb_path)

        # Pre-register shared resource counts so instances survive between sequential nodes
        self._register_shared_resources(pipeline)
        # Exclude nodes already in a terminal state (e.g. completed from a resumed run)
        remaining = {
            node_id for node_id in node_map
            if record.nodes[node_id].status not in {NodeStatus.COMPLETED}
        }
        in_progress: dict[str, asyncio.Task[_NodeExecutionOutcome]] = {}
        semaphore = asyncio.Semaphore(pipeline.concurrency)
        periodic_state = {
            node_id: _PeriodicNodeRuntimeState()
            for node_id, node in node_map.items()
            if node.schedule is not None
        }
        runtime_templates = {
            node_id: node
            for node_id, node in node_map.items()
            if node.fanout_from is not None
        }
        runtime_expanded = set(record.pipeline.fanouts) & set(runtime_templates)
        remaining.difference_update(runtime_expanded)
        pool_semaphores = {
            name: asyncio.Semaphore(limit)
            for name, limit in pipeline.concurrency_pools.items()
        }
        deadline_exceeded = False

        async def launch(node_id: str) -> _NodeExecutionOutcome:
            node = node_map[node_id]

            async def execute() -> _NodeExecutionOutcome:
                async with semaphore:
                    if node.schedule is None:
                        return await self._execute_node(run_id, node_id)
                    state = periodic_state[node_id]
                    state.tick_count += 1
                    tick_started_at = utcnow_iso()
                    state.last_tick_started_at = tick_started_at
                    state.last_tick_started_mono = loop.time()
                    record.nodes[node_id].tick_count = state.tick_count
                    record.nodes[node_id].last_tick_started_at = tick_started_at
                    record.nodes[node_id].next_scheduled_at = None
                    return await self._execute_node(
                        run_id,
                        node_id,
                        periodic_tick_number=state.tick_count,
                        periodic_tick_started_at=tick_started_at,
                    )

            pool = pool_semaphores.get(node.concurrency_pool or "")
            if pool is None:
                return await execute()
            async with pool:
                return await execute()

        async def expire_deadline() -> None:
            nonlocal deadline_exceeded
            if deadline_exceeded:
                return
            deadline_exceeded = True
            await self._publish(
                run_id,
                "run_deadline_exceeded",
                deadline_seconds=pipeline.deadline_seconds,
            )
            for node_id in list(remaining):
                await self._mark_node_cancelled(
                    run_id,
                    node_id,
                    "run_deadline_exceeded",
                )
                remaining.remove(node_id)
            self._node_cancel_flags.setdefault(run_id, set()).update(in_progress)

        while remaining or in_progress:
            if (
                run_deadline is not None
                and loop.time() >= run_deadline
                and not deadline_exceeded
            ):
                await expire_deadline()

            if self._should_cancel(run_id):
                for node_id in list(remaining):
                    await self._mark_node_cancelled(run_id, node_id, "run_cancelled")
                    remaining.remove(node_id)
                if not in_progress:
                    break

            for template_id, template in runtime_templates.items():
                if template_id in runtime_expanded:
                    await self._settle_runtime_fanout(run_id, template)
                    continue
                if template_id not in remaining:
                    continue
                if not all(record.nodes[dependency].status == NodeStatus.COMPLETED for dependency in template.depends_on):
                    continue
                remaining.remove(template_id)
                try:
                    await self._expand_runtime_fanout(
                        run_id,
                        template,
                        node_map=node_map,
                        remaining=remaining,
                    )
                    runtime_expanded.add(template_id)
                    await self._settle_runtime_fanout(run_id, template)
                except Exception as exc:  # noqa: BLE001 - surface expansion failures as node failures.
                    result = record.nodes[template_id]
                    result.status = NodeStatus.FAILED
                    result.success = False
                    result.finished_at = utcnow_iso()
                    result.success_details = [str(exc)]
                    await self._publish(
                        run_id,
                        "node_failed",
                        node_id=template_id,
                        error=str(exc),
                    )
                    await self.store.persist_run(run_id)

            failed_nodes = {
                node_id
                for node_id, node in record.nodes.items()
                if node.status in {NodeStatus.FAILED, NodeStatus.TIMED_OUT}
            }
            if pipeline.fail_fast and failed_nodes:
                for node_id in list(remaining):
                    record.nodes[node_id].status = NodeStatus.SKIPPED
                    record.nodes[node_id].finished_at = utcnow_iso()
                    remaining.remove(node_id)
                    await self._publish(run_id, "node_skipped", node_id=node_id, reason="fail_fast")

            # Collect ALL nodes involved in cycles — endpoints AND nodes between them.
            # Without this, nodes between restart target and tail (e.g. workers between
            # orchestrator and wave_review) get eagerly skipped when orchestrator
            # fails on attempt 1, even though it may succeed on retry.
            cycle_nodes: set[str] = set()
            cycle_tail_nodes: set[str] = set()
            for n in pipeline.nodes:
                if n.on_failure_restart:
                    cycle_tail_nodes.add(n.id)
                    cycle_nodes.add(n.id)
                    cycle_nodes.update(n.on_failure_restart)
                    # Include all nodes between restart targets and this tail
                    for target_id in n.on_failure_restart:
                        for mid_id in self._nodes_between(node_map, target_id, n.id):
                            cycle_nodes.add(mid_id)
            # Nodes that depend on a cycle tail should not be eagerly
            # skipped — the tail may succeed on a future iteration.
            # But once the cycle is exhausted, allow normal blocking.
            active_cycle_tails: set[str] = set()
            for tail_id in cycle_tail_nodes:
                iter_key = (run_id, tail_id)
                tail_status = record.nodes[tail_id].status
                # A tail is only active if it hasn't succeeded yet AND
                # still has iterations remaining.
                if (
                    tail_status != NodeStatus.COMPLETED
                    and iteration_counts.get(iter_key, 0) < pipeline.max_iterations
                ):
                    active_cycle_tails.add(tail_id)
            cycle_downstream: set[str] = set()
            for n in pipeline.nodes:
                if any(dep in active_cycle_tails for dep in n.depends_on):
                    cycle_downstream.add(n.id)

            blocked = [
                node_id
                for node_id in list(remaining)
                if node_id not in cycle_nodes  # don't skip any node in a cycle
                and node_id not in cycle_downstream  # don't skip nodes waiting on cycle outcome
                and any(record.nodes[dependency].status in {NodeStatus.FAILED, NodeStatus.TIMED_OUT, NodeStatus.SKIPPED, NodeStatus.CANCELLED} for dependency in node_map[node_id].depends_on)
            ]
            for node_id in blocked:
                record.nodes[node_id].status = NodeStatus.SKIPPED
                record.nodes[node_id].finished_at = utcnow_iso()
                remaining.remove(node_id)
                await self._publish(run_id, "node_skipped", node_id=node_id, reason="upstream_failure")
            for node_id in list(remaining):
                node = node_map[node_id]
                if node.schedule is None:
                    continue
                if any(record.nodes[dependency].status != NodeStatus.COMPLETED for dependency in node.depends_on):
                    continue
                if not self._fanout_group_settled(
                    pipeline,
                    record.nodes,
                    node.schedule.until_fanout_settles_from,
                ):
                    continue
                remaining.remove(node_id)
                await self._finalize_periodic_node(run_id, node_id, reason="watched_group_settled")

            now = loop.time()
            ready: list[str] = []
            for node_id in list(remaining):
                if node_id in in_progress:
                    continue
                node = node_map[node_id]
                # Cycle nodes can proceed when deps are COMPLETED or FAILED
                if node_id in cycle_nodes or node.on_failure_restart:
                    terminal = {NodeStatus.COMPLETED, NodeStatus.FAILED, NodeStatus.TIMED_OUT}
                    if not all(record.nodes[dep].status in terminal for dep in node.depends_on):
                        continue
                elif not all(record.nodes[dep].status == NodeStatus.COMPLETED for dep in node.depends_on):
                    continue
                if node.schedule is None:
                    ready.append(node_id)
                    continue
                state = periodic_state[node_id]
                if state.waiting_for_actuation:
                    continue
                watched_members = pipeline.fanouts.get(
                    node.schedule.until_fanout_settles_from,
                    [],
                )
                if watched_members and all(
                    record.nodes[member_id].status
                    in {NodeStatus.PENDING, NodeStatus.READY, NodeStatus.QUEUED}
                    for member_id in watched_members
                ):
                    # A controller cannot observe useful state before any watched
                    # member has started. Let workers launch first so tick 1 has a
                    # stable view of their logs and lifecycle state.
                    continue
                if state.next_tick_at is None or now >= state.next_tick_at:
                    ready.append(node_id)
            for node_id in ready:
                if node_id not in in_progress:
                    remaining.remove(node_id)
                    record.nodes[node_id].status = NodeStatus.QUEUED
                    in_progress[node_id] = asyncio.create_task(launch(node_id))
            if in_progress:
                wait_timeout = 0.1
                if run_deadline is not None and not deadline_exceeded:
                    wait_timeout = max(0.0, min(wait_timeout, run_deadline - loop.time()))
                done, _ = await asyncio.wait(
                    in_progress.values(),
                    timeout=wait_timeout,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if (
                    run_deadline is not None
                    and loop.time() >= run_deadline
                    and not deadline_exceeded
                ):
                    await expire_deadline()
                finished_ids = [node_id for node_id, task in in_progress.items() if task in done]
                for node_id in finished_ids:
                    task = in_progress.pop(node_id)
                    node = node_map[node_id]
                    self._node_cancel_flags.setdefault(run_id, set()).discard(node_id)
                    try:
                        outcome = await task
                    except Exception as exc:  # noqa: BLE001 - keep scheduling and connector cleanup alive.
                        node_result = record.nodes[node_id]
                        node_result.status = NodeStatus.FAILED
                        node_result.success = False
                        node_result.finished_at = utcnow_iso()
                        node_result.success_details = [f"node execution crashed: {exc}"]
                        if node_result.attempts and node_result.attempts[-1].status == NodeStatus.RUNNING:
                            node_result.attempts[-1].status = NodeStatus.FAILED
                            node_result.attempts[-1].finished_at = node_result.finished_at
                            node_result.attempts[-1].success = False
                            node_result.attempts[-1].success_details = list(node_result.success_details)
                        await self._publish(
                            run_id,
                            "node_failed",
                            node_id=node_id,
                            error=str(exc),
                            success=False,
                            success_details=node_result.success_details,
                        )
                        await self.store.persist_run(run_id)
                        continue

                    if node.schedule is not None:
                        if outcome.periodic_actions is not None:
                            await self.store.write_artifact_json(
                                run_id,
                                node_id,
                                f"periodic-actions-tick-{outcome.periodic_tick_number}.json",
                                outcome.periodic_actions.model_dump(mode="json"),
                            )
                        elif outcome.periodic_action_parse_error is not None:
                            await self.store.write_artifact_json(
                                run_id,
                                node_id,
                                f"periodic-actions-tick-{outcome.periodic_tick_number}.json",
                                {"error": outcome.periodic_action_parse_error},
                            )
                            await self._publish(
                                run_id,
                                "node_control_actions_rejected",
                                node_id=node_id,
                                watched_group=node.schedule.until_fanout_settles_from,
                                actions=[{"reason": outcome.periodic_action_parse_error}],
                            )

                        if outcome.periodic_actions is not None:
                            await self._apply_periodic_actions(
                                run_id,
                                node_id,
                                watched_group=node.schedule.until_fanout_settles_from,
                                actions=outcome.periodic_actions,
                                remaining=remaining,
                                in_progress=in_progress,
                            )
                            if any(
                                action.kind in {"cancel", "rerun"} and action.node_ids
                                for action in outcome.periodic_actions.actions
                            ):
                                periodic_state[node_id].waiting_for_actuation = True

                        node_result = record.nodes[node_id]
                        if (
                            node_result.status == NodeStatus.READY
                            and not self._should_cancel(run_id)
                            and not deadline_exceeded
                        ):
                            if self._fanout_group_settled(
                                pipeline,
                                record.nodes,
                                node.schedule.until_fanout_settles_from,
                            ):
                                await self._finalize_periodic_node(run_id, node_id, reason="watched_group_settled")
                            else:
                                state = periodic_state[node_id]
                                if state.last_tick_started_mono is None:
                                    state.next_tick_at = loop.time() + node.schedule.every_seconds
                                else:
                                    state.next_tick_at = state.last_tick_started_mono + node.schedule.every_seconds
                                seconds_until_next_tick = max(state.next_tick_at - loop.time(), 0.0)
                                next_tick_at = datetime.now(timezone.utc) + timedelta(seconds=seconds_until_next_tick)
                                node_result.next_scheduled_at = next_tick_at.isoformat()
                                remaining.add(node_id)
                                await self._publish(
                                    run_id,
                                    "node_waiting",
                                    node_id=node_id,
                                    tick_count=node_result.tick_count,
                                    next_scheduled_at=node_result.next_scheduled_at,
                                )
                                await self.store.persist_run(run_id)

                    # -- on_failure_restart: cycle back-edge handling --
                    if (
                        record.nodes[node_id].status in {NodeStatus.FAILED, NodeStatus.TIMED_OUT}
                        and node.on_failure_restart
                        and not self._should_cancel(run_id)
                        and not deadline_exceeded
                    ):
                        iteration_key = (run_id, node_id)
                        iteration_counts[iteration_key] = iteration_counts.get(iteration_key, 0) + 1
                        if iteration_counts[iteration_key] < pipeline.max_iterations:
                            await self._publish(
                                run_id, "node_cycle_restart",
                                node_id=node_id,
                                iteration=iteration_counts[iteration_key],
                                restart_targets=node.on_failure_restart,
                            )
                            # Reset the failed node itself
                            record.nodes[node_id].status = NodeStatus.PENDING
                            record.nodes[node_id].finished_at = None
                            remaining.add(node_id)
                            # Reset all restart targets and their downstream chain
                            for target_id in node.on_failure_restart:
                                self._reset_node_for_cycle(record, target_id, remaining)
                                # Also reset nodes between target and this node
                                for mid_id in self._nodes_between(node_map, target_id, node_id):
                                    self._reset_node_for_cycle(record, mid_id, remaining)
                            # Reset any nodes that were SKIPPED due to this cycle
                            # node failing — they should get a chance to run once
                            # the cycle eventually succeeds.
                            for dep_node in pipeline.nodes:
                                if (
                                    node_id in dep_node.depends_on
                                    and record.nodes.get(dep_node.id)
                                    and record.nodes[dep_node.id].status == NodeStatus.SKIPPED
                                ):
                                    self._reset_node_for_cycle(record, dep_node.id, remaining)
                            await self.store.persist_run(run_id)
                        else:
                            await self._publish(
                                run_id, "node_cycle_exhausted",
                                node_id=node_id,
                                max_iterations=pipeline.max_iterations,
                            )

                    if (
                        node_id in self._pending_node_reruns.setdefault(run_id, set())
                        and record.nodes[node_id].status in _TERMINAL_NODE_STATUSES
                        and not self._should_cancel(run_id)
                        and not deadline_exceeded
                    ):
                        self._pending_node_reruns[run_id].discard(node_id)
                        record.nodes[node_id].status = NodeStatus.PENDING
                        record.nodes[node_id].finished_at = None
                        record.nodes[node_id].next_scheduled_at = None
                        remaining.add(node_id)
                        await self._publish(run_id, "node_rerun_queued", node_id=node_id)
                        await self.store.persist_run(run_id)
                for template_id in runtime_expanded:
                    await self._settle_runtime_fanout(run_id, runtime_templates[template_id])
            elif remaining:
                await asyncio.sleep(0.05)
            else:
                break

        if (
            run_deadline is not None
            and loop.time() >= run_deadline
            and not deadline_exceeded
        ):
            await expire_deadline()

        if deadline_exceeded:
            record.status = RunStatus.FAILED
        elif record.status == RunStatus.CANCELLING or self._should_cancel(run_id):
            record.status = RunStatus.CANCELLED
        elif any(
            node.status in {NodeStatus.FAILED, NodeStatus.TIMED_OUT}
            for node in record.nodes.values()
        ):
            record.status = RunStatus.FAILED
        else:
            record.status = RunStatus.COMPLETED
        record.finished_at = utcnow_iso()
        await self._publish(run_id, "run_completed", status=record.status.value)
        await self.store.clear_cancel_request(run_id)
        await self.store.persist_run(run_id)
        self._node_cancel_flags.pop(run_id, None)
        self._pending_node_reruns.pop(run_id, None)
        return record
