from __future__ import annotations

import json
import queue
import threading
from collections import defaultdict, deque
from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError

from agentflow.output_capture import RETAINED_RUN_TRACE_EVENTS_MAX_COUNT
from agentflow.specs import RunEvent, RunRecord
from agentflow.utils import ensure_dir


class RunStore:
    def __init__(self, base_dir: str | Path = ".agentflow/runs") -> None:
        self.base_dir = ensure_dir(Path(base_dir).expanduser())
        self._runs: dict[str, RunRecord] = {}
        self._locks: defaultdict[str, threading.Lock] = defaultdict(threading.Lock)
        self._subscribers: defaultdict[str, set[queue.Queue[RunEvent]]] = defaultdict(set)
        self._events_cache: defaultdict[str, list[RunEvent]] = defaultdict(list)
        self._trace_event_cache_counts: defaultdict[str, int] = defaultdict(int)
        self._load_existing_runs()

    def _load_event_cache(self, events_path: Path) -> list[RunEvent]:
        retained: list[tuple[int, RunEvent]] = []
        recent_trace_lines: deque[tuple[int, str]] = deque(
            maxlen=RETAINED_RUN_TRACE_EVENTS_MAX_COUNT
        )
        with events_path.open("r", encoding="utf-8") as handle:
            for sequence, line in enumerate(handle):
                if not line.strip():
                    continue
                # RunEvent.model_dump_json() emits compact top-level fields. Do
                # not construct hundreds of thousands of Pydantic objects that
                # will immediately be discarded from the bounded trace tail.
                trace_offset = line.find('"type":"node_trace"')
                data_offset = line.find('"data":')
                if trace_offset >= 0 and (data_offset < 0 or trace_offset < data_offset):
                    recent_trace_lines.append((sequence, line))
                else:
                    retained.append((sequence, RunEvent.model_validate_json(line)))
        recent_traces = [
            (sequence, RunEvent.model_validate_json(line))
            for sequence, line in recent_trace_lines
        ]
        return [
            event
            for _, event in sorted([*retained, *recent_traces], key=lambda item: item[0])
        ]

    def _cache_event(self, run_id: str, event: RunEvent) -> None:
        self._events_cache[run_id].append(event)
        if event.type != "node_trace":
            return
        self._trace_event_cache_counts[run_id] += 1
        trace_count = self._trace_event_cache_counts[run_id]
        trigger = RETAINED_RUN_TRACE_EVENTS_MAX_COUNT + max(
            1, min(1024, RETAINED_RUN_TRACE_EVENTS_MAX_COUNT // 4)
        )
        if trace_count < trigger:
            return
        to_remove = trace_count - RETAINED_RUN_TRACE_EVENTS_MAX_COUNT
        compacted: list[RunEvent] = []
        for cached in self._events_cache[run_id]:
            if cached.type == "node_trace" and to_remove:
                to_remove -= 1
                continue
            compacted.append(cached)
        self._events_cache[run_id] = compacted
        self._trace_event_cache_counts[run_id] = RETAINED_RUN_TRACE_EVENTS_MAX_COUNT

    def _load_existing_runs(self) -> None:
        for run_file in sorted(self.base_dir.glob("*/run.json")):
            run_id = run_file.parent.name
            try:
                run = RunRecord.model_validate_json(run_file.read_text(encoding="utf-8"))
                self._runs[run_id] = run
                events_path = run_file.parent / "events.jsonl"
                if events_path.exists():
                    events = self._load_event_cache(events_path)
                    self._events_cache[run_id] = events
                    self._trace_event_cache_counts[run_id] = sum(
                        event.type == "node_trace" for event in events
                    )
            except (OSError, ValidationError, json.JSONDecodeError, KeyError):
                continue

    async def create_run(self, record: RunRecord | None = None) -> RunRecord:
        if record is None:
            raise ValueError("create_run requires a RunRecord")
        self._runs[record.id] = record
        await self.persist_run(record.id)
        return record

    def new_run_id(self) -> str:
        return uuid4().hex

    def run_dir(self, run_id: str) -> Path:
        return ensure_dir(self.base_dir / run_id)

    def node_artifact_dir(self, run_id: str, node_id: str) -> Path:
        return ensure_dir(self.run_dir(run_id) / "artifacts" / node_id)

    def run_artifact_dir(self, run_id: str) -> Path:
        return ensure_dir(self.run_dir(run_id) / "artifacts" / "_run")

    def artifact_path(self, run_id: str, node_id: str, name: str) -> Path:
        return self.node_artifact_dir(run_id, node_id) / name

    def cancel_request_path(self, run_id: str) -> Path:
        return self.run_dir(run_id) / "cancel.requested"

    async def persist_run(self, run_id: str) -> None:
        record = self._runs[run_id]
        run_dir = self.run_dir(run_id)
        lock = self._locks[run_id]
        with lock:
            (run_dir / "run.json").write_text(
                record.model_dump_json(indent=2),
                encoding="utf-8",
            )

    async def append_event(self, run_id: str, event: RunEvent) -> None:
        lock = self._locks[run_id]
        with lock:
            run_dir = self.run_dir(run_id)
            with (run_dir / "events.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(event.model_dump_json())
                handle.write("\n")
            self._cache_event(run_id, event)
        for subscriber in list(self._subscribers[run_id]):
            subscriber.put_nowait(event)

    async def publish_transient_event(self, run_id: str, event: RunEvent) -> None:
        """Publish a live event without duplicating it in durable/cache state."""

        for subscriber in list(self._subscribers[run_id]):
            subscriber.put_nowait(event)

    async def request_cancel(self, run_id: str) -> None:
        lock = self._locks[run_id]
        with lock:
            self.cancel_request_path(run_id).write_text("cancel\n", encoding="utf-8")

    def cancel_requested(self, run_id: str) -> bool:
        return self.cancel_request_path(run_id).exists()

    async def clear_cancel_request(self, run_id: str) -> None:
        lock = self._locks[run_id]
        with lock:
            self.cancel_request_path(run_id).unlink(missing_ok=True)

    async def append_artifact_text(self, run_id: str, node_id: str, name: str, content: str) -> None:
        path = self.artifact_path(run_id, node_id, name)
        ensure_dir(path.parent)
        lock = self._locks[run_id]
        with lock:
            with path.open("a", encoding="utf-8") as handle:
                handle.write(content)

    async def append_artifact_text_bounded(
        self,
        run_id: str,
        node_id: str,
        name: str,
        content: str,
        *,
        max_bytes: int,
        truncation_marker: str,
    ) -> bool:
        """Append whole text records until a byte limit, then one marker.

        Existing artifacts are never shortened. The marker may exceed
        ``max_bytes`` so a previously oversized artifact still records why new
        output is no longer being appended.
        """

        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        path = self.artifact_path(run_id, node_id, name)
        ensure_dir(path.parent)
        content_bytes = content.encode("utf-8")
        marker = truncation_marker.rstrip("\n") + "\n"
        marker_bytes = marker.encode("utf-8")
        lock = self._locks[run_id]
        with lock:
            current_size = path.stat().st_size if path.exists() else 0
            if current_size + len(content_bytes) <= max_bytes:
                with path.open("ab") as handle:
                    handle.write(content_bytes)
                return True

            marker_present = False
            if path.exists() and current_size:
                with path.open("rb") as handle:
                    handle.seek(max(0, current_size - len(marker_bytes)))
                    marker_present = handle.read().endswith(marker_bytes)
            if not marker_present:
                with path.open("ab") as handle:
                    handle.write(marker_bytes)
            return False

    async def write_artifact_text(self, run_id: str, node_id: str, name: str, content: str) -> None:
        path = self.artifact_path(run_id, node_id, name)
        ensure_dir(path.parent)
        lock = self._locks[run_id]
        with lock:
            path.write_text(content, encoding="utf-8")

    async def write_artifact_json(self, run_id: str, node_id: str, name: str, payload: object) -> None:
        await self.write_artifact_text(run_id, node_id, name, json.dumps(payload, ensure_ascii=False, indent=2))

    async def write_run_artifact_json(self, run_id: str, name: str, payload: object) -> None:
        path = self.run_artifact_dir(run_id) / name
        lock = self._locks[run_id]
        with lock:
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def read_artifact_text(self, run_id: str, node_id: str, name: str) -> str:
        return self.artifact_path(run_id, node_id, name).read_text(encoding="utf-8")

    def get_run(self, run_id: str) -> RunRecord:
        return self._runs[run_id]

    def list_runs(self) -> list[RunRecord]:
        return sorted(self._runs.values(), key=lambda run: run.created_at, reverse=True)

    def get_events(self, run_id: str) -> list[RunEvent]:
        return list(self._events_cache[run_id])

    async def subscribe(self, run_id: str) -> queue.Queue[RunEvent]:
        subscriber: queue.Queue[RunEvent] = queue.Queue()
        self._subscribers[run_id].add(subscriber)
        return subscriber

    async def unsubscribe(self, run_id: str, subscriber: queue.Queue[RunEvent]) -> None:
        self._subscribers[run_id].discard(subscriber)
