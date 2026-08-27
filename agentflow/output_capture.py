from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field


# Keep enough output for useful diagnostics and raw-stdout fallback without
# allowing a chatty subprocess to retain the lifetime of its output in memory.
RETAINED_STREAM_MAX_BYTES = 1024 * 1024

# Raw stream artifacts are diagnostic data. Eight MiB per stream and node is
# sufficient for inspection while bounding disk growth from structured clients
# that repeat their assembled response alongside every token delta.
STREAM_ARTIFACT_MAX_BYTES = 8 * 1024 * 1024

# Normalized traces remain useful after raw stdout has been capped, but token
# deltas must not grow run state and diagnostic artifacts without limit.
TRACE_ARTIFACT_MAX_BYTES = 64 * 1024 * 1024
RETAINED_TRACE_EVENT_MAX_COUNT = 4096
TRACE_EVENT_COMPACTION_TRIGGER_COUNT = 5120
RETAINED_RUN_TRACE_EVENTS_MAX_COUNT = 4096

# asyncio's subprocess StreamReader must keep draining even when a tool emits a
# single enormous JSONL record.  Records above this limit are discarded and
# replaced with a compact diagnostic marker instead of wedging process.wait().
STREAM_RECORD_MAX_BYTES = 8 * 1024 * 1024

OUTPUT_TRUNCATION_MARKER = "[AgentFlow output truncated: older or excess stream data was omitted]"
OVERSIZED_STREAM_RECORD_MARKER = "[AgentFlow stream record omitted: exceeded safe capture limit]"
TRACE_ARTIFACT_TRUNCATION_MARKER = "[AgentFlow trace artifact capped: additional trace events were omitted]"


@dataclass(slots=True)
class BoundedLineBuffer:
    """Retain the newest complete output lines up to a UTF-8 byte budget."""

    max_bytes: int = RETAINED_STREAM_MAX_BYTES
    _lines: deque[tuple[str, int]] = field(default_factory=deque)
    _retained_bytes: int = 0
    _truncated: bool = False

    def append(self, text: str) -> None:
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) > self.max_bytes:
            encoded = encoded[-self.max_bytes :]
            text = encoded.decode("utf-8", errors="ignore")
            encoded = text.encode("utf-8")
            self._lines.clear()
            self._retained_bytes = 0
            self._truncated = True

        size = len(encoded)
        while self._lines and self._retained_bytes + size > self.max_bytes:
            _, removed_size = self._lines.popleft()
            self._retained_bytes -= removed_size
            self._truncated = True

        if size <= self.max_bytes:
            self._lines.append((text, size))
            self._retained_bytes += size

    def clear(self) -> None:
        self._lines.clear()
        self._retained_bytes = 0
        self._truncated = False

    def as_list(self) -> list[str]:
        lines = [text for text, _ in self._lines]
        return [OUTPUT_TRUNCATION_MARKER, *lines] if self._truncated else lines

    def latest(self) -> str | None:
        return self._lines[-1][0] if self._lines else None
