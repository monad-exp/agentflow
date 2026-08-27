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

OUTPUT_TRUNCATION_MARKER = "[AgentFlow output truncated: older or excess stream data was omitted]"


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
