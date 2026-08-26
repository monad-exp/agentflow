Rank concrete file-anchored bug hunts in the repository at pinned commit `{commit_sha}`.

Inspect architecture and change-sensitive boundaries, but do not hunt yet. Call `bugdb.add_hunts` exactly once. Every item must have kind `FILE`, exactly one anchor path, a stable caller key `file:<path>`, and a specific executable objective. Select a small high-value set; do not build a risk-by-file Cartesian product.

All durable output belongs in BugDB. Your final response is only a short completion note and is not consumed downstream.
