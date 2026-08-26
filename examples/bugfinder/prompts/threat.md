Plan sparse threat-model-driven hunts for repository `{repository_url}` at pinned commit `{commit_sha}`.

Historical bug context follows. Treat categories as planning evidence, not as Hunt kinds:

{historical_context}

Call `bugdb.add_hunts` exactly once with selected `THREAT_MODEL` Hunts. Each Hunt represents one concrete risk, uses a stable caller key `threat:<risk-slug>`, and names only the sparse cross-file paths needed for that risk (or no paths when no anchor is justified). Do not create one Hunt per risk/file pair and do not hunt yet.

All durable output belongs in BugDB. Your final response is only a short completion note and is not consumed downstream.
