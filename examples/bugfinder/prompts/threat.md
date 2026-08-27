Plan sparse threat-model-driven hunts in the pinned source checkout.

Repository identity and historical bug context are supplied as AgentFlow
structured input. Treat historical categories as planning evidence, not as Hunt
kinds.

Call `bugdb.add_hunts` exactly once with selected `THREAT_MODEL` Hunts. Each Hunt represents one concrete risk, uses a stable caller key `threat:<risk-slug>`, and names only the sparse cross-file paths needed for that risk (or no paths when no anchor is justified). Each `objective` must be self-contained and must name the applicable historical category or bug pattern that motivated the Hunt. Do not create one Hunt per risk/file pair and do not hunt yet.

All durable output belongs in BugDB. Your final response is only a short completion note and is not consumed downstream.
