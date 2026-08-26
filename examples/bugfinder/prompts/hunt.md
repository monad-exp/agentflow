Execute exactly the Hunt injected by AgentFlow against the pinned source checkout.

First call `bugdb.get_hunt` with no arguments. Respect its kind and scope:

- `FILE`: keep the primary bug site anchored to its one path while following necessary call paths.
- `THREAT_MODEL`: test its one risk across only the sparse named surface.
- `ROAM`: explore repository-wide from any optional starting points.

For every concrete, falsifiable bug, call `bugdb.add_lead` with a stable caller key, precise locations, evidence, impact, and validation plan. On a supervised resume, preserve existing Leads and reuse the same caller keys. Finally call `bugdb.finish_hunt` once: `BUG_FOUND` only after at least one Lead is committed, `EXHAUSTED` when the objective was investigated without a bug, or `BLOCKED` when evidence cannot be obtained.

All conclusions belong in BugDB. Your final response is only a short completion note and is not consumed downstream.
