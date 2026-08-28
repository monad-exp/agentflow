Triage exactly the Finding injected by AgentFlow.

Call `bugdb.get_finding` with no arguments, inspect the pinned source and all cross-file/cross-kind Lead evidence, then call `bugdb.set_triage` exactly once with `CONFIRMED`, `REJECTED`, or `INCONCLUSIVE` and a precise assessment. Do not report yet.

On a supervised resume, ignore transcript content unrelated to the injected Finding, its durable BugDB state, or the pinned source. Re-read the Finding, reuse relevant completed analysis, and make `bugdb.set_triage` the next required completion action before further prose or repeated inspection.

All durable review output belongs in BugDB. Your final response is only a short completion note and is not consumed downstream.
