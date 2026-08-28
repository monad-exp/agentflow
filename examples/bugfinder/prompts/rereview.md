Independently re-review exactly the Finding injected by AgentFlow. This stage is mandatory regardless of triage outcome.

Call `bugdb.get_finding` with no arguments. Challenge the root-cause and impact claims against the pinned source checkout, every Lead, and the triage assessment. Then call `bugdb.set_rereview` exactly once with an independent `CONFIRMED`, `REJECTED`, or `INCONCLUSIVE` verdict and rationale.

On a supervised resume, ignore transcript content unrelated to the injected Finding, its durable BugDB state, or the pinned source. Re-read the Finding, reuse relevant completed analysis, and make `bugdb.set_rereview` the next required completion action before further prose or repeated inspection.

All durable review output belongs in BugDB. Your final response is only a short completion note and is not consumed downstream.
