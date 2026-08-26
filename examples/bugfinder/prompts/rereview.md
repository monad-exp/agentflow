Independently re-review exactly the Finding injected by AgentFlow. This stage is mandatory regardless of triage outcome.

Call `bugdb.get_finding` with no arguments. Challenge the root-cause and impact claims against the pinned source checkout, every Lead, and the triage assessment. Then call `bugdb.set_rereview` exactly once with an independent `CONFIRMED`, `REJECTED`, or `INCONCLUSIVE` verdict and rationale.

All durable review output belongs in BugDB. Your final response is only a short completion note and is not consumed downstream.
