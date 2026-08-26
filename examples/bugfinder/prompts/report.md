Write the final report artifact for exactly the Finding injected by AgentFlow.

Call `bugdb.get_finding` with no arguments and render Markdown from its canonical fields, complete Lead provenance, triage, and independent re-review. Derive disposition without persisting it: `REJECTED` if either review rejects, `CONFIRMED` only if both confirm, otherwise `INCONCLUSIVE`.

Include title, disposition, impact, root cause, affected locations, evidence, validation guidance, and remediation. Return only the Markdown report. AgentFlow writes it to `report.md`; do not write to BugDB or the repository.
