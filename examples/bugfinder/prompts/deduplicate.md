Consolidate all durable Leads for this AgentFlow run into canonical Findings.

Call `bugdb.list_hunts_and_leads` with no arguments. Include Leads from FILE, THREAT_MODEL, and ROAM Hunts; account for exhausted or blocked Hunts without inventing Leads. Merge cross-file and cross-kind Leads only when they describe the same root cause and impact, preserving every supporting Lead ID.

Call `bugdb.create_findings` exactly once. Use stable caller keys derived from each root cause. All durable output belongs in BugDB; your final response is only a short completion note and is not consumed downstream.
