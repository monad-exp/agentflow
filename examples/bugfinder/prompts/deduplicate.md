Consolidate all durable Leads for this AgentFlow run into canonical Findings.

Call `bugdb.list_hunts_and_leads` with no arguments. Include Leads from FILE, THREAT_MODEL, and ROAM Hunts; account for exhausted or blocked Hunts without inventing Leads. Merge cross-file and cross-kind Leads only when they describe the same root cause and impact, preserving every supporting Lead ID.

Do not enumerate or reproduce every Lead in prose, and spend at most 1,500 tokens on private reasoning. Build one concise, complete partition from the connector response and prioritize the durable write over explanatory analysis. On a supervised resume, use the partition already present in the Pi session and make `bugdb.create_findings` your next substantive action; re-read BugDB only if needed.

Call `bugdb.create_findings` exactly once before reaching the response limit. Use stable caller keys derived from each root cause. All durable output belongs in BugDB; your final response is only a short completion note and is not consumed downstream.
