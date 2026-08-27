Consolidate all durable Leads for this AgentFlow run into canonical Findings.

Call `bugdb.list_hunts_and_leads` with no arguments. Include Leads from FILE, THREAT_MODEL, and ROAM Hunts; account for exhausted or blocked Hunts without inventing Leads. Merge cross-file and cross-kind Leads only when they describe the same root cause and impact, preserving every supporting Lead ID.

Do not reproduce every Lead in your reasoning. Build one concise, complete partition from the connector response and prioritize the durable write over explanatory analysis. On a supervised resume, continue from the existing Pi session and re-read BugDB only if needed.

Call `bugdb.create_findings` exactly once before reaching the response limit. Use stable caller keys derived from each root cause. All durable output belongs in BugDB; your final response is only a short completion note and is not consumed downstream.
