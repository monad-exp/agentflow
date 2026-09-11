## HISTORICAL goal: {{THREAT_ID}}

Your /goal is to find a security vulnerability related to {{THREAT_STATEMENT}}

Test exactly historical risk {{THREAT_ID}}, and no other.
Assignment: model {{THREAT_MODEL_ID}}, revision {{THREAT_MODEL_REVISION}}.

Attacker capability: {{ATTACKER_CAPABILITY}}

Protected asset: {{PROTECTED_ASSET}}

Security impact: {{SECURITY_IMPACT}}

Assigned attack surface: {{ATTACK_SURFACE}}

Excluded preconditions: {{EXCLUDED_PRECONDITIONS}}

Source issues: {{SOURCE_ISSUE_REFS}}

Known findings: {{KNOWN_FINDING_REFS}}

Confidence: {{CONFIDENCE}}

Find a distinct variant within these capabilities, assets, impact, and exclusions.
The implementation mechanism may differ from the source issue. Check the supplied
known findings before recording a lead; rediscovering a source issue is not
success. The assignment above, together with the `goal` object in your structured
input, is the complete context for this risk; do not substitute another one.
