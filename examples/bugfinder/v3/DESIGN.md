# Bugfinder v3 on AgentFlow: design and module contract

This document is the contract between the modules under `examples/bugfinder/v3/`
and the small AgentFlow core additions that support them. It is also the
rationale a reviewer needs. Keep it in sync with the code.

## 1. Decisions

Bugfinder v3 is the Smithers reference topology in
`monad-exp/security-workflows/.smithers/workflows/bugfinder-v3`. This port moves
it off Smithers onto AgentFlow with these decisions:

1. **Per-run state lives in the AgentFlow run store, not in BugDB.** Every model
   node returns one JSON object as its final response. The orchestrator
   captures it, validates it against a JSON Schema (`output_json_schema`
   success criterion), and stores it as `structured_output` in
   `artifacts/<node>/result.json`. Trusted python collector nodes read those
   files, validate cross-member invariants, repair or mark gaps, and print one
   compact JSON collection. Downstream fan-outs use the plain
   `fanout_from(collector, path=...)`, which hands every member its item as
   `node.input` (appended verbatim to the prompt as a JSON block).
2. **Agents hold no database tools.** BugDB is not used by v3. Cross-run
   known-finding search reads an append-only JSONL corpus that the final
   collector writes (`BUGFINDER_KNOWN_FINDINGS`). A Postgres archive can be
   added later by trusted code; it is out of scope here.
3. **Hunt = attempt.** One attempt is one (work item, profile, replica). A
   trusted planner node expands work items over the profile matrix; each hunt
   template is one (lane, profile, replica) slot and fans out over that slot's
   items only.
4. **Barriers, not per-finding streaming.** A fan-out template expands only
   after its source collector completes and settles when every member is
   terminal. Gate members run in parallel under provider pools.
5. **Three outcomes plus a reason.** Final decision is CONFIRMED, REJECTED or
   INCONCLUSIVE with a closed `reason` enum (KNOWN, INTENDED, FIXED,
   INFORMATIONAL, FALSE, UNPROVEN, or null for CONFIRMED). Reports are written
   only for CONFIRMED findings.
6. **Bounty policy is vendored.** `policy/monad-bounty.md` is the pinned copy
   of the bounty gist; `policy.py` encodes its severity matrix and PoC rules.
   Gate 3 records impact and likelihood; trusted code computes severity.
7. **Budget profiles.** `config.yaml` has `budgets.low|medium|high`; the
   selected profile sets threshold, matrix size, caps, timeouts and
   concurrency.
8. **One AgentFlow run per target**, started by `run.py`.

## 2. Safety rules that every module must obey

- Templates never set `input=`. If a fan-out template has `input`, members do
  not receive their item. Static context (policy, environment, source commit)
  goes into the prompt text at build time or through orchestrator-produced
  Jinja values such as `{{ nodes.snapshot.data.sourceCommit }}`.
- Prompts never reference agent-derived data through Jinja
  (`{{ item.<field> }}`, `{{ nodes.<agent>.output }}`). The fan-out pre-render
  substitutes raw text into the prompt and Jinja then evaluates it. Agent data
  reaches a member only as `node.input` (verbatim JSON block) or as a file
  path. A test lints every prompt for this.
- Plain principal consumers (`rank_files`, `threat_synthesis`,
  `history_synthesis`, `goal_plan`, `deduplicate`) are not fan-out members and
  receive no `node.input`. `pipeline.py` appends a `## Structured input`
  section that names the upstream collector's `result.json` through
  `{{ nodes.<collector>.artifacts.result_json }}`; these are
  orchestrator-produced paths of trusted python nodes, never agent text, and
  the only Jinja added outside `prompts.py`.
- Collectors read member outputs from `artifacts/<node>/result.json`
  (`structured_output`) and member statuses from `run.json`; they never trust
  file existence alone and never embed agent text into Python code.
- Collector output is compact, sorted, exact JSON under 1 MiB
  (`collectors.MAX_OUTPUT_BYTES`: AgentFlow retains at most that much stdout per
  attempt, and a longer line is cut and unparseable). `run()` fails the node
  above the limit instead of printing; the planners (`plan_file_hunts`,
  `plan_goal_hunts`) size their lanes to `OUTPUT_BUDGET_BYTES` and report what
  they deferred. Bulk data that every slot would otherwise copy (rank
  objectives, the history corpus, lead records) travels as a collector artifact
  path inside the item (`rankPath`, `historyPath`, `findingPath`). Items never
  use the key `id` (it shadows node ids in the render context); use
  `attemptId`, `findingId`, `workItemId`.
- Only python collectors are fan-out sources; agents never are.
- Every agent node has `repo_instructions_mode="ignore"`,
  `retries=workflow.retries` (1 in the shipped config), a per-phase
  `timeout_seconds` (`prompts.PHASE_TIMEOUT_FIELDS`, the single phase-to-budget
  mapping), a provider `concurrency_pool`, and an `output_json_schema` success
  criterion. Hunt, rank, dedup, context, planning, synthesis and report nodes
  are `tools="read_only"`; validity and impact nodes are `tools="read_write"`.
  The codex sandbox follows `tools`; it is not a config knob.
- Agent-derived Markdown (threat model, report) is a string field inside the
  JSON response; collectors write the `.md` artifacts.
- Residual trust boundary: agents run on the same filesystem as the run store
  (their cwd is `runtime/<node>` inside the run directory and every node
  receives `AGENTFLOW_RUN_DIR`), so a prompt-injected `read_write` gate agent
  could rewrite another member's `result.json` or `run.json` before a collector
  reads it. Collectors validate shape and cross-member invariants, not
  authorship; isolating the store from agent processes is outside this port.

## 3. Package layout

```
examples/bugfinder/v3/
  __init__.py
  DESIGN.md              this file
  config.yaml            declarative config (targets, profiles, roles, budgets, phases, triagePolicy)
  config.py              pydantic models + invariants; load_config(); resolve_budget()
  policy.py              severity matrix, PoC rules, decision derivation (pure functions)
  policy/monad-bounty.md vendored bounty gist (pinned revision in config.yaml)
  schemas/*.json         JSON Schemas for every agent output (see section 6)
  prompts/*.md           agent prompts (no Jinja except the three {{*_TIMEOUT_MS}} placeholders of the hunt prompts, see section 9)
  templates/*.md         python-rendered goal overlays (placeholders like {{THREAT_ID}}; never Jinja-rendered)
  prompts.py             prompt assembly: build_prompt(phase, ...) -> str
  collectors.py          trusted python collectors; run(name, params) entry point
  rendering.py           deterministic Markdown renderers (threat-model.md)
  pipeline.py            build_pipeline(config, target_id, budget=None) -> Graph
  run.py                 launcher: python -m examples.bugfinder.v3.run --target monad [--budget medium]
```

Tests live in `tests/test_bugfinder_v3_*.py`. The existing `pipeline.py`,
`prompts/`, connector and tests for the v2 pipeline are untouched.

## 4. Config (`config.yaml`, `config.py`)

`config.py` exposes:

```python
class V3Config(BaseModel): ...            # extra="forbid" everywhere
def load_config(path: Path | None = None) -> V3Config   # default: v3/config.yaml; rejects duplicate YAML keys
def resolve_budget(config: V3Config, name: str | None = None) -> BudgetProfile
def select_target(config: V3Config, target_id: str) -> Target   # ValueError on unknown id
def profiles_for(config, role: str, *, exclude: tuple[str, ...] = (), only: str | None = None) -> list[str]
def replicas_for(config, budget: BudgetProfile, role: str) -> int
def validity_profile_ids(config) -> list[str]   # workerSmart minus phases.triageImpact.profile
```

`workflow.retries` is the per-agent-node retry count (`pipeline.agent_node`);
`workflow.id` and `schemaVersion` are identity literals.

Top-level keys: `schemaVersion: 1`, `workflow`, `budget` (default profile
name), `budgets`, `targets`, `profiles`, `roles`, `phases`, `triagePolicy`.

Target: `id` (kebab slug), `repository` (`owner/repo`), `repositoryUrl`,
`sourceRef`, `historyFile` (optional path, `file://` or plain; text corpus of
past security issues), `scope` (`include` and `exclude` glob lists; default
include `**/*`).

Profile: `harness` in `codex | claude | pi`, `model`, `reasoning`
(`low|medium|high|xhigh|max|ultra`), optional `provider` block for pi with the
keys of AgentFlow's `ProviderConfig` (`name`, `base_url`, `api_key_env`,
`wire_api`). There is no `sandbox` knob: AgentFlow derives the sandbox from
each phase's `tools`. Default profiles: `codex-gpt-5-6-sol` (xhigh),
`claude-code-fable-5` (max), `claude-code-opus-5` (max), `pi-glm-5-3`
(openrouter, max), `codex-gpt-5-6-luna` (medium).

Roles: `principal` (`defaultProfile`, `allowedProfiles`), `workerSmart`
(`profiles`), `workerCheap` (`profiles`; optional, reserved for future
high-volume phases and unused by v3, as in Smithers). Replicas come from the
budget. A test asserts that every config field is read by `pipeline.py`,
`prompts.py`, `run.py` or a config invariant, or is listed as reserved.

Budget profile fields (all required in each of low/medium/high):

| field | low | medium | high |
|---|---|---|---|
| fileRankThreshold | 5 | 4 | 3 |
| huntProfiles (count from workerSmart, in order) | 2 | 3 | all |
| replicasPerProfile | 1 | 1 | 2 |
| contextWorkerProfiles | 2 | 3 | all |
| maxRoamGoals | 0 | 1 | 1 |
| triageFindingCap | 8 | 16 | 32 |
| validityProfiles | 2 | 3 | all |
| maxItemsPerSlot | 256 | 512 | 2048 |
| timeouts.rankMin / huntMin / contextWorkerMin / synthesisMin / goalPlanMin / dedupMin / gate1Min / gate2Min / gate3Min / reportMin | 30/30/30/20/20/30/15/30/60/20 | 30/45/45/30/30/45/20/45/120/30 | 30/55/45/30/30/45/20/45/180/30 |
| engineConcurrency | 8 | 16 | 24 |
| pools.codex / claude / pi | 4/2/2 | 8/4/4 | 12/8/12 |
| deadlineHours | 12 | 48 | null |

`huntProfiles: all` means every workerSmart profile; an integer
`huntProfiles`/`contextWorkerProfiles` above the workerSmart pool or a
`validityProfiles` above `validity_profile_ids` is rejected (it would be
truncated silently). Fixed phase assignments: gate 3 (`triage_impact`) uses
`phases.triageImpact.profile` (default `claude-code-fable-5`); validity excludes
that profile; a validator rejects a config where the impact model equals the
context model or the model of any other workerSmart profile, so excluding the
profile id is the whole validity rule.

`triagePolicy`: `guidanceSources.officialDocumentation[]` (id, url on
docs.monad.xyz), `bountyTerms` (`source: gist`, `url`, `revision`,
`path: policy/monad-bounty.md`), `pocRequiredForSeverities: [CRITICAL, HIGH]`,
`knownIssueSources.repositories[]`, `referenceClients: [geth, nethermind]`,
`routing` (`timeoutDisposition: INCONCLUSIVE`, `conflictingEvidenceDisposition: INCONCLUSIVE`),
`prohibitedActions[]` (from the gist). Validators: the vendored file exists,
its sha256 matches `bountyTerms.sha256`, every target repository is in
`knownIssueSources.repositories`, docs URLs are https on docs.monad.xyz.

## 5. Topology and node ids

Slot key: `slot_key(profile_id, replica) = profile_id.replace("-", "_") + f"_r{replica}"`,
e.g. `codex_gpt_5_6_sol_r1`. Node ids use `__` between phase and slot.

```
snapshot (python)                      -> {targetId, repositoryUrl, sourceRef, sourceCommit, scopeFiles:[...]}
rank_files (principal)                 <- reads snapshot result.json (## Structured input); output: rank.schema.json
plan_file_hunts (python)               -> {lanes: {<slot>: [attempt items]}, unranked:[...], belowThreshold:n, deferred:[...], deferredCount:n, rankPath}; writes ranked-files.json
file_hunt__<slot>  x (profiles*R)      fanout_from(plan_file_hunts, "$.lanes.<slot>", as_="attempt")
plan_context_workers (python)          <- snapshot -> {threat: {<slot>: [one item]}, history: {<slot>: [one item]}}; writes history.txt
threat_model__<slot>                   fanout_from(plan_context_workers, "$.threat.<slot>")
history_risk__<slot>                   fanout_from(plan_context_workers, "$.history.<slot>")   (only if target.historyFile)
collect_threat_drafts (python)         -> {drafts:[...], gaps:[...]}
threat_synthesis (principal)           <- reads collect_threat_drafts result.json; output: threat-model-canonical.schema.json
collect_threat_model (python)          -> {threatModel:{modelId, revision:1, ...}, markdownPath}; writes threat-model.md
collect_history_candidates (python)    -> {candidates:[...], gaps:[...]}          (history lane only)
history_synthesis (principal)          <- reads collect_history_candidates result.json; output: history-catalog.schema.json
collect_history_model (python)         -> {historyModel:{...}, markdownPath}
goal_plan (principal)                  <- reads collect_threat_model (+ collect_history_model) result.json; output: goal-plan.schema.json
plan_goal_hunts (python)               -> {lanes: {threat__<slot>:[...], historical__<slot>:[...], roam__<slot>:[...]}, goals, deferredGoals}
goal_hunt__threat__<slot>              fanout_from(plan_goal_hunts, "$.lanes.threat__<slot>", as_="attempt")
goal_hunt__historical__<slot>          (history lane only)
goal_hunt__roam__<slot>
collect_leads (python)                 depends on every hunt template -> {attempts:[...], leads:[...]}; writes leads.json
deduplicate (principal)                <- reads collect_leads result.json; output: dedup.schema.json
collect_findings (python)              -> {items:[finding+leads+knownFindingCandidates], deferredFindingIds:[...]}
triage_context (principal)             fanout_from(collect_findings, "$.items", as_="finding"); output: triage-context.schema.json
collect_contexts (python)              -> {validity: {<slot>: [items]}, findings:[...]}; writes findings/<findingId>.json per scheduled finding
triage_validity__<slot>                fanout_from(collect_contexts, "$.validity.<slot>", as_="finding"); tools read_write
collect_validity (python)              -> {items:[{findingId, finding, context, validityAttempts, gaps}]}
triage_impact (principal, Fable)       fanout_from(collect_validity, "$.items", as_="finding"); tools read_write
trusted_report (python)                -> {items:[handoffs for CONFIRMED]}; writes trusted-report.json
report (principal)                     fanout_from(trusted_report, "$.items", as_="finding"); output: report.schema.json
collect_reports (python)               writes reports/<findingId>.md, run-summary.json, appends known-findings JSONL
```

Dependencies beyond fan-out sources: `snapshot` runs first;
`plan_context_workers` and `rank_files` depend on `snapshot`;
`threat_synthesis` depends on `collect_threat_drafts`; `goal_plan` depends on `collect_threat_model` (and
`collect_history_model` when present); `collect_leads` depends on every hunt
template; `collect_validity` depends on every validity template and on
`collect_contexts`; `collect_reports` depends on `report`. Every agent node
also depends on `snapshot`: `prompts.py` renders
`{{ nodes.snapshot.data.sourceCommit }}` into gate and report prompts and
StrictUndefined needs the node in the results map. Hunt and context-worker
slots use `replicasPerProfile`; validity slots use one replica per profile
(Smithers parity) and exclude every profile whose model equals the impact
profile's model.

Attempt item (hunts): `{attemptId, kind: FILE|THREAT_MODEL|HISTORICAL|ROAM,
workItemId, profileId, replica, sourceCommit, path?, score?, rankPath?,
threatId?, goal?, overlay?}` where `overlay` is the python-rendered goal text,
`goal` the goal object and `rankPath` the `ranked-files.json` artifact holding
each file's `score`, `securityObjective` and `rationale` (every slot copies
every item, so per-file prose lives in the file, not the item). Context-worker
items: `{attemptId, kind: THREAT_DRAFT|HISTORY, workItemId, profileId, replica,
slotKey, targetId, sourceCommit, historyPath?}`. Validity items:
`{attemptId, kind: VALIDITY, workItemId, findingId, profileId, replica, slotKey,
sourceCommit, finding, context, leadIds, findingPath}`.

## 6. Agent output schemas (`schemas/`)

Each schema is a Draft 2020-12 object schema with `additionalProperties: false`
at the top level and on every nested object (port of the zod strict objects).
Field names below are required unless marked optional; optional scalars accept
`null` as well as absence and collectors treat `null` as absent.
`history-catalog` items carry the candidate fields plus `threatId` (the
`key -> threatId` relation lives in `mappings`).

- `rank.schema.json`: `{rankedFiles: [{path, score (int 1..5), securityObjective, rationale}]}`
- `hunt-result.schema.json`: `{result: BUG_FOUND|EXHAUSTED|BLOCKED, summary, leads: [{callerKey, claim, locations[min 1], evidence, attackerPreconditions?, impact?, validationPlan?}]}`; `BUG_FOUND` requires at least one lead (collector enforces).
- `threat-model-draft.schema.json`: `{summary, scope, assumptions[], exclusions[], actors:[{key, name, role, capabilities[], controlledInputs[], excludedPowers[], sourceRefs[]}], assets:[{key, name, protectedResource, securityProperties[], compromiseConsequences[], sourceRefs[]}], trustBoundaries:[{key, name, sides[], entryPoints[], enforcedChecks[], sourceRefs[]}], threats:[{key, title, violation, securityProperty, attackSurface[], preconditions[], expectedImpact, existingControls[], confidence low|medium|high, openQuestions[], actorKeys[], assetKeys[], boundaryKeys[], sourceRefs[]}]}`
- `threat-model-canonical.schema.json`: draft fields plus `sourceModels:[{attemptId}]`, `entityMappings:[{sourceAttemptId, entityType actor|asset|trust_boundary|threat, sourceKey, canonicalKey, disposition RETAINED|DEDUPLICATED, rationale?}]`, `disagreements[]`.
- `history-candidates.schema.json`: `{candidates:[{key, statement, attackSurface, attackerCapability, protectedAsset, securityImpact, excludedPreconditions[], sourceIssueRefs[min 1], knownFindingRefs[], confidence}]}`
- `history-catalog.schema.json`: `{items:[historical threat = candidate fields + threatId], sourceAttemptIds[], mappings:[{sourceAttemptId, sourceKey, threatId, disposition}]}`
- `goal-plan.schema.json`: `{goals:[{callerKey, kind THREAT_MODEL|HISTORICAL|ROAM, threatId?, outcome, scope, attackerCapabilities[], excludedPreconditions[], evidenceBar}], historyDispositions:[{historicalId, disposition ELIGIBLE|NO_VARIANT|SKIP, rationale, goalCallerKey?}]}`
- `dedup.schema.json`: `{findings:[{callerKey, title, rootCause, impact, leadIds[min 1]}]}`
- `triage-context.schema.json`: `{disposition REVIEW|KNOWN|INTENDED|FIXED|INCONCLUSIVE, rationale, guidanceReview:{expectedBehavior, documentationStatus SUPPORTED|CONTRADICTED|UNKNOWN, bountyStatus IN_SCOPE|OUT_OF_SCOPE|UNKNOWN, references:[{kind documentation|bounty-terms|specification|issue|pull-request|known-finding, url, revision, excerpt}]}, knownIssueSearch:{status COMPLETE|PARTIAL|UNAVAILABLE, sources[], matches:[reference]}, targetCommit, fixCommit (string|null), validityRequired, impactRequired, existingEvidenceIds[], validityMethods[], impactMethods[]}`; methods enum `UNIT|INTEGRATION|SOLONET|DIFFERENTIAL|SANITIZER|STATIC_PROOF|STATISTICAL|EXISTING`.
- `triage-evidence.schema.json`: `{stage VALIDITY|IMPACT, state PROVEN|FALSIFIED|INCONCLUSIVE, summary, guidanceReview, evidenceIds[], methods[], productionAssessment (object|null), differentialResults[]}` with the v3 shapes for the last two.
- `triage-impact.schema.json`: `{decision CONFIRMED|REJECTED|INCONCLUSIVE, reason KNOWN|INTENDED|FIXED|INFORMATIONAL|FALSE|UNPROVEN|null, mechanism/reachability/impactSupport SUPPORTED|CONTRADICTED|UNKNOWN, guidanceReview, evidenceIds[], rationale, limitations[], nonRuntimeJustification (string|null), impactEvidence:[triage-evidence with stage IMPACT], impact CRITICAL|HIGH|MEDIUM|LOW|null, likelihood HIGH|MEDIUM|LOW|null, ambiguousCellChoice MEDIUM|LOW|null, pocProvided bool, pocEnvironment devnet|solonet|none, localFullNodeDemonstrated bool, publicEntryPointDemonstrated bool}`
- `report.schema.json`: `{findingId, markdown}`

## 7. `policy.py`

```python
IMPACT_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
LIKELIHOOD_LEVELS = ("HIGH", "MEDIUM", "LOW")
SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
def compute_severity(impact: str, likelihood: str, ambiguous_choice: str | None = None) -> str
    # gist matrix; HIGH impact x LOW likelihood is "MEDIUM / LOW": requires ambiguous_choice in {MEDIUM, LOW}, else ValueError
def poc_required(severity: str, policy_levels: tuple[str, ...]) -> bool
def derive_decision(context: dict, validity: list[dict], impact: dict | None, *, policy: dict) -> Decision
    # Decision(decision, reason, severity, blockers: list[str]); ports v3 reportDisposition.
    # blockers list the CONFIRMED-path checks that failed; echoed (context != REVIEW) and
    # passed-through (impact != CONFIRMED) decisions carry their reason and have no blockers
    # unless the inputs were inconsistent (unknown disposition, disputed echo, missing reason).
    # missing impact -> INCONCLUSIVE/UNPROVEN "missing impact decision"
    # context not REVIEW -> decision must echo context (KNOWN/INTENDED/FIXED -> REJECTED with that reason; INCONCLUSIVE -> INCONCLUSIVE); disagreement -> INCONCLUSIVE
    # impact.decision != CONFIRMED -> pass through with its reason
    # knownIssueSearch.status != COMPLETE -> INCONCLUSIVE
    # docs != SUPPORTED or bounty != IN_SCOPE -> INCONCLUSIVE
    # any FALSIFIED in validity or impactEvidence -> INCONCLUSIVE
    # validityRequired and no PROVEN validity -> INCONCLUSIVE; impactRequired and no PROVEN impact -> INCONCLUSIVE
    # every planned method must appear in some PROVEN attempt -> else INCONCLUSIVE
    # not impactRequired requires existingEvidenceIds and nonRuntimeJustification -> else INCONCLUSIVE
    # impact.evidenceIds must be subset of established ids -> else INCONCLUSIVE
    # severity from compute_severity; if poc_required(severity) and not pocProvided (devnet|solonet) -> INCONCLUSIVE
    # resource exhaustion claims (methods include STATISTICAL or limitations mention DoS) need localFullNodeDemonstrated -> else INCONCLUSIVE
def severity_guidance_text(policy_md: str) -> str   # extracts the severity/PoC sections for prompts
```

## 8. `collectors.py`

Entry point used by every python node:

```python
def run(name: str, params: dict) -> None   # dispatches to collect_<name>, prints json.dumps(result, sort_keys=True, separators=(",", ":"))
```

Runtime discovery, never Jinja: `AGENTFLOW_RUN_DIR`, `AGENTFLOW_RUN_ID` and
`AGENTFLOW_NODE_ID` (set by the orchestrator, see section 10). `run()` raises
`CollectorError` when the compact JSON exceeds `MAX_OUTPUT_BYTES`. Helpers:

```python
class RunView:  # reads <run_dir>/run.json with a 3x retry on JSONDecodeError; node inputs are indexed once
    def fanout_members(self, template_id) -> list[str]
    def node_status(self, node_id) -> str
    def structured_output(self, node_id) -> Any | None   # artifacts/<node>/result.json -> structured_output
    def node_input(self, node_id) -> Any | None          # pipeline node spec input
    def write_artifact(self, name, text) / write_json(name, obj)   # into artifacts/<own node>/
```

Collectors and their `params` (static JSON embedded at build time):

- `snapshot(params={targetId, repositoryUrl, sourceRef, include[], exclude[]})`: `git rev-parse HEAD` and `git ls-files` in cwd (the pinned worktree); applies globs; prints `{targetId, repositoryUrl, sourceRef, sourceCommit, scopeFiles, scopeFilesPath, trackedFileCount}` and writes `scope-files.txt`.
- `plan_file_hunts(params={rankNode, snapshotNode, threshold, maxItemsPerSlot, slots:[{slotKey, profileId, replica}]})`: validates ranks against `scopeFiles` (missing files become score 1 with rationale `unranked`, logged in `unranked`; unknown paths dropped and logged), writes `ranked-files.json` (path -> `{score, securityObjective, rationale}`), filters `score >= threshold`, keeps the first `maxItemsPerSlot` by `(-score, path)`, then shrinks the plan (binary search over the item count) until the compact output fits `OUTPUT_BUDGET_BYTES`; lane items carry `path`, `score` and `rankPath` only. `deferred` lists at most 200 deferred paths, `deferredCount` the total; `unranked`/`unrankedCount` likewise; both caps are logged.
- `plan_context_workers(params={snapshotNode, slots, history: bool, historyText})`: one item per slot per lane with `targetId` and `sourceCommit` from the snapshot; the corpus is written once to `history.txt` and referenced as `historyPath`, never inlined.
- `collect_threat_drafts(params={templates:[...]})`, `collect_history_candidates(params={templates})`: gather member outputs; members with status != completed become `gaps`.
- `collect_threat_model(params={synthesisNode, draftsNode, snapshotNode, targetId})`: validates every draft entity key of every completed draft has exactly one mapping, every canonical key exists, DEDUPLICATED has rationale; assigns `modelId = "tm_" + sha256(run_id)[:12]`, `revision: 1`; records `sourceCommit` (from the snapshot) and `targetId` on the model; renders Markdown via `rendering.render_threat_model_markdown`; writes `threat-model.md`.
- `collect_history_model(params={synthesisNode, candidatesNode, snapshotNode, targetId})`: same shape; `modelId = "hm_..."`; writes `history-catalog.md`.
- `plan_goal_hunts(params={goalPlanNode, threatModelNode, historyModelNode|null, snapshotNode, slots, maxRoamGoals, maxItemsPerSlot, templatesDir})`: validates goals (THREAT_MODEL threatId in frozen model, HISTORICAL threatId in catalog with ELIGIBLE disposition, every catalog item has exactly one disposition, ELIGIBLE has exactly one goal), keeps first `maxRoamGoals` ROAM goals (extras logged), renders overlays from `templates/goal-threat-model.md` and `templates/goal-historical.md` with `str.replace` of `{{THREAT_ID}}`-style placeholders (`prompts.TEMPLATE_PLACEHOLDER`; JSON-encoded values for arrays, never Jinja), caps each kind at `maxItemsPerSlot`, shrinks to `OUTPUT_BUDGET_BYTES` from the tail of the plan, expands slots. Every slot gets all three lanes (empty lists allowed); `deferredGoals` lists what was dropped; an unresolved placeholder or missing template raises `CollectorError`, a build defect.
- `collect_leads(params={templates:[...]})`: for every member: status completed and result present -> attempt row + leads (`leadId = "lead_" + sha256(attemptId + "\0" + callerKey)[:16]`; `BUG_FOUND` with zero leads becomes `EXHAUSTED` with a note); status failed/timed_out/cancelled/skipped -> attempt row with `terminalState` upper-cased status and no leads. Writes `leads.json`.
- `collect_findings(params={dedupNode, leadsNode, cap, knownFindingsPath|null})`: partition check; unknown leadIds dropped and logged; leads assigned twice keep the first; unassigned leads become singleton findings (`title` from claim); `findingId = "finding_" + sha256(callerKey)[:16]`; order by dedup order then singletons; cap; `deferredFindingIds`; known-finding candidates by token overlap (>= 3 shared tokens of title/rootCause/locations) from the JSONL corpus. Writes `findings.json`.
- `collect_contexts(params={gateTemplate, findingsNode, validitySlots})`: validates the v3 superRefine rules (see section 6); invalid or missing context -> `disposition: INCONCLUSIVE` with `gap` reason; emits validity items for `REVIEW && validityRequired`. Each scheduled finding's bundle (`finding`, `leads`, `context`, `discoveryOutcomes`, `knownFindingCandidates`) is written to `findings/<findingId>.json`; the validity item carries `finding`, `context`, `leadIds` and `findingPath`, while the `findings` entries keep the leads inline for `collect_validity`. A `targetCommit` that differs from the leads' source commit is logged, not treated as a gap.
- `collect_validity(params={validityTemplates, contextsNode})`: bundles per finding; failed members become `gaps: [{attemptId, nodeId, slotKey, status, reasons}]`. Findings whose context gate produced a gap are listed under `skipped`, not `items`, so gate 3 never runs on an empty context.
- `trusted_report(params={impactTemplate, validityNode, policy})`: `policy.derive_decision` per finding; missing impact member -> INCONCLUSIVE/UNPROVEN; writes `trusted-report.json = {findingIds (CONFIRMED), dispositions:[{findingId, decision, reason, severity, blockers}], deferredFindingIds}`; emits handoffs `{findingId, finding, leads, context, validityAttempts, impactDecision, disposition, severity, discoveryOutcomes (attempts whose leads belong to the finding), knownFindingCandidates}`. `skipped` findings get INCONCLUSIVE/UNPROVEN with a `context gap:` blocker without calling policy. The node output is a superset of the file: `{items, findingIds, dispositions, deferredFindingIds, findings (per-finding summaries), gaps, log}`.
- `collect_reports(params={reportTemplate, trustedNode, targetId, repositoryUrl, knownFindingsPath|null, sourceCommit?})`: validates `findingId` equals the member's item, markdown starts with `# `, contains the finding id, and every `github.com/<owner>/<repo>/blob|tree/<ref>/` link into the target repository (`owner/repo` from `repositoryUrl`) uses the run's source commit (a branch name or another sha is rejected); links into other repositories (reference clients, specifications) may pin any ref. Invalid reports are recorded as `rejected` (not raised). `sourceCommit` is present when the pipeline was built with a resolved sha; otherwise the leads' source commit is used and, if still unknown, the permalink check is skipped and logged; without `repositoryUrl` every GitHub permalink is held to the source commit (logged). Writes `reports/<findingId>.md`, `run-summary.json`; appends one JSON line per disposition to `params.knownFindingsPath` when set.

Every collector exits non-zero only on programming errors or missing
upstream artifacts; policy failures are recorded in the output.

## 9. `prompts.py` and prompt files

```python
def build_prompt(phase: str, *, config: V3Config, budget: BudgetProfile, target: Target, schema: dict, extra: dict[str, str] | None = None, source_ref: str | None = None) -> str
def phase_timeout_minutes(phase: str, budget: BudgetProfile) -> int   # PHASE_TIMEOUT_FIELDS[phase]; pipeline.py derives timeout_seconds from it
TEMPLATE_PLACEHOLDER = re.compile(r"\{\{([A-Z][A-Z0-9_]*)\}\}")          # shared with collectors (no inner whitespace)
```

Assembles: the phase prompt from `prompts/<phase>.md` (goal hunts:
`goal-common.md`; the overlay arrives inside `node.input.overlay`), then a
`## Target` section (repository URL, the effective source ref — `source_ref`,
the sha `run.py` resolved, else `target.sourceRef` — and, on gate and report
phases, `{{ nodes.snapshot.data.sourceCommit }}`), then a
`## Required output` section with the JSON Schema (`json.dumps(schema, indent=2)`),
then `## Response rules` (return only one JSON object; no prose; no Markdown
fences; the structured input block below is your assignment, or the files named
in a `Structured input` section when no block is appended), then for triage
and report phases a `## Bounty policy` section with the severity and PoC
guidance (`policy.severity_guidance_text`) and the `triagePolicy` JSON, and for
hunts the timeout numbers substituted by `str.replace` from
`{{SEARCH_TIMEOUT_MS}}`, `{{FINALIZATION_GRACE_MS}}`, `{{HARD_TIMEOUT_MS}}`
(search = hard - 5 min, grace = 5 min); these three placeholders are the only
`{{` sequences allowed in a prompt file. The assembled prompt must contain no
`{{`, `{%` or `{#` sequences except orchestrator-safe Jinja that `prompts.py`
adds itself (currently only `{{ nodes.snapshot.data.sourceCommit }}`); the
`## Structured input` pointer of section 2 is added by `pipeline.py` after
assembly. All parameters are the real pydantic models; there is no
duck-typing for stand-ins.

Prompt files (ported from v3, rewritten for JSON output instead of BugDB tool
calls): `rank.md`, `file-hunt.md`, `goal-common.md`, `threat.md`,
`threat-synthesis.md`, `historical-risk-classes.md`,
`historical-synthesis.md`, `goal-plan.md`, `deduplicate.md`,
`triager-1-context.md`, `triager-2-validity.md`, `triager-3-impact.md`,
`report.md`. Templates: `templates/goal-threat-model.md`,
`templates/goal-historical.md`, `templates/goal-roam.md`.

## 10. AgentFlow core additions (all small, backward compatible)

1. `contracts.parse_json_output`: after the existing whole-text attempt, try
   the text as one fenced block (first and last lines are fence markers), then
   the last fenced block whose body parses (fence markers count only on lines
   of their own, so a ``` inside a JSON string never closes a block; openers
   and closers are tried from the end), then the last top-level `{...}` or
   `[...]` that starts the text, starts a line or follows a colon and runs to
   the end (`json.JSONDecoder.raw_decode`; prose such as `see [1]` is not
   JSON). Error text unchanged when nothing parses.
2. `contracts.validate_json_instance(instance, schema) -> list[str]`: sorted,
   capped (20) error strings `"<json pointer>: <message>"`.
3. New success criteria in `specs.py` and `success.py`:
   - `{"kind": "output_json_schema", "schema": {...}}` validates the parsed
     final response (`result.structured_output` or re-parsed output).
   - `{"kind": "file_json_schema", "path": "...", "schema": {...}, "root": "runtime"|"workdir", "modified_in_attempt": true}`;
     `modified_in_attempt` allows a 50 ms mtime tolerance for the coarse kernel clock.
   The wire key is `schema`; the pydantic attribute is `json_schema`
   (`Field(alias="schema")`, since `schema` shadows `BaseModel.schema`).
   `evaluate_success(node, result, working_dir, *, runtime_dir=None, attempt_started_at=None)`.
   Messages list every schema error (capped) so the retry prompt can show them.
4. Orchestrator: pass `runtime_dir` and `attempt_started_at` to
   `evaluate_success`; on an in-loop retry (`retry_index > 0`, the previous
   attempt FAILED or TIMED_OUT) whose previous attempt has `success is False`,
   append `"\n\nAgentFlow previous attempt did not meet its success criteria:\n- ..."` (failed lines only, at most 2000 chars) to the attempt prompt. A recovered or rerun attempt after a cancelled one is not a retry and gets the plain prompt.
5. Orchestrator sets `AGENTFLOW_RUN_ID`, `AGENTFLOW_RUN_DIR`, `AGENTFLOW_NODE_ID`,
   `AGENTFLOW_RUNTIME_DIR` in the adapter node env for every node (values
   from the store and `ExecutionPaths`): `AGENTFLOW_RUN_DIR` is the resolved
   host run directory, `AGENTFLOW_RUNTIME_DIR` the runtime directory as the
   node process sees it. They override same-named `node.env` keys and are
   never written to the stored spec.
6. `context.py`: add `run: {id, directory, artifacts_directory, runtime_directory}`
   to the render context and `runtime_dir` to every `nodes.<id>.artifacts`.
7. `agents/pi.py`: cwd is the runtime dir when `repo_instructions_mode == ignore`
   (parity with codex, claude, kimi).
8. `agents/util.py` `PythonAdapter`: honour `node.executable` (default
   `python3`).
9. `orchestrator.resume()`: also copy `runtime/<node>` directories of
   completed nodes.
10. `docs/pipelines.md`: document the two criteria, the `run` context key,
    the env variables, and the retry feedback.
11. `store.RunStore`: `run.json`, `artifacts/<node>/*` and run artifacts are
    written to a sibling temp file and renamed into place (`os.replace`), so a
    collector reading `run.json` or a member's `result.json` while the
    orchestrator rewrites it never sees a torn file.

## 11. `pipeline.py` and `run.py`

```python
def build_pipeline(config: V3Config, target_id: str, *, budget: str | None = None, agentflow_root: Path | None = None, python_executable: str | None = None, source_ref: str | None = None, environment: Mapping[str, str] | None = None) -> Graph
```

`source_ref` (the sha `run.py` resolved) overrides `target.sourceRef` for
`source_snapshot.inputRef`, the snapshot params, the `## Target` section of
every prompt and, when it is a full sha, `collect_reports.sourceCommit`.
`environment` (default `os.environ`) supplies `BUGFINDER_REPO_PATH`,
`BUGFINDER_WORKSPACE_ROOT` and `BUGFINDER_KNOWN_FINDINGS`; the builder reads
no other process state. Agent timeouts are
`phase_timeout_minutes(phase, budget) * 60`; the three fan-out shapes (hunt,
context worker, gate) share one `fanout_agent` helper and the schema loaded for
a prompt is the same object used by its success criterion.

Graph: `name="bugfinder-v3-<target>"`, `working_dir=<checkout path>`
(`BUGFINDER_WORKSPACE_ROOT/<target.id>` or `BUGFINDER_REPO_PATH`),
`source_snapshot={repositoryUrl, inputRef: sourceRef or resolved sha}`,
`concurrency=budget.engineConcurrency`, `concurrency_pools` per harness,
`deadline_seconds` from `deadlineHours` (None allowed), `fail_fast=False`.
Python nodes use `python_node(task_id, code=..., executable=python_executable or sys.executable, timeout_seconds=600)`
with code:

```python
import json, sys
sys.path.insert(0, <agentflow_root>)
from examples.bugfinder.v3 import collectors
collectors.run(<name>, json.loads(<params json literal>))
```

`run.py`: `--target <id> [--budget low|medium|high] [--config path] [--print] [--runs-dir]`;
ensures `$BUGFINDER_WORKSPACE_ROOT/<target>` is a clone of `repositoryUrl`
(`git fetch --force origin +<sourceRef>:refs/bugfinder/source`, detached
checkout of the resolved sha), builds the pipeline with `source_ref=<sha>`,
and either prints the pipeline JSON (`--print`) or runs it through
Orchestrator submit/wait. With `BUGFINDER_REPO_PATH` set the worktree is used
as-is and its `HEAD` is the pinned sha (no clone or fetch). The orchestrator
then runs every node in a run-scoped pinned worktree
(`<repo>/.agentflow/worktrees/<run>/source`). Targets run sequentially.

## 12. Tests

- `tests/test_bugfinder_v3_config.py`: loads the shipped config, budget
  resolution, every invariant has a negative case, vendored policy hash.
- `tests/test_bugfinder_v3_policy.py`: severity matrix table (every cell),
  ambiguous cell, PoC rule, `derive_decision` one case per branch.
- `tests/test_bugfinder_v3_collectors.py`: each collector against a fake run
  directory (`run.json` + `artifacts/<node>/result.json` fixtures): partition
  repair, threshold filter, goal validation, ROAM cap, gaps, report checks,
  known-findings append and match.
- `tests/test_bugfinder_v3_prompts.py`: every phase prompt renders through
  `render_node_prompt` with an empty results map (the four phases that render
  the source commit use a completed `snapshot` result); lint: no `{{ item.`
  and no `nodes.<agent-node>` in any prompt; schema block present.
- `tests/test_bugfinder_v3_pipeline.py`: node ids and `depends_on` for each
  budget, no template has `input`, every agent node has `output_json_schema`,
  timeouts and pools from the budget, impact model independent from context
  and validity models, slot counts, history lane absent without `historyFile`.
- `tests/test_bugfinder_v3_e2e.py`: Orchestrator run with a fixture adapter
  (registered for codex, claude and pi) that returns canned JSON per node id
  prefix and `node.input`, emitted as one final-message event in each
  harness's own stream format (the orchestrator picks the trace parser by
  agent kind, so codex-style events would be dropped for claude and pi
  nodes); plain principal nodes read the upstream collector's `result.json`.
  Budget `low`; a two-file fixture repository; asserts every node completed
  on its first attempt, `trusted-report.json` has exactly one CONFIRMED
  finding with severity HIGH, `reports/<findingId>.md` carries the source
  commit in a permalink, `run-summary.json` and the known-findings JSONL are
  written, the rendered prompts carry the collector path (principal nodes)
  and the source commit (gates), and a second scenario where dedup omits a
  lead produces a singleton finding that ends INCONCLUSIVE while the run
  still completes.
- Core tests: `tests/test_success.py` (both criteria, modified_in_attempt),
  `tests/test_contracts.py` (parser fallbacks), `tests/test_context.py`
  (`run` key), `tests/test_agents.py` (pi cwd, python executable),
  `tests/test_runtime_workflows.py` (retry feedback text, env vars, resume
  copies runtime dir).
