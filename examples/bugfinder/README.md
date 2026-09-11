# Bugfinder: issue #1 MVP

This example is a single-commit, database-backed workflow:

`source snapshot → FILE / THREAT_MODEL / optional ROAM planning → Hunt fan-out → all-terminal fan-in → dedup → triage → mandatory re-review → report artifacts`

AgentFlow owns source identity, prompts, providers, models, concurrency, retries,
timeouts, node lifecycle, logs, traces, and reports. PostgreSQL owns only Hunts,
immutable Leads, canonical Findings, and write-once review fields. `runId` is the
join key. Runtime fan-out reads only stable Hunt/Finding IDs through the
connector's protected control endpoint; no downstream agent consumes another
agent's stdout or final response.

The production command and production-graph fixture both use
`build_pipeline(config)`.

## Setup and integration test

Node 20+, PostgreSQL 16+, and the AgentFlow Python package are required.

```bash
cd examples/bugfinder
npm install
npm run prisma:generate

docker run --name agentflow-bugfinder-postgres \
  -e POSTGRES_PASSWORD=agentflow_test \
  -e POSTGRES_DB=bugfinder_test \
  -p 127.0.0.1:55432:5432 \
  -d postgres:16-alpine

DATABASE_URL='postgresql://postgres:agentflow_test@127.0.0.1:55432/bugfinder_test' \
  npm run prisma:migrate

docker exec agentflow-bugfinder-postgres psql -U postgres -d bugfinder_test \
  -c "CREATE ROLE agentflow_bugdb_login LOGIN PASSWORD 'agentflow_app_test' IN ROLE agentflow_bugdb_app"

export DATABASE_URL='postgresql://agentflow_bugdb_login:agentflow_app_test@127.0.0.1:55432/bugfinder_test'
npm test

cd ../..
BUGFINDER_TEST_DATABASE_URL="$DATABASE_URL" \
  pytest -q tests/test_bugfinder_postgres_e2e.py
```

The migration owns schema changes. The application role receives `SELECT`,
`INSERT`, and only the narrow update columns required by `finish_hunt`, Lead
assignment, triage, and re-review. Database triggers enforce insert-only
canonical data and write-once transitions even if connector checks are bypassed.

The database and end-to-end fixtures create FILE, THREAT_MODEL, and exhausted
ROAM Hunts; merge one FILE Lead and one THREAT_MODEL Lead into one Finding;
apply both independent reviews; verify conflict semantics and privileges; and
assert the domain schema has no JSON columns. The workflow fixture loads the
real production graph with deterministic model adapters and launches the real
TypeScript connector.

## Run one scan

Run one command from the AgentFlow repository root:

```bash
export BUGFINDER_REPO_PATH=/absolute/path/to/repository
export BUGFINDER_REPOSITORY_URL="$(git -C "$BUGFINDER_REPO_PATH" remote get-url origin)"
export BUGFINDER_INPUT_REF=main
export DATABASE_URL='postgresql://agentflow_bugdb_login:agentflow_app_test@127.0.0.1:55432/bugfinder_test'

agentflow run examples/bugfinder/pipeline.py --output summary
```

The pipeline resolves `BUGFINDER_INPUT_REF` at run start and creates a detached
run-scoped worktree. It persists `repositoryUrl`,
`inputRef`, and the full commit SHA at
`.agentflow/runs/<run-id>/artifacts/_run/source-snapshot.json` before analysis.
The connector uses a separate port for each run and discovers its tool schemas
from MCP. Each stage receives only its allowed tools.

After both reviews, a trusted Python node asks BugDB for the canonical Finding.
BugDB derives disposition, and the Python node renders
`report.md`; a model cannot select or replace disposition.

Codex is the default for every role and uses the existing Codex CLI subscription
login with `gpt-5.6-luna`. Override globally with `BUGFINDER_AGENT=claude` or
`BUGFINDER_AGENT=pi`, or per role with variables such as
`BUGFINDER_HUNT_AGENT=pi`. Pi defaults to OpenRouter and reads
`OPENROUTER_API_KEY`. Named provider pools bound each backend independently.

Hunt nodes use supervised durable-goal retries by default: retries re-read BugDB
and reuse stable caller keys. Planner and deduplication nodes do not retry after
an uncertain commit because their narrow tool surfaces cannot fully reconcile
one. Native mode is rejected until an adapter has a tested native `/goal`
integration. Timeout, workflow deadline, and retry policy stay in Python.

## Bugfinder v3 — experimental (`examples/bugfinder/v3/`)

Experimental: writable agent processes share filesystem access with authoritative
run state. Schema validation checks structure, not who wrote the data. State
isolation remains unresolved; this example is not ready for production use.

v3 ports the Smithers `bugfinder-v3` security workflow onto AgentFlow without a
database. Every model node returns one JSON object, which the orchestrator
validates against a JSON Schema (`output_json_schema`) and stores as
`structured_output`; trusted Python collector nodes read those results, enforce
cross-member invariants, and print the collections that the next fan-out
consumes. The topology is:

`snapshot → rank_files → file hunts (per profile slot) → threat-model drafts →
synthesis → goal plan → goal hunts → collect_leads → deduplicate →
triage_context (gate 1) → triage_validity (gate 2, per slot) → triage_impact
(gate 3, fixed independent model) → trusted_report → report → collect_reports`

Trusted code, not a model, derives the final decision (CONFIRMED, REJECTED or
INCONCLUSIVE plus a closed reason) from the three gates and the vendored bounty
policy (`v3/policy/monad-bounty.md`, severity matrix and PoC rules in
`v3/policy.py`). Reports are written only for CONFIRMED findings. The contract
for every module is `v3/DESIGN.md`.

### Run one target

```bash
export BUGFINDER_WORKSPACE_ROOT=/absolute/path/to/workspaces   # <root>/<target> is cloned and pinned
export BUGFINDER_KNOWN_FINDINGS=/absolute/path/to/known-findings.jsonl
export OPENROUTER_API_KEY=...                                  # only for pi profiles

python -m examples.bugfinder.v3.run --target monad --budget medium
python -m examples.bugfinder.v3.run --target monad --budget low --print   # pipeline JSON only
```

`--print` still clones or fetches the target and resolves its SHA, so the
printed pipeline carries the same pinned `inputRef` a real run would use.

Targets, profiles, roles, budgets (`low`, `medium`, `high`) and the triage
policy live in `v3/config.yaml`; `--budget` picks the profile that sets the
rank threshold, matrix size, caps, timeouts, concurrency and deadline. Several
`--target` flags run sequentially, one AgentFlow run each; the exit code is
non-zero when any run does not complete.

Environment variables:

| Variable | Purpose |
| --- | --- |
| `BUGFINDER_WORKSPACE_ROOT` | Parent of the managed checkouts. `run.py` clones `repositoryUrl` into `<root>/<target>`, fetches `sourceRef`, resolves the SHA and detaches there. Default `.agentflow/workspaces`. |
| `BUGFINDER_REPO_PATH` | Use this existing worktree as-is (no clone or fetch); its `HEAD` becomes the pinned commit. Overrides the workspace root. |
| `BUGFINDER_KNOWN_FINDINGS` | Append-only JSONL corpus. `collect_findings` searches it for known-finding candidates; `collect_reports` appends one line per disposition. Unset disables both. |
| `OPENROUTER_API_KEY` | Read by the `pi-glm-5-3` profile's OpenRouter provider. |

Codex and Claude profiles use the harness's own login. The orchestrator runs
every node in a run-scoped pinned worktree (`<repo>/.agentflow/worktrees/<run>/source`).

### Artifacts

Everything lands under `.agentflow/runs/<run-id>/` (override with `--runs-dir`):

| Path | Content |
| --- | --- |
| `artifacts/_run/source-snapshot.json` | `repositoryUrl`, `inputRef`, pinned `commitSha`. |
| `artifacts/<node>/result.json` | Every node's result, including the schema-validated `structured_output`. |
| `artifacts/snapshot/scope-files.txt` | In-scope tracked files. |
| `artifacts/collect_threat_model/threat-model.md` | Frozen threat model. |
| `artifacts/collect_history_model/history-catalog.md` | Historical risk catalog (only when the target has a `historyFile`). |
| `artifacts/collect_leads/leads.json` | Every hunt attempt and lead. |
| `artifacts/collect_findings/findings.json` | Deduplicated findings, singleton repairs, deferred ids, known-finding candidates. |
| `artifacts/trusted_report/trusted-report.json` | `findingIds` (CONFIRMED), `dispositions` with severity and blockers, `deferredFindingIds`. |
| `artifacts/collect_reports/reports/<findingId>.md` | One report per CONFIRMED finding. |
| `artifacts/collect_reports/run-summary.json` | Findings, dispositions, written and rejected reports. |

### Tests

```bash
pytest -q tests/test_bugfinder_v3_*.py
```

`tests/test_bugfinder_v3_e2e.py` runs the real low-budget graph through the
orchestrator with deterministic fixture adapters for codex, claude and pi
against a two-file git repository; no model CLI or network is used.

### Deliberately not implemented

- Solonet and differential evidence runners: gate 2 and gate 3 agents record
  what they ran, and trusted code checks the recorded evidence shape, but no
  node provisions a solonet or drives reference clients.
- A Postgres archive of findings: the known-findings JSONL corpus is the only
  cross-run store.
- A network egress policy for agent sandboxes: the config lists prohibited
  actions and the prompts repeat them, but nothing enforces them at the OS level.
