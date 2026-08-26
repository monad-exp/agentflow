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
