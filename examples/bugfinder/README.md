# Bugfinder: issue #1 MVP

This example is a single-commit, database-backed workflow:

`source snapshot → FILE / THREAT_MODEL / optional ROAM planning → Hunt fan-out → all-terminal fan-in → dedup → triage → mandatory re-review → report artifacts`

AgentFlow owns source identity, prompts, providers, models, concurrency, retries,
timeouts, node lifecycle, logs, traces, and reports. PostgreSQL owns only Hunts,
immutable Leads, canonical Findings, and write-once review fields. `runId` is the
join key. Runtime fan-out reads only stable Hunt/Finding IDs through the
connector's protected control endpoint; no downstream agent consumes another
agent's stdout or final response.

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

The database and end-to-end fixtures create FILE, THREAT_MODEL, and exhausted ROAM Hunts;
merges one FILE Lead and one THREAT_MODEL Lead into one Finding; applies both
independent reviews; verifies conflict semantics and privileges; and asserts the
domain schema has no JSON columns. The end-to-end fixture launches the real
TypeScript connector through AgentFlow and verifies the resulting `report.md`.

## Run one scan

Check out the commit to inspect, then run one command from the repository root:

```bash
export BUGFINDER_REPO_PATH=/absolute/path/to/repository
export BUGFINDER_REPOSITORY_URL="$(git -C "$BUGFINDER_REPO_PATH" remote get-url origin)"
export BUGFINDER_INPUT_REF=main
export DATABASE_URL='postgresql://agentflow_bugdb_login:agentflow_app_test@127.0.0.1:55432/bugfinder_test'

agentflow run examples/bugfinder/pipeline.py --output summary
```

The pipeline resolves `BUGFINDER_INPUT_REF`, requires a clean working tree whose
`HEAD` matches it, and persists `repositoryUrl`, `inputRef`, and the full commit SHA at
`.agentflow/runs/<run-id>/artifacts/_run/source-snapshot.json` before launching
analysis nodes. Each report worker writes `report.md` in its own artifact
directory.

Codex is the default for every role and uses the existing Codex CLI subscription
login with `gpt-5.6-luna`. Override globally with `BUGFINDER_AGENT=claude` or
`BUGFINDER_AGENT=pi`, or per role with variables such as
`BUGFINDER_HUNT_AGENT=pi`. Pi defaults to OpenRouter and reads
`OPENROUTER_API_KEY`. Named provider pools bound each backend independently.

Nodes use supervised durable-goal retries by default: retries re-read BugDB and
reuse stable caller keys. Set `BUGFINDER_GOAL_MODE=native` only for an executor
that supports a native `/goal` command. Timeout and retry policy stays in Python.

For a one-model connector check, run:

```bash
agentflow run examples/bugfinder/smoke.py --output summary
```

It uses subscription-authenticated Codex with `gpt-5.6-luna` to append one
Hunt, fan out from the durable Hunt ID, read the injected scope, and set an
`EXHAUSTED` result. Required connector-call success criteria make the nodes
retry if an agent returns without performing the durable write. The connector
receives `DATABASE_URL`; local agent subprocesses do not.
