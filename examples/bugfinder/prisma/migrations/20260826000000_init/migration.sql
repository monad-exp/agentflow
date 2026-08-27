CREATE TYPE "HuntKind" AS ENUM ('FILE', 'THREAT_MODEL', 'ROAM');
CREATE TYPE "HuntResult" AS ENUM ('BUG_FOUND', 'EXHAUSTED', 'BLOCKED');
CREATE TYPE "FindingVerdict" AS ENUM ('CONFIRMED', 'REJECTED', 'INCONCLUSIVE');

CREATE TABLE "hunts" (
    "id" TEXT NOT NULL,
    "run_id" TEXT NOT NULL,
    "kind" "HuntKind" NOT NULL,
    "objective" TEXT NOT NULL,
    "paths" TEXT[] NOT NULL,
    "result" "HuntResult",
    "result_summary" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "hunts_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "hunts_file_scope_check" CHECK ("kind" <> 'FILE' OR cardinality("paths") = 1),
    CONSTRAINT "hunts_result_pair_check" CHECK (("result" IS NULL) = ("result_summary" IS NULL))
);

CREATE TABLE "findings" (
    "id" TEXT NOT NULL,
    "run_id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "root_cause" TEXT NOT NULL,
    "impact" TEXT NOT NULL,
    "triage_verdict" "FindingVerdict",
    "triage_assessment" TEXT,
    "rereview_verdict" "FindingVerdict",
    "rereview_assessment" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "findings_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "findings_triage_pair_check" CHECK (("triage_verdict" IS NULL) = ("triage_assessment" IS NULL)),
    CONSTRAINT "findings_rereview_pair_check" CHECK (("rereview_verdict" IS NULL) = ("rereview_assessment" IS NULL))
);

CREATE TABLE "leads" (
    "id" TEXT NOT NULL,
    "hunt_id" TEXT NOT NULL,
    "finding_id" TEXT,
    "claim" TEXT NOT NULL,
    "locations" TEXT[] NOT NULL,
    "evidence" TEXT NOT NULL,
    "attacker_preconditions" TEXT,
    "impact" TEXT,
    "validation_plan" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "leads_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "hunts_run_id_kind_idx" ON "hunts"("run_id", "kind");
CREATE INDEX "leads_hunt_id_idx" ON "leads"("hunt_id");
CREATE INDEX "leads_finding_id_idx" ON "leads"("finding_id");
CREATE INDEX "findings_run_id_idx" ON "findings"("run_id");

ALTER TABLE "leads" ADD CONSTRAINT "leads_hunt_id_fkey" FOREIGN KEY ("hunt_id") REFERENCES "hunts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "leads" ADD CONSTRAINT "leads_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "findings"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE FUNCTION enforce_hunt_write_once() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
    IF (NEW.id, NEW.run_id, NEW.kind, NEW.objective, NEW.paths, NEW.created_at)
       IS DISTINCT FROM
       (OLD.id, OLD.run_id, OLD.kind, OLD.objective, OLD.paths, OLD.created_at) THEN
        RAISE EXCEPTION 'hunt definitions are insert-only';
    END IF;
    IF OLD.result IS NOT NULL AND
       (NEW.result, NEW.result_summary) IS DISTINCT FROM (OLD.result, OLD.result_summary) THEN
        RAISE EXCEPTION 'hunt result is write-once';
    END IF;
    IF OLD.result IS NULL AND NEW.result = 'BUG_FOUND' AND
       NOT EXISTS (SELECT 1 FROM leads WHERE hunt_id = OLD.id) THEN
        RAISE EXCEPTION 'BUG_FOUND requires at least one committed Lead';
    END IF;
    RETURN NEW;
END
$body$;

CREATE FUNCTION enforce_lead_write_once() RETURNS trigger LANGUAGE plpgsql AS $body$
DECLARE
    hunt_run_id TEXT;
BEGIN
    IF (NEW.id, NEW.hunt_id, NEW.claim, NEW.locations, NEW.evidence,
        NEW.attacker_preconditions, NEW.impact, NEW.validation_plan, NEW.created_at)
       IS DISTINCT FROM
       (OLD.id, OLD.hunt_id, OLD.claim, OLD.locations, OLD.evidence,
        OLD.attacker_preconditions, OLD.impact, OLD.validation_plan, OLD.created_at) THEN
        RAISE EXCEPTION 'Leads are insert-only';
    END IF;
    IF OLD.finding_id IS NOT NULL AND NEW.finding_id IS DISTINCT FROM OLD.finding_id THEN
        RAISE EXCEPTION 'a Lead can be assigned at most once';
    END IF;
    IF NEW.finding_id IS NOT NULL THEN
        SELECT run_id INTO hunt_run_id FROM hunts WHERE id = OLD.hunt_id;
        IF NOT EXISTS (
            SELECT 1 FROM findings WHERE id = NEW.finding_id AND run_id = hunt_run_id
        ) THEN
            RAISE EXCEPTION 'Lead and Finding must belong to the same run';
        END IF;
    END IF;
    RETURN NEW;
END
$body$;

CREATE FUNCTION reject_lead_after_hunt_finish() RETURNS trigger LANGUAGE plpgsql AS $body$
DECLARE
    hunt_result "HuntResult";
BEGIN
    SELECT result INTO hunt_result FROM hunts WHERE id = NEW.hunt_id FOR UPDATE;
    IF FOUND AND hunt_result IS NOT NULL THEN
        RAISE EXCEPTION 'cannot append a Lead after its Hunt is finished';
    END IF;
    RETURN NEW;
END
$body$;

CREATE FUNCTION enforce_finding_write_once() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
    IF (NEW.id, NEW.run_id, NEW.title, NEW.root_cause, NEW.impact, NEW.created_at)
       IS DISTINCT FROM
       (OLD.id, OLD.run_id, OLD.title, OLD.root_cause, OLD.impact, OLD.created_at) THEN
        RAISE EXCEPTION 'Finding canonical fields are insert-only';
    END IF;
    IF OLD.triage_verdict IS NOT NULL AND
       (NEW.triage_verdict, NEW.triage_assessment)
       IS DISTINCT FROM (OLD.triage_verdict, OLD.triage_assessment) THEN
        RAISE EXCEPTION 'triage is write-once';
    END IF;
    IF OLD.rereview_verdict IS NOT NULL AND
       (NEW.rereview_verdict, NEW.rereview_assessment)
       IS DISTINCT FROM (OLD.rereview_verdict, OLD.rereview_assessment) THEN
        RAISE EXCEPTION 're-review is write-once';
    END IF;
    RETURN NEW;
END
$body$;

CREATE TRIGGER hunts_write_once BEFORE UPDATE ON hunts
FOR EACH ROW EXECUTE FUNCTION enforce_hunt_write_once();
CREATE TRIGGER leads_before_hunt_finish BEFORE INSERT ON leads
FOR EACH ROW EXECUTE FUNCTION reject_lead_after_hunt_finish();
CREATE TRIGGER leads_write_once BEFORE UPDATE ON leads
FOR EACH ROW EXECUTE FUNCTION enforce_lead_write_once();
CREATE TRIGGER findings_write_once BEFORE UPDATE ON findings
FOR EACH ROW EXECUTE FUNCTION enforce_finding_write_once();

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agentflow_bugdb_app') THEN
        CREATE ROLE agentflow_bugdb_app NOLOGIN;
    END IF;
END
$roles$;

REVOKE ALL ON "hunts", "leads", "findings" FROM agentflow_bugdb_app;
GRANT USAGE ON SCHEMA public TO agentflow_bugdb_app;
GRANT USAGE ON TYPE "HuntKind", "HuntResult", "FindingVerdict" TO agentflow_bugdb_app;
GRANT SELECT ON "hunts", "leads", "findings" TO agentflow_bugdb_app;
GRANT INSERT ("id", "run_id", "kind", "objective", "paths") ON "hunts" TO agentflow_bugdb_app;
GRANT INSERT (
    "id", "hunt_id", "claim", "locations", "evidence",
    "attacker_preconditions", "impact", "validation_plan"
) ON "leads" TO agentflow_bugdb_app;
GRANT INSERT ("id", "run_id", "title", "root_cause", "impact") ON "findings" TO agentflow_bugdb_app;
GRANT UPDATE ("result", "result_summary") ON "hunts" TO agentflow_bugdb_app;
GRANT UPDATE ("finding_id") ON "leads" TO agentflow_bugdb_app;
GRANT UPDATE ("triage_verdict", "triage_assessment", "rereview_verdict", "rereview_assessment") ON "findings" TO agentflow_bugdb_app;
