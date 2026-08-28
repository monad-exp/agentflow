import { randomUUID } from "node:crypto";

import { FindingVerdict, HuntKind, HuntResult, PrismaClient } from "@prisma/client";
import { afterAll, describe, expect, test } from "vitest";

import {
  addHunts,
  addLead,
  createFindings,
  finishHunt,
  getFinding,
  listHuntsAndLeads,
  setRereview,
  setTriage,
} from "../src/bugdb.js";

const databaseUrl = process.env.DATABASE_URL;

describe.skipIf(!databaseUrl)("append-constrained BugDB tools", () => {
  const prisma = new PrismaClient();
  const runId = `fixture-${randomUUID()}`;
  const runScope = { runId };

  afterAll(async () => prisma.$disconnect());

  test("merges FILE and THREAT_MODEL Leads while preserving an exhausted Hunt", async () => {
    await expect(
      addHunts(prisma, runScope, {
        hunts: [
          { callerKey: "duplicate", kind: HuntKind.ROAM, objective: "First", paths: [] },
          { callerKey: "duplicate", kind: HuntKind.ROAM, objective: "Second", paths: [] },
        ],
      }),
    ).rejects.toThrow(/caller keys must be unique/);
    await expect(
      addHunts(prisma, runScope, {
        hunts: [{ callerKey: "blank", kind: HuntKind.ROAM, objective: "   ", paths: [] }],
      }),
    ).rejects.toThrow();
    expect(await prisma.hunt.count({ where: { runId } })).toBe(0);

    const huntsInput = {
      hunts: [
        {
          callerKey: "file:src/parser.ts",
          kind: HuntKind.FILE,
          objective: "Audit parse-mode cache construction from the parser entry point.",
          paths: ["src/parser.ts"],
        },
        {
          callerKey: "threat:cross-mode-cache-confusion",
          kind: HuntKind.THREAT_MODEL,
          objective: "Test whether untrusted mode changes can cross the parser/cache seam.",
          paths: ["src/parser.ts", "src/cache.ts"],
        },
        {
          callerKey: "roam:v1",
          kind: HuntKind.ROAM,
          objective: "Explore unreviewed state-sharing boundaries.",
          paths: [],
        },
      ],
    };
    const hunts = await addHunts(prisma, runScope, huntsInput);
    const replay = await addHunts(prisma, runScope, huntsInput);
    expect(replay.map((hunt) => hunt.id)).toEqual(hunts.map((hunt) => hunt.id));
    await expect(
      addHunts(prisma, runScope, {
        hunts: [{ ...huntsInput.hunts[0], objective: "different payload under one caller key" }],
      }),
    ).rejects.toThrow(/idempotency conflict/);

    const fileLead = await addLead(prisma, { runId, itemId: hunts[0].id }, {
      callerKey: "parser-mode-missing-from-key",
      claim: "The parser cache key omits parse mode.",
      locations: ["src/parser.ts:42"],
      evidence: "The key is constructed from source text only before cache lookup.",
      impact: "A caller can receive an AST produced under a different mode.",
      validationPlan: "Parse the same source under two modes and compare cache hits.",
    });
    const threatLead = await addLead(prisma, { runId, itemId: hunts[1].id }, {
      callerKey: "cache-reuses-cross-mode-ast",
      claim: "The shared cache returns parser output without checking mode.",
      locations: ["src/cache.ts:17", "src/parser.ts:42"],
      evidence: "The cache lookup consumes the mode-free parser key unchanged.",
      attackerPreconditions: "The attacker can submit equivalent source under different modes.",
      impact: "Validation can run against an AST with the wrong grammar semantics.",
      validationPlan: "Prime one mode, request the second mode, and assert the AST grammar.",
    });
    const fileLeadReplay = await addLead(prisma, { runId, itemId: hunts[0].id }, {
      callerKey: "parser-mode-missing-from-key",
      claim: "The parser cache key omits parse mode.",
      locations: ["src/parser.ts:42"],
      evidence: "The key is constructed from source text only before cache lookup.",
      impact: "A caller can receive an AST produced under a different mode.",
      validationPlan: "Parse the same source under two modes and compare cache hits.",
    });
    expect(fileLeadReplay.id).toBe(fileLead.id);

    await finishHunt(prisma, { runId, itemId: hunts[0].id }, {
      result: HuntResult.BUG_FOUND,
      resultSummary: "Committed one parser-key Lead.",
    });
    await finishHunt(prisma, { runId, itemId: hunts[1].id }, {
      result: HuntResult.BUG_FOUND,
      resultSummary: "Committed one cross-file threat-model Lead.",
    });
    const durableLeadReplay = await addLead(prisma, { runId, itemId: hunts[0].id }, {
      callerKey: "parser-mode-missing-from-key",
      claim: "The parser cache key omits parse mode.",
      locations: ["src/parser.ts:42"],
      evidence: "The key is constructed from source text only before cache lookup.",
      impact: "A caller can receive an AST produced under a different mode.",
      validationPlan: "Parse the same source under two modes and compare cache hits.",
    });
    expect(durableLeadReplay.id).toBe(fileLead.id);
    await finishHunt(prisma, { runId, itemId: hunts[2].id }, {
      result: HuntResult.EXHAUSTED,
      resultSummary: "No additional concrete defect survived validation.",
    });
    const exhaustedReplay = await finishHunt(prisma, { runId, itemId: hunts[2].id }, {
      result: HuntResult.EXHAUSTED,
      resultSummary: "No additional concrete defect survived validation.",
    });
    expect(exhaustedReplay.result).toBe(HuntResult.EXHAUSTED);
    await expect(
      addLead(prisma, { runId, itemId: hunts[2].id }, {
        callerKey: "late-lead",
        claim: "This Lead must not be appended after Hunt completion.",
        locations: ["src/late.ts:1"],
        evidence: "The Hunt already has a final result.",
      }),
    ).rejects.toThrow(/already finished/);
    await expect(
      prisma.lead.create({
        data: {
          id: `late-${randomUUID()}`,
          huntId: hunts[2].id,
          claim: "Direct inserts must obey the same terminal Hunt invariant.",
          locations: ["src/late.ts:2"],
          evidence: "This write bypasses the connector guard.",
        },
      }),
    ).rejects.toThrow(/cannot append a Lead after its Hunt is finished/);

    const durableInput = await listHuntsAndLeads(prisma, runScope);
    expect(durableInput).toHaveLength(3);
    expect(durableInput.find((hunt) => hunt.kind === HuntKind.ROAM)?.result).toBe(HuntResult.EXHAUSTED);

    const findingAppend = {
      findings: [{
        callerKey: "parser-mode-cache-confusion",
        title: "Parser cache can return an AST for the wrong mode",
        rootCause: "Parser mode is omitted from a cache key reused across the parser/cache seam.",
        impact: "Untrusted requests can receive or validate the wrong AST semantics.",
        leadIds: [fileLead.id, threatLead.id],
      }],
    };
    await expect(
      createFindings(prisma, runScope, {
        findings: [{ ...findingAppend.findings[0], leadIds: [fileLead.id] }],
      }),
    ).rejects.toThrow(/partition every Lead/);
    expect(await prisma.finding.count({ where: { runId } })).toBe(0);
    expect(await prisma.lead.count({ where: { id: { in: [fileLead.id, threatLead.id] }, findingId: null } })).toBe(2);
    await expect(
      createFindings(prisma, runScope, {
        findings: [
          { ...findingAppend.findings[0], leadIds: [fileLead.id] },
          { ...findingAppend.findings[0], leadIds: [threatLead.id] },
        ],
      }),
    ).rejects.toThrow(/caller keys must be unique/);
    expect(await prisma.finding.count({ where: { runId } })).toBe(0);
    const [findings, concurrentReplay] = await Promise.all([
      createFindings(prisma, runScope, findingAppend),
      createFindings(prisma, runScope, findingAppend),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].leads).toHaveLength(2);
    expect(new Set(findings[0].leads.map((lead) => lead.hunt.kind))).toEqual(
      new Set([HuntKind.FILE, HuntKind.THREAT_MODEL]),
    );
    expect(concurrentReplay[0].id).toBe(findings[0].id);

    const [lateHunt] = await addHunts(prisma, runScope, {
      hunts: [{
        callerKey: "file:src/recovered.ts",
        kind: HuntKind.FILE,
        objective: "Audit a source file recovered after the first Finding partition.",
        paths: ["src/recovered.ts"],
      }],
    });
    const lateLeadA = await addLead(prisma, { runId, itemId: lateHunt.id }, {
      callerKey: "recovered-boundary-a",
      claim: "A late recovered Hunt found one side of a boundary defect.",
      locations: ["src/recovered.ts:10"],
      evidence: "The recovered source path reaches the unchecked boundary.",
    });
    const lateLeadB = await addLead(prisma, { runId, itemId: lateHunt.id }, {
      callerKey: "recovered-boundary-b",
      claim: "The same late recovered Hunt confirmed the other side of the boundary defect.",
      locations: ["src/recovered.ts:20"],
      evidence: "The second path confirms the same unchecked boundary.",
    });
    await finishHunt(prisma, { runId, itemId: lateHunt.id }, {
      result: HuntResult.BUG_FOUND,
      resultSummary: "Committed two Leads after the first Finding partition.",
    });
    const lateFinding = {
      callerKey: "recovered-boundary-confusion",
      title: "Recovered boundary can use the wrong state",
      rootCause: "A shared boundary omits the state discriminator.",
      impact: "A late request can consume state from the wrong boundary.",
      leadIds: [lateLeadA.id, lateLeadB.id],
    };
    await expect(
      createFindings(prisma, runScope, {
        findings: [{ ...lateFinding, leadIds: [lateLeadA.id] }],
      }),
    ).rejects.toThrow(/partition every Lead currently unassigned/);
    const lateFindings = await createFindings(prisma, runScope, { findings: [lateFinding] });
    expect(lateFindings).toHaveLength(1);
    expect(lateFindings[0].leads.map((lead) => lead.id).sort()).toEqual(
      [lateLeadA.id, lateLeadB.id].sort(),
    );
    const lateReplay = await createFindings(prisma, runScope, { findings: [lateFinding] });
    expect(lateReplay[0].id).toBe(lateFindings[0].id);
    expect(await prisma.finding.count({ where: { runId } })).toBe(2);

    await expect(
      createFindings(prisma, runScope, {
        findings: [
          { ...findingAppend.findings[0], leadIds: [fileLead.id] },
          {
            callerKey: "second-finding",
            title: "A different grouping",
            rootCause: "A different root cause",
            impact: "A different impact",
            leadIds: [threatLead.id],
          },
        ],
      }),
    ).rejects.toThrow(/idempotency conflict/);
    expect(await prisma.finding.count({ where: { runId } })).toBe(2);

    const findingScope = { runId, itemId: findings[0].id };
    await setTriage(prisma, findingScope, {
      verdict: FindingVerdict.CONFIRMED,
      assessment: "Both Leads reproduce one mode-confusion root cause.",
    });
    await setRereview(prisma, findingScope, {
      verdict: FindingVerdict.CONFIRMED,
      assessment: "Independent source review confirms the cache-key omission and impact.",
    });
    const triageReplay = await setTriage(prisma, findingScope, {
      verdict: FindingVerdict.CONFIRMED,
      assessment: "Both Leads reproduce one mode-confusion root cause.",
    });
    expect(triageReplay.triageVerdict).toBe(FindingVerdict.CONFIRMED);
    const finding = await getFinding(prisma, findingScope);
    expect(finding.triageVerdict).toBe(FindingVerdict.CONFIRMED);
    expect(finding.rereviewVerdict).toBe(FindingVerdict.CONFIRMED);
    expect(finding.disposition).toBe(FindingVerdict.CONFIRMED);
    expect(finding.leads).toHaveLength(2);

    await expect(
      setTriage(prisma, findingScope, {
        verdict: FindingVerdict.REJECTED,
        assessment: "A conflicting second write must fail.",
      }),
    ).rejects.toThrow(/already set/);
  });

  test("the app role cannot mutate canonical fields and the schema contains no JSON", async () => {
    const privilegeRunId = `privilege-${randomUUID()}`;
    const [hunt] = await addHunts(prisma, { runId: privilegeRunId }, {
      hunts: [{
        callerKey: "privilege-fixture",
        kind: HuntKind.ROAM,
        objective: "Provide an independent fixture for database privilege checks.",
        paths: [],
      }],
    });
    const finding = await prisma.finding.create({
      data: {
        id: `finding-${randomUUID()}`,
        runId: privilegeRunId,
        title: "Privilege fixture",
        rootCause: "The privilege test needs a self-contained Finding.",
        impact: "None; this row exists only for the database test.",
      },
    });
    await expect(
      prisma.hunt.update({ where: { id: hunt.id }, data: { objective: "forbidden mutation" } }),
    ).rejects.toThrow();
    await expect(
      prisma.hunt.create({
        data: {
          id: `forbidden-result-${randomUUID()}`,
          runId: privilegeRunId,
          kind: HuntKind.ROAM,
          objective: "Cannot insert a pre-finished Hunt.",
          paths: [],
          result: HuntResult.EXHAUSTED,
          resultSummary: "Forbidden direct result.",
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.lead.create({
        data: {
          id: `forbidden-finding-${randomUUID()}`,
          huntId: hunt.id,
          findingId: finding.id,
          claim: "Cannot insert a pre-assigned Lead.",
          locations: ["src/forbidden.ts:1"],
          evidence: "Forbidden direct membership.",
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.finding.create({
        data: {
          id: `forbidden-review-${randomUUID()}`,
          runId: privilegeRunId,
          title: "Cannot insert a pre-reviewed Finding",
          rootCause: "Forbidden direct review fields.",
          impact: "The write must fail.",
          triageVerdict: FindingVerdict.CONFIRMED,
          triageAssessment: "Forbidden direct review.",
        },
      }),
    ).rejects.toThrow();

    const jsonColumns = await prisma.$queryRaw<Array<{ column_name: string }>>`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name IN ('hunts', 'leads', 'findings')
        AND data_type IN ('json', 'jsonb')
    `;
    expect(jsonColumns).toEqual([]);
  });
});
