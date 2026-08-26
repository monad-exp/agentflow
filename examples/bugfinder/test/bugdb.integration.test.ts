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
    await finishHunt(prisma, { runId, itemId: hunts[2].id }, {
      result: HuntResult.EXHAUSTED,
      resultSummary: "No additional concrete defect survived validation.",
    });
    const exhaustedReplay = await finishHunt(prisma, { runId, itemId: hunts[2].id }, {
      result: HuntResult.EXHAUSTED,
      resultSummary: "No additional concrete defect survived validation.",
    });
    expect(exhaustedReplay.result).toBe(HuntResult.EXHAUSTED);

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
    expect(finding.leads).toHaveLength(2);

    await expect(
      setTriage(prisma, findingScope, {
        verdict: FindingVerdict.REJECTED,
        assessment: "A conflicting second write must fail.",
      }),
    ).rejects.toThrow(/already set/);
  });

  test("the app role cannot mutate canonical fields and the schema contains no JSON", async () => {
    const hunts = await prisma.hunt.findMany({ where: { runId }, take: 1 });
    await expect(
      prisma.hunt.update({ where: { id: hunts[0].id }, data: { objective: "forbidden mutation" } }),
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
