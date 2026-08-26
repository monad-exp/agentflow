import { createHash } from "node:crypto";

import {
  FindingVerdict,
  HuntKind,
  HuntResult,
  Prisma,
  PrismaClient,
} from "@prisma/client";
import { z } from "zod";

export type BugDbScope = {
  runId: string;
  itemId?: string;
};

const callerKey = z.string().min(1).max(256);

export const addHuntsInput = z.object({
  hunts: z.array(
    z.object({
      callerKey,
      kind: z.nativeEnum(HuntKind),
      objective: z.string().min(1),
      paths: z.array(z.string().min(1)),
    }),
  ),
});
export const getHuntInput = z.object({});
export const addLeadInput = z.object({
  callerKey,
  claim: z.string().min(1),
  locations: z.array(z.string().min(1)).min(1),
  evidence: z.string().min(1),
  attackerPreconditions: z.string().min(1).optional(),
  impact: z.string().min(1).optional(),
  validationPlan: z.string().min(1).optional(),
});
export const finishHuntInput = z.object({
  result: z.nativeEnum(HuntResult),
  resultSummary: z.string().min(1),
});
export const listHuntsAndLeadsInput = z.object({});
export const createFindingsInput = z.object({
  findings: z.array(
    z.object({
      callerKey,
      title: z.string().min(1),
      rootCause: z.string().min(1),
      impact: z.string().min(1),
      leadIds: z.array(z.string().min(1)).min(1),
    }),
  ),
});
export const getFindingInput = z.object({});
export const setReviewInput = z.object({
  verdict: z.nativeEnum(FindingVerdict),
  assessment: z.string().min(1),
});

function stableId(kind: "hunt" | "lead" | "finding", scope: string, key: string): string {
  const digest = createHash("sha256").update(scope).update("\0").update(key).digest("hex");
  return `${kind}_${digest}`;
}

function sameStrings(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function requireItem(scope: BugDbScope, kind: "Hunt" | "Finding"): string {
  if (!scope.itemId) throw new Error(`${kind} scope was not injected by AgentFlow`);
  return scope.itemId;
}

function isUniqueConflict(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002";
}

type HuntAppend = z.infer<typeof addHuntsInput>["hunts"][number];

function assertSameHunt(existing: {
  id: string;
  runId: string;
  kind: HuntKind;
  objective: string;
  paths: string[];
}, runId: string, expected: HuntAppend): void {
  if (
    existing.runId !== runId ||
    existing.kind !== expected.kind ||
    existing.objective !== expected.objective ||
    !sameStrings(existing.paths, expected.paths)
  ) {
    throw new Error(`idempotency conflict for Hunt ${existing.id}`);
  }
}

export async function addHunts(
  prisma: PrismaClient,
  scope: BugDbScope,
  raw: z.input<typeof addHuntsInput>,
) {
  const input = addHuntsInput.parse(raw);
  const ids = input.hunts.map((hunt) => stableId("hunt", scope.runId, hunt.callerKey));
  try {
    await prisma.$transaction(async (tx) => {
      for (const [index, hunt] of input.hunts.entries()) {
        if (hunt.kind === HuntKind.FILE && hunt.paths.length !== 1) {
          throw new Error("FILE Hunts require exactly one anchor path");
        }
        const existing = await tx.hunt.findUnique({ where: { id: ids[index] } });
        if (existing) {
          assertSameHunt(existing, scope.runId, hunt);
          continue;
        }
        await tx.hunt.create({
          data: {
            id: ids[index],
            runId: scope.runId,
            kind: hunt.kind,
            objective: hunt.objective,
            paths: hunt.paths,
          },
        });
      }
    });
  } catch (error) {
    if (!isUniqueConflict(error)) throw error;
  }
  const rows = await prisma.hunt.findMany({ where: { id: { in: ids } } });
  if (rows.length !== ids.length) throw new Error("concurrent Hunt append did not commit the full request");
  for (const [index, id] of ids.entries()) {
    const row = rows.find((item) => item.id === id);
    if (!row) throw new Error(`Hunt ${id} is missing after append`);
    assertSameHunt(row, scope.runId, input.hunts[index]);
  }
  return ids.map((id) => rows.find((row) => row.id === id)!);
}

export async function getHunt(prisma: PrismaClient, scope: BugDbScope) {
  const id = requireItem(scope, "Hunt");
  const hunt = await prisma.hunt.findFirst({
    where: { id, runId: scope.runId },
    include: { leads: { orderBy: { createdAt: "asc" } } },
  });
  if (!hunt) throw new Error("injected Hunt does not belong to this run");
  return hunt;
}

export async function addLead(
  prisma: PrismaClient,
  scope: BugDbScope,
  raw: z.input<typeof addLeadInput>,
) {
  const hunt = await getHunt(prisma, scope);
  const input = addLeadInput.parse(raw);
  const id = stableId("lead", hunt.id, input.callerKey);
  try {
    return await prisma.lead.create({
      data: {
        id,
        huntId: hunt.id,
        claim: input.claim,
        locations: input.locations,
        evidence: input.evidence,
        attackerPreconditions: input.attackerPreconditions,
        impact: input.impact,
        validationPlan: input.validationPlan,
      },
    });
  } catch (error) {
    if (!isUniqueConflict(error)) throw error;
    const existing = await prisma.lead.findUnique({ where: { id } });
    if (
      !existing ||
      existing.huntId !== hunt.id ||
      existing.claim !== input.claim ||
      !sameStrings(existing.locations, input.locations) ||
      existing.evidence !== input.evidence ||
      existing.attackerPreconditions !== (input.attackerPreconditions ?? null) ||
      existing.impact !== (input.impact ?? null) ||
      existing.validationPlan !== (input.validationPlan ?? null)
    ) {
      throw new Error(`idempotency conflict for Lead ${id}`);
    }
    return existing;
  }
}

export async function finishHunt(
  prisma: PrismaClient,
  scope: BugDbScope,
  raw: z.input<typeof finishHuntInput>,
) {
  const hunt = await getHunt(prisma, scope);
  const input = finishHuntInput.parse(raw);
  if (hunt.result !== null) {
    if (hunt.result === input.result && hunt.resultSummary === input.resultSummary) return hunt;
    throw new Error(`Hunt ${hunt.id} result is already set`);
  }
  if (input.result === HuntResult.BUG_FOUND && hunt.leads.length === 0) {
    throw new Error("BUG_FOUND requires at least one committed Lead");
  }
  const updated = await prisma.hunt.updateMany({
    where: { id: hunt.id, runId: scope.runId, result: null },
    data: { result: input.result, resultSummary: input.resultSummary },
  });
  const current = await getHunt(prisma, scope);
  if (updated.count === 0 && (current.result !== input.result || current.resultSummary !== input.resultSummary)) {
    throw new Error(`Hunt ${hunt.id} result was set concurrently to a different value`);
  }
  return current;
}

export async function listHuntsAndLeads(prisma: PrismaClient, scope: BugDbScope) {
  return prisma.hunt.findMany({
    where: { runId: scope.runId },
    include: { leads: { orderBy: { createdAt: "asc" } } },
    orderBy: [{ kind: "asc" }, { createdAt: "asc" }],
  });
}

type FindingAppend = z.infer<typeof createFindingsInput>["findings"][number];

function assertSameFinding(existing: {
  id: string;
  runId: string;
  title: string;
  rootCause: string;
  impact: string;
}, runId: string, expected: FindingAppend): void {
  if (
    existing.runId !== runId ||
    existing.title !== expected.title ||
    existing.rootCause !== expected.rootCause ||
    existing.impact !== expected.impact
  ) {
    throw new Error(`idempotency conflict for Finding ${existing.id}`);
  }
}

export async function createFindings(
  prisma: PrismaClient,
  scope: BugDbScope,
  raw: z.input<typeof createFindingsInput>,
) {
  const input = createFindingsInput.parse(raw);
  const ids = input.findings.map((finding) => stableId("finding", scope.runId, finding.callerKey));
  const allLeadIds = input.findings.flatMap((finding) => finding.leadIds);
  if (new Set(allLeadIds).size !== allLeadIds.length) {
    throw new Error("a Lead may appear in only one Finding append");
  }
  const commit = async () => prisma.$transaction(async (tx) => {
    const leads = await tx.lead.findMany({
      where: { id: { in: allLeadIds }, hunt: { runId: scope.runId } },
    });
    if (leads.length !== allLeadIds.length) {
      throw new Error("every Lead must belong to this AgentFlow run");
    }
    for (const [index, finding] of input.findings.entries()) {
      const id = ids[index];
      const existing = await tx.finding.findUnique({ where: { id } });
      if (existing) assertSameFinding(existing, scope.runId, finding);
      else {
        await tx.finding.create({
          data: {
            id,
            runId: scope.runId,
            title: finding.title,
            rootCause: finding.rootCause,
            impact: finding.impact,
          },
        });
      }
      const findingLeads = leads.filter((lead) => finding.leadIds.includes(lead.id));
      if (findingLeads.some((lead) => lead.findingId !== null && lead.findingId !== id)) {
        throw new Error("a Lead is already assigned to another Finding");
      }
      await tx.lead.updateMany({
        where: { id: { in: finding.leadIds }, findingId: null },
        data: { findingId: id },
      });
    }
  });
  try {
    await commit();
  } catch (error) {
    if (!isUniqueConflict(error)) throw error;
  }
  const findings = await prisma.finding.findMany({
    where: { id: { in: ids }, runId: scope.runId },
    include: { leads: { include: { hunt: true } } },
  });
  if (findings.length !== ids.length) throw new Error("Finding append did not commit completely");
  for (const [index, id] of ids.entries()) {
    const finding = findings.find((item) => item.id === id);
    if (!finding) throw new Error(`Finding ${id} is missing after append`);
    assertSameFinding(finding, scope.runId, input.findings[index]);
    if (!sameStrings(finding.leads.map((lead) => lead.id).sort(), [...input.findings[index].leadIds].sort())) {
      throw new Error(`Finding ${id} has a different Lead membership`);
    }
  }
  return ids.map((id) => findings.find((finding) => finding.id === id)!);
}

export async function getFinding(prisma: PrismaClient, scope: BugDbScope) {
  const id = requireItem(scope, "Finding");
  const finding = await prisma.finding.findFirst({
    where: { id, runId: scope.runId },
    include: { leads: { include: { hunt: true }, orderBy: { createdAt: "asc" } } },
  });
  if (!finding) throw new Error("injected Finding does not belong to this run");
  return finding;
}

async function setReview(
  prisma: PrismaClient,
  scope: BugDbScope,
  raw: z.input<typeof setReviewInput>,
  kind: "triage" | "rereview",
) {
  const finding = await getFinding(prisma, scope);
  const input = setReviewInput.parse(raw);
  const verdict = kind === "triage" ? finding.triageVerdict : finding.rereviewVerdict;
  const assessment = kind === "triage" ? finding.triageAssessment : finding.rereviewAssessment;
  if (verdict !== null) {
    if (verdict === input.verdict && assessment === input.assessment) return finding;
    throw new Error(`${kind} review is already set`);
  }
  const data = kind === "triage"
    ? { triageVerdict: input.verdict, triageAssessment: input.assessment }
    : { rereviewVerdict: input.verdict, rereviewAssessment: input.assessment };
  const where = kind === "triage"
    ? { id: finding.id, runId: scope.runId, triageVerdict: null }
    : { id: finding.id, runId: scope.runId, rereviewVerdict: null };
  const updated = await prisma.finding.updateMany({ where, data });
  const current = await getFinding(prisma, scope);
  const currentVerdict = kind === "triage" ? current.triageVerdict : current.rereviewVerdict;
  const currentAssessment = kind === "triage" ? current.triageAssessment : current.rereviewAssessment;
  if (updated.count === 0 && (currentVerdict !== input.verdict || currentAssessment !== input.assessment)) {
    throw new Error(`${kind} review was set concurrently to a different value`);
  }
  return current;
}

export function setTriage(
  prisma: PrismaClient,
  scope: BugDbScope,
  raw: z.input<typeof setReviewInput>,
) {
  return setReview(prisma, scope, raw, "triage");
}

export function setRereview(
  prisma: PrismaClient,
  scope: BugDbScope,
  raw: z.input<typeof setReviewInput>,
) {
  return setReview(prisma, scope, raw, "rereview");
}
