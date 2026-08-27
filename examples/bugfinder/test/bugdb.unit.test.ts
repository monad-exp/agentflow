import { FindingVerdict } from "@prisma/client";
import { describe, expect, test } from "vitest";

import { deriveDisposition } from "../src/bugdb.js";

describe("derived Finding disposition", () => {
  test.each([
    [FindingVerdict.CONFIRMED, FindingVerdict.CONFIRMED, FindingVerdict.CONFIRMED],
    [FindingVerdict.CONFIRMED, FindingVerdict.REJECTED, FindingVerdict.REJECTED],
    [FindingVerdict.CONFIRMED, FindingVerdict.INCONCLUSIVE, FindingVerdict.INCONCLUSIVE],
    [FindingVerdict.REJECTED, FindingVerdict.CONFIRMED, FindingVerdict.REJECTED],
    [FindingVerdict.REJECTED, FindingVerdict.REJECTED, FindingVerdict.REJECTED],
    [FindingVerdict.REJECTED, FindingVerdict.INCONCLUSIVE, FindingVerdict.REJECTED],
    [FindingVerdict.INCONCLUSIVE, FindingVerdict.CONFIRMED, FindingVerdict.INCONCLUSIVE],
    [FindingVerdict.INCONCLUSIVE, FindingVerdict.REJECTED, FindingVerdict.REJECTED],
    [FindingVerdict.INCONCLUSIVE, FindingVerdict.INCONCLUSIVE, FindingVerdict.INCONCLUSIVE],
  ])("derives %s and %s as %s", (triage, rereview, expected) => {
    expect(deriveDisposition(triage, rereview)).toBe(expected);
  });

});
