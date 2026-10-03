import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, it } from "vitest";
import { MINING_GUIDE_URL } from "./content";

it("ships the reviewed combined PDF byte-for-byte as a static website document", () => {
  const pdf = readFileSync(resolve(process.cwd(), "public", MINING_GUIDE_URL.slice(1)));
  expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
  expect(pdf.length).toBe(113118);
  expect(createHash("sha256").update(pdf).digest("hex")).toBe("2cbd8c06f7984ab5b09a4382ae383ac30237b55b9180f90376c84f8771f4c0da");
});
