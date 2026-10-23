// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// SPDX-FileCopyrightText: 2025 Cogni-DAO
/**
 * Module: `@scripts/ci/native-preparation-experiment`
 * Purpose: Bound the matched TEST image experiment and observe unchanged startup phases.
 * Scope: Owned TEST source, public receipt and fixed phase labels. Does not select CI exemptions.
 * Invariants: One immutable image for both runs; source drift fails; all cleanup attempts settle.
 * Side-effects: IO (Git reads and fixed phase records), time (phase timestamps).
 * Links: task.5314, operator-ci-proof-lanes Checkpoint2 seq8
 * @internal
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

export const experimentImage =
  "ghcr.io/cogni-test-org/cogni-template@sha256:aaf189799c9d22211fa668dcbaca6a456706735135cf8911ce552a36ac61adf8";
// Complete nonexperiment tracked tree at TEST2290457557, a docs-only child of reviewed6f03.
export const expectedFrozenTree =
  "49320108608b3510a6f8bea9d09575e12d27724a698b16560401d7fa722694a3";
const source = "6f03d37d63c8b3cee619a3a024eaa3d8f6d7562b";
const declared = "ghcr.io/cogni-test-org/cogni-template:litellm-46f38f4447c2";
const experimentPaths = new Set([
  "scripts/ci/native-preparation-experiment.mjs",
  "scripts/ci/tests/native-preparation-experiment.test.mjs",
  "tests/ci-invariants/native/preparation-image-receipt.json",
  "tests/ci-invariants/native/litellm-readiness-recovery.spec.ts",
]);
export function frozenSourceIdentity(root) {
  const git = (...args) =>
    execFileSync("git", args, {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 8_388_608,
    });
  const tree = git("ls-tree", "-r", "--full-tree", "HEAD")
    .split("\n")
    .filter((line) => line && !experimentPaths.has(line.split("\t")[1]))
    .join("\n");
  // Full tracked tree identity is a conservative experiment freeze, not a safe-path certificate.
  const dirty = [
    ...git("diff", "HEAD", "--name-only").trim().split("\n"),
    ...git("ls-files", "--others", "--exclude-standard").trim().split("\n"),
  ].filter((name) => name && !experimentPaths.has(name));
  assert.equal(
    dirty.length,
    0,
    "native experiment source has unreviewed filesystem changes"
  );
  return createHash("sha256").update(tree).digest("hex");
}
export function verifyExperimentReceipt(receipt, repository, platform) {
  assert.equal(repository, "cogni-test-org/cogni-monorepo");
  assert.equal(platform, "linux");
  assert.equal(receipt.repository, repository);
  assert.equal(receipt.head_sha, source);
  assert.equal(receipt.workflow?.name, "PR Build");
  assert.equal(receipt.workflow?.run_id, "39938747904");
  assert.equal(receipt.workflow?.run_attempt, "1");
  assert.equal(receipt.platform, "linux/amd64");
  assert.equal(receipt.image_name, "ghcr.io/cogni-test-org/cogni-template");
  assert.equal(receipt.image_tag, `sha-${source}`);
  const targets = receipt.targets.filter(
    (target) => target.target === "litellm"
  );
  assert.equal(targets.length, 1);
  assert.deepEqual(targets[0], {
    target: "litellm",
    tag: declared,
    digest: experimentImage,
  });
  return { image: experimentImage, declared };
}
export function verifyPulledImage(image) {
  assert.equal(image.Os, "linux");
  assert.equal(image.Architecture, "amd64");
  assert.ok(
    image.RepoDigests?.includes(experimentImage),
    "pulled image differs from fixed TEST receipt"
  );
}
const phases = new Set([
  "network-start",
  "postgres-start",
  "dolt-start",
  "gateway-resolution",
  "gateway-first-up",
  "gateway-image-identity",
  "cleanup-watchdog",
  "cleanup-faults",
  "cleanup-compose",
  "cleanup-databases",
  "cleanup-network",
  "cleanup-directory",
]);
export function createPhaseObserver(write = (line) => console.info(line)) {
  const record = (phase, state) => {
    assert.ok(phases.has(phase), "unknown native preparation phase");
    write(
      JSON.stringify({
        proof: "native-preparation-phase",
        phase,
        state,
        time: new Date().toISOString(),
      })
    );
  };
  return {
    async run(phase, action) {
      record(phase, "begin");
      try {
        const result = await action();
        record(phase, "end");
        return result;
      } catch (error) {
        record(phase, "failure");
        throw error;
      }
    },
    sync(phase, action) {
      record(phase, "begin");
      try {
        const result = action();
        record(phase, "end");
        return result;
      } catch (error) {
        record(phase, "failure");
        throw error;
      }
    },
  };
}
export async function attemptCleanup(actions, primaryFailed) {
  const failed = [];
  for (const [phase, action] of actions) {
    try {
      await action();
    } catch {
      failed.push(phase);
    }
  }
  // Actions record only fixed phase failures; never serialize raw exceptions or credentials.
  if (failed.length && !primaryFailed)
    throw new Error(`native experiment cleanup failed: ${failed.join(",")}`);
  return failed;
}
