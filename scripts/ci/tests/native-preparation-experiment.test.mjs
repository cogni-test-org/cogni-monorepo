// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// SPDX-FileCopyrightText: 2025 Cogni-DAO
/**
 * Module: `@scripts/ci/tests/native-preparation-experiment`
 * Purpose: Reject image/source drift and verify bounded markers plus complete cleanup attempts.
 * Scope: Public fixtures, fake actions and owned temporary Git trees. Does not run Docker or native faults.
 * Invariants: Failed setup stays failed; original error survives cleanup failures; unknown source changes abort.
 * Side-effects: IO (owned temporary files and Git child processes).
 * Links: task.5314, native-preparation-experiment.mjs
 * @internal
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  attemptCleanup,
  createPhaseObserver,
  experimentImage,
  frozenSourceIdentity,
  verifyExperimentReceipt,
  verifyPulledImage,
} from "../native-preparation-experiment.mjs";

const receipt = JSON.parse(
  readFileSync(
    new URL(
      "../../../tests/ci-invariants/native/preparation-image-receipt.json",
      import.meta.url
    ),
    "utf8"
  )
);
test("only the exact TEST source/run/digest/platform receipt can choose the experiment image", () => {
  assert.equal(
    verifyExperimentReceipt(receipt, "cogni-test-org/cogni-monorepo", "linux")
      .image,
    experimentImage
  );
  for (const patch of [
    { head_sha: "0".repeat(40) },
    { repository: "cogni-dao/cogni" },
    { platform: "linux/arm64" },
    { workflow: { ...receipt.workflow, run_attempt: "2" } },
    {
      targets: [
        ...receipt.targets,
        receipt.targets.find((target) => target.target === "litellm"),
      ],
    },
    {
      targets: receipt.targets.map((target) =>
        target.target === "litellm"
          ? {
              ...target,
              digest:
                "ghcr.io/cogni-dao/cogni-template@sha256:" + "a".repeat(64),
            }
          : target
      ),
    },
  ])
    assert.throws(() =>
      verifyExperimentReceipt(
        { ...receipt, ...patch },
        "cogni-test-org/cogni-monorepo",
        "linux"
      )
    );
  assert.throws(() =>
    verifyExperimentReceipt(receipt, "cogni-dao/cogni", "linux")
  );
  assert.throws(() =>
    verifyExperimentReceipt(receipt, "cogni-test-org/cogni-monorepo", "darwin")
  );
  verifyPulledImage({
    Os: "linux",
    Architecture: "amd64",
    RepoDigests: [experimentImage],
  });
  assert.throws(() =>
    verifyPulledImage({
      Os: "linux",
      Architecture: "arm64",
      RepoDigests: [experimentImage],
    })
  );
  assert.throws(() =>
    verifyPulledImage({ Os: "linux", Architecture: "amd64", RepoDigests: [] })
  );
});
test("fixed markers never serialize action results/errors and preserve the original failure", async () => {
  const lines = [];
  const phase = createPhaseObserver((line) => lines.push(line));
  const failure = new Error("private-value-must-not-be-serialized");
  assert.equal(
    await phase.run("postgres-start", async () => "private-result"),
    "private-result"
  );
  await assert.rejects(
    phase.run("dolt-start", async () => {
      throw failure;
    }),
    (error) => error === failure
  );
  assert.throws(() => phase.sync("untrusted-phase", () => 1));
  const values = lines.map(JSON.parse);
  assert.deepEqual(
    values.map(({ phase, state }) => [phase, state]),
    [
      ["postgres-start", "begin"],
      ["postgres-start", "end"],
      ["dolt-start", "begin"],
      ["dolt-start", "failure"],
    ]
  );
  for (const value of values)
    assert.deepEqual(Object.keys(value), ["proof", "phase", "state", "time"]);
  assert.ok(!lines.join("\n").includes("private"));
});
test("watchdog/database cleanup failures cannot suppress remaining cleanup or replace original failure", async () => {
  const attempted = [];
  const actions = [
    "cleanup-watchdog",
    "cleanup-faults",
    "cleanup-compose",
    "cleanup-databases",
    "cleanup-network",
    "cleanup-directory",
  ].map((phase) => [
    phase,
    async () => {
      attempted.push(phase);
      if (["cleanup-watchdog", "cleanup-databases"].includes(phase))
        throw new Error("private cleanup detail");
    },
  ]);
  await assert.rejects(
    attemptCleanup(actions, false),
    /cleanup-watchdog,cleanup-databases/
  );
  assert.equal(attempted.length, 6);
  attempted.length = 0;
  const original = new Error("original native failure");
  await assert.rejects(
    (async () => {
      try {
        throw original;
      } finally {
        await attemptCleanup(actions, true);
      }
    })(),
    (error) => error === original
  );
  assert.equal(attempted.length, 6);
});
test("complete nonexperiment source freeze detects helper/config membership, content and mode drift", () => {
  const root = mkdtempSync(path.join(tmpdir(), "native-preparation-source-"));
  const git = (...args) =>
    execFileSync("git", args, { cwd: root, stdio: "ignore" });
  try {
    git("init", "-q");
    git("config", "user.name", "fixture");
    git("config", "user.email", "fixture@example.invalid");
    writeFileSync(path.join(root, "producer.sh"), "original\n");
    git("add", ".");
    git("commit", "-qm", "baseline");
    const baseline = frozenSourceIdentity(root);
    writeFileSync(path.join(root, "producer.sh"), "new input\n");
    assert.throws(() => frozenSourceIdentity(root), /filesystem changes/);
    git("add", ".");
    git("commit", "-qm", "helper drift");
    assert.notEqual(frozenSourceIdentity(root), baseline);
    chmodSync(path.join(root, "producer.sh"), 0o755);
    assert.throws(() => frozenSourceIdentity(root), /filesystem changes/);
    git("add", ".");
    git("commit", "-qm", "mode drift");
    const mode = frozenSourceIdentity(root);
    writeFileSync(path.join(root, "new-config"), "new member\n");
    assert.throws(() => frozenSourceIdentity(root), /filesystem changes/);
    git("add", ".");
    git("commit", "-qm", "config membership");
    assert.notEqual(frozenSourceIdentity(root), mode);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
