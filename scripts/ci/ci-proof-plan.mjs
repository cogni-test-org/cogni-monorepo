// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// SPDX-FileCopyrightText: 2025 Cogni-DAO

/**
 * Module: `@scripts/ci/ci-proof-plan`
 * Purpose: Select only unchanged reviewed native proof with exact trusted-base execution evidence.
 * Scope: Git objects and bounded read-only native witness metadata; no deployment authority.
 * Invariants: UNKNOWN_MEANS_FULL; TRUSTED_EXEMPTION_POLICY; REQUIRED_PROOF_FAILS_CLOSED.
 * Side-effects: IO (Git reads, bounded witness reads, audited GitHub output/summary files).
 * API: plan|verify-unit|verify-component|verify-manifest; standalone stdlib module for exact event-base loading.
 * Policy: A v2 omission requires exact reviewed BASE inputs, immutable execution images, current cohort and full-main witness.
 * Unknown, old policy, forks, main and MQ execute full native proof. Missing witness cannot self-certify dependencies.
 * CI_NATIVE_SPLIT=true excludes native specs from run-unit-tests.sh only in CI's required split graph;
 * ordinary local discovery stays full. Plan inputs: CI_EVENT, EVENT_BASE_SHA, EVENT_HEAD_SHA,
 * EVENT_BASE_REF, POLICY_SHA. Outputs record exact identities, config blob and reason. Terminal verification
 * consumes named child *_RESULT and plan outputs from workflow needs.
 * Links: task.5314, .github/workflows/ci.yaml, .github/workflows/pr-build.yml
 * @internal
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  compareNativeInputs,
  nativeEligibility,
  trustedNativeBranch,
} from "./native-proof.mjs";

const env = process.env;
const policyPath = "scripts/ci/ci-proof-plan.mjs";
// Only reviewed BASE code and a compatible successful main witness may omit native.
// Missing/old policy and unknown input states retain executable full proof.
const isSha = (value) => /^[a-f0-9]{40}$/.test(value ?? "");
const git = (...args) =>
  execFileSync("git", args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 32 * 1024 * 1024,
  });
function requireThat(condition, message) {
  if (!condition) throw new Error(message);
}
function success(key) {
  requireThat(
    env[key] === "success",
    `${key} must succeed (got '${env[key] ?? ""}')`
  );
}

async function plan() {
  const base = env.EVENT_BASE_SHA ?? "";
  const head = env.EVENT_HEAD_SHA ?? "";
  const tested = env.EVENT_TESTED_SHA ?? "";
  const result = {
    plan_version: "2",
    native_required: "true",
    reason: "full-event",
    policy_sha: env.POLICY_SHA ?? "",
    base_sha: base,
    head_sha: head,
    tested_sha: tested,
    native_config: "unavailable",
    policy_digest: "",
    closure_digest: "",
    cohort_digest: "",
    image_digest: "",
    witness_run: "",
    witness_attempt: "",
  };
  if (env.CI_EVENT !== "pull_request") return result;
  if (env.EVENT_BASE_REF !== trustedNativeBranch)
    return { ...result, reason: "non-main-target" };
  if (env.EVENT_HEAD_REPO !== env.GITHUB_REPOSITORY)
    return { ...result, reason: "fork-full-native" };
  try {
    requireThat(
      isSha(base) && isSha(head) && isSha(tested) && env.POLICY_SHA === base,
      "unresolved-event-identity"
    );
    requireThat(
      git("show", `${base}:${policyPath}`) ===
        readFileSync(fileURLToPath(import.meta.url), "utf8"),
      "policy-bytes-mismatch"
    );
    requireThat(
      git("show", `${base}:scripts/ci/native-proof.mjs`) ===
        readFileSync(new URL("./native-proof.mjs", import.meta.url), "utf8"),
      "native-helper-bytes-mismatch"
    );
    const raw = readFileSync(
      new URL("./native-proof-policy.json", import.meta.url),
      "utf8"
    );
    requireThat(
      raw === git("show", `${base}:scripts/ci/native-proof-policy.json`),
      "native-policy-bytes-mismatch"
    );
    const policy = JSON.parse(raw);
    const decision = await nativeEligibility({
      repository: env.GITHUB_REPOSITORY,
      base,
      head,
      tested,
      baseRef: env.EVENT_BASE_REF,
      policy,
      token: env.GITHUB_TOKEN,
    });
    if (!decision.eligible) return { ...result, reason: decision.reason };
    return {
      ...result,
      native_required: "false",
      reason: decision.reason,
      policy_digest: decision.policyDigest,
      closure_digest: decision.fingerprint,
      cohort_digest: decision.cohortDigest,
      image_digest: decision.imageDigest,
      witness_run: String(decision.witnessRun),
      witness_attempt: String(decision.witnessAttempt),
    };
  } catch {
    return {
      ...result,
      reason: "missing-or-incompatible-trusted-native-policy",
    };
  }
}

function verifyUnit() {
  for (const key of ["CLASSIFIER_RESULT", "CORE_RESULT", "SHELL_RESULT"])
    success(key);
  requireThat(
    ["1", "2"].includes(env.PLAN_VERSION),
    "missing/unsupported plan version"
  );
  requireThat(
    ["true", "false"].includes(env.NATIVE_REQUIRED),
    "missing/malformed native decision"
  );
  requireThat(isSha(env.POLICY_SHA), "missing policy identity");
  requireThat(
    env.PLAN_BASE_SHA === env.EVENT_BASE_SHA &&
      env.PLAN_HEAD_SHA === env.EVENT_HEAD_SHA,
    "plan/event identity mismatch"
  );
  if (env.EVENT_BASE_SHA)
    requireThat(
      env.POLICY_SHA === env.EVENT_BASE_SHA,
      "policy/event-base mismatch"
    );
  if (env.PLAN_VERSION === "2")
    requireThat(
      env.PLAN_TESTED_SHA === env.EVENT_TESTED_SHA &&
        isSha(env.PLAN_TESTED_SHA),
      "plan/tested identity mismatch"
    );
  if (env.NATIVE_REQUIRED === "false" && env.PLAN_VERSION === "2") {
    for (const key of [
      "POLICY_DIGEST",
      "CLOSURE_DIGEST",
      "COHORT_DIGEST",
      "IMAGE_DIGEST",
    ])
      requireThat(
        /^[a-f0-9]{64}$/.test(env[key] ?? ""),
        "missing verified native compatibility"
      );
    requireThat(
      /^[1-9][0-9]{0,15}$/.test(env.WITNESS_RUN ?? "") &&
        /^[1-9][0-9]{0,5}$/.test(env.WITNESS_ATTEMPT ?? ""),
      "missing trusted native witness"
    );
    const raw = git(
      "show",
      `${env.EVENT_BASE_SHA}:scripts/ci/native-proof-policy.json`
    );
    requireThat(
      createHash("sha256").update(raw).digest("hex") === env.POLICY_DIGEST,
      "omission/base policy digest mismatch"
    );
    const policy = JSON.parse(raw);
    const compatibility = compareNativeInputs({
      base: env.EVENT_BASE_SHA,
      tested: env.EVENT_TESTED_SHA,
      policy,
    });
    requireThat(
      compatibility.compatible &&
        compatibility.fingerprint === env.CLOSURE_DIGEST,
      "omission/tested input mismatch"
    );
    requireThat(
      createHash("sha256")
        .update(JSON.stringify(policy.images))
        .digest("hex") === env.IMAGE_DIGEST,
      "omission/image binding mismatch"
    );
    requireThat(
      env.NATIVE_RESULT === "skipped",
      "verified omission/result mismatch"
    );
  } else {
    // Old v1 false/unknown decisions never omit current native proof.
    success("NATIVE_RESULT");
  }
}

function verifyManifest() {
  success("RESOLVE_RESULT");
  success("DETECT_RESULT");
  requireThat(
    isSha(env.SOURCE_SHA) && env.IMAGE_TAG === `sha-${env.SOURCE_SHA}`,
    "missing/incoherent source SHA and image tag"
  );
  const targets = JSON.parse(env.TARGETS_JSON ?? "null");
  requireThat(
    Array.isArray(targets) &&
      targets.every(
        (target) =>
          typeof target === "string" && /^[a-z0-9][a-z0-9-]*$/.test(target)
      ) &&
      new Set(targets).size === targets.length,
    "malformed target plan"
  );
  requireThat(
    ["true", "false"].includes(env.HAS_TARGETS) &&
      (env.HAS_TARGETS === "true") === targets.length > 0,
    "incoherent target plan"
  );
  if (env.HAS_TARGETS === "true") success("BUILD_RESULT");
  else
    requireThat(
      ["success", "skipped"].includes(env.BUILD_RESULT),
      "no-target build failed/cancelled"
    );
}

try {
  switch (process.argv[2]) {
    case "plan": {
      const result = await plan();
      console.log(JSON.stringify(result));
      if (env.GITHUB_OUTPUT)
        appendFileSync(
          env.GITHUB_OUTPUT,
          Object.entries(result)
            .map(([key, value]) => `${key}=${value}\n`)
            .join("")
        );
      if (env.GITHUB_STEP_SUMMARY)
        appendFileSync(
          env.GITHUB_STEP_SUMMARY,
          `### Native proof plan\n\n${Object.entries(result)
            .map(([key, value]) => `- ${key}: \`${value}\``)
            .join("\n")}\n`
        );
      break;
    }
    case "verify-unit":
      verifyUnit();
      break;
    case "verify-component":
      success("COMPONENT_RESULT");
      success("MIGRATOR_RESULT");
      break;
    case "verify-manifest":
      verifyManifest();
      break;
    default:
      throw new Error(
        "expected plan, verify-unit, verify-component or verify-manifest"
      );
  }
} catch (error) {
  console.error(`::error::${error.message}`);
  process.exitCode = 1;
}
