// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// SPDX-FileCopyrightText: 2025 Cogni-DAO

/**
 * Module: `@scripts/ci/native-proof`
 * Purpose: Compare a finite reviewed native input inventory and exact trusted-main proof identity.
 * Scope: Git objects and bounded public GitHub metadata; never discovers or certifies dependencies.
 * Invariants: UNKNOWN_MEANS_FULL; BASE_OWNS_POLICY; MAIN_AND_MQ_REMAIN_FULL.
 * Side-effects: IO (bounded read-only Git subprocesses and GitHub metadata/log requests).
 * API: compareNativeInputs, validateNativeWitness, lookupNativeWitness; load only from the event base.
 * Links: scripts/ci/ci-proof-plan.mjs, task.5314
 * @internal
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

const sha = (value) =>
  typeof value === "string" && /^[a-f0-9]{40}$/.test(value);
const digest = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const hash = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const validPath = (value) =>
  typeof value === "string" &&
  /^[A-Za-z0-9_.@/-]+$/.test(value) &&
  !value.startsWith("/") &&
  value
    .split("/")
    .every((part) => part !== "" && part !== "." && part !== "..");

function requireThat(condition, message) {
  if (!condition) throw new Error(message);
}

function tree(commit, cwd) {
  requireThat(sha(commit), "unresolved-input-tree");
  const output = execFileSync(
    "git",
    ["ls-tree", "-rz", "--full-tree", commit],
    {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 10_000,
      maxBuffer: 16 * 1024 * 1024,
    }
  );
  const rows = output.split("\0").filter(Boolean);
  requireThat(rows.length <= 50_000, "input-tree-budget");
  return rows.map((line) => {
    const match = /^(\d{6}) (blob|commit) ([a-f0-9]{40})\t(.+)$/.exec(line);
    requireThat(match && validPath(match[4]), "unsupported-input-path");
    return { path: match[4], mode: match[1], kind: match[2], oid: match[3] };
  });
}

// These are deliberately conservative supersets. Dependency changes cannot
// silently become eligible by editing a pointer or adding a nearer config.
function discovered(path) {
  const basename = path.slice(path.lastIndexOf("/") + 1);
  return (
    basename === "package.json" ||
    /^tsconfig[^/]*\.json$/.test(basename) ||
    [
      "config/",
      "tests/ci-invariants/native/",
      "infra/catalog/",
      "infra/images/litellm/",
    ].some((prefix) => path.startsWith(prefix))
  );
}

function inventory(rows, policy) {
  const byPath = new Map(rows.map((row) => [row.path, row]));
  const required = new Set(policy.members.map((row) => row.path));
  for (const path of policy.absentSentinels) required.add(path);
  for (const row of rows) if (discovered(row.path)) required.add(row.path);
  return [...required].sort().map((path) => {
    const row = byPath.get(path);
    if (!row) return { path, absent: true };
    requireThat(
      row.kind === "blob" && ["100644", "100755"].includes(row.mode),
      "unsupported-input-mode"
    );
    return row;
  });
}

/** Compare objects against reviewed membership, at BOTH the actual base and tested tree. */
export function compareNativeInputs({
  base,
  tested,
  policy,
  cwd = process.cwd(),
}) {
  try {
    requireThat(policy?.version === 1, "unsupported-native-policy");
    requireThat(
      Array.isArray(policy.members) &&
        policy.members.length > 0 &&
        policy.members.length <= 2_000 &&
        Array.isArray(policy.absentSentinels) &&
        policy.absentSentinels.length <= 200,
      "malformed-native-policy"
    );
    const names = [
      ...policy.members.map((row) => row.path),
      ...policy.absentSentinels,
    ];
    requireThat(
      names.every(validPath) && new Set(names).size === names.length,
      "ambiguous-native-membership"
    );
    requireThat(
      policy.members.every(
        (row) =>
          row.kind === "blob" &&
          ["100644", "100755"].includes(row.mode) &&
          sha(row.oid)
      ),
      "malformed-reviewed-input"
    );
    const expected = [
      ...policy.members,
      ...policy.absentSentinels.map((path) => ({ path, absent: true })),
    ].sort((a, b) => a.path.localeCompare(b.path, "en"));
    // Sort paths identically to Git-independent membership sorting. Locale
    // collation is not part of a fingerprint.
    expected.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    const baseInventory = inventory(tree(base, cwd), policy);
    const testedInventory = inventory(tree(tested, cwd), policy);
    const fingerprint = hash(expected);
    requireThat(
      hash(baseInventory) === fingerprint,
      "base-input-membership-drift"
    );
    requireThat(
      hash(testedInventory) === fingerprint,
      "tested-input-membership-drift"
    );
    return { compatible: true, fingerprint };
  } catch (error) {
    return {
      compatible: false,
      reason: error.message.startsWith("Command failed:")
        ? "unresolved-input-objects"
        : error.message,
    };
  }
}

function validNativeCohort(value) {
  const dockerKeys = [
    "client",
    "clientApi",
    "server",
    "serverApi",
    "kernel",
    "os",
    "arch",
  ];
  return (
    value &&
    /^ubuntu[0-9]+$/.test(value.runnerImageOS ?? "") &&
    /^[0-9.]{1,80}$/.test(value.runnerImageVersion ?? "") &&
    value.runnerArch === "X64" &&
    /^22\.\d+\.\d+$/.test(value.nativeNodeVersion ?? "") &&
    /^9\.\d+\.\d+$/.test(value.nativePnpmVersion ?? "") &&
    dockerKeys.every(
      (key) =>
        typeof value.docker?.[key] === "string" &&
        /^[A-Za-z0-9_.+-]{1,100}$/.test(value.docker[key])
    ) &&
    value.docker.os === "linux" &&
    value.docker.arch === "amd64"
  );
}

/** Read the actual hosted runner/Docker cohort before any omission decision. */
export function readNativeCohort({
  nativeNodeVersion,
  nativePnpmVersion,
  env = process.env,
  command = execFileSync,
}) {
  try {
    requireThat(
      /^22\.\d+\.\d+$/.test(nativeNodeVersion) &&
        /^9\.\d+\.\d+$/.test(nativePnpmVersion),
      "unreviewed-native-tools"
    );
    requireThat(
      env.GITHUB_ACTIONS === "true" &&
        env.RUNNER_OS === "Linux" &&
        env.RUNNER_ARCH === "X64" &&
        /^ubuntu[0-9]+$/.test(env.ImageOS ?? "") &&
        /^[0-9.]{1,80}$/.test(env.ImageVersion ?? ""),
      "unavailable-hosted-cohort"
    );
    const version = JSON.parse(
      command("docker", ["version", "--format", "{{json .}}"], {
        encoding: "utf8",
        timeout: 5_000,
        maxBuffer: 65_536,
        stdio: ["ignore", "pipe", "pipe"],
      })
    );
    const fields = {
      client: version.Client?.Version,
      clientApi: version.Client?.ApiVersion,
      server: version.Server?.Version,
      serverApi: version.Server?.ApiVersion,
      kernel: version.Server?.KernelVersion,
      os: version.Server?.Os,
      arch: version.Server?.Arch,
    };
    requireThat(
      Object.values(fields).every(
        (v) => typeof v === "string" && /^[A-Za-z0-9_.+-]{1,100}$/.test(v)
      ) &&
        fields.os === "linux" &&
        fields.arch === "amd64",
      "unavailable-docker-cohort"
    );
    return {
      compatible: true,
      cohort: {
        runnerImageOS: env.ImageOS,
        runnerImageVersion: env.ImageVersion,
        runnerArch: env.RUNNER_ARCH,
        nativeNodeVersion,
        nativePnpmVersion,
        docker: fields,
      },
    };
  } catch {
    return { compatible: false, reason: "unavailable-current-native-cohort" };
  }
}

/** Validate an already bounded API run/job/receipt; success is TESTED evidence, never certification. */
export function validateNativeWitness({
  repository,
  base,
  policyDigest,
  fingerprint,
  workflowBlob,
  run,
  job,
  receipt,
  expectedTests,
  currentCohort,
  expectedImages,
}) {
  try {
    requireThat(
      repository === "cogni-dao/cogni" ||
        repository === "cogni-test-org/cogni-monorepo",
      "unsupported-witness-repository"
    );
    requireThat(
      sha(base) &&
        sha(workflowBlob) &&
        digest(policyDigest) &&
        digest(fingerprint),
      "malformed-witness-binding"
    );
    requireThat(
      Array.isArray(expectedTests) &&
        expectedTests.length === 6 &&
        new Set(expectedTests).size === 6,
      "malformed-six-test-contract"
    );
    requireThat(
      run?.repository?.full_name?.toLowerCase() === repository &&
        run.event === "push" &&
        run.head_branch === "main" &&
        run.head_sha === base &&
        run.status === "completed" &&
        run.conclusion === "success" &&
        Number.isSafeInteger(run.id) &&
        run.id > 0 &&
        Number.isSafeInteger(run.run_attempt) &&
        run.run_attempt > 0 &&
        run.path === ".github/workflows/ci.yaml",
      "untrusted-main-run"
    );
    requireThat(
      job?.name === "native" &&
        job.run_id === run.id &&
        job.run_attempt === run.run_attempt &&
        job.status === "completed" &&
        job.conclusion === "success",
      "untrusted-native-job"
    );
    requireThat(
      receipt?.version === 1 &&
        receipt.repository === repository &&
        receipt.sourceSha === base &&
        receipt.event === "push" &&
        receipt.ref === "refs/heads/main" &&
        receipt.runId === run.id &&
        receipt.runAttempt === run.run_attempt &&
        receipt.workflowBlob === workflowBlob &&
        receipt.policyDigest === policyDigest &&
        receipt.fingerprint === fingerprint &&
        receipt.install === "pnpm install --frozen-lockfile --ignore-scripts" &&
        Array.isArray(receipt.tests) &&
        receipt.tests.length === expectedTests.length,
      "incompatible-native-receipt"
    );
    requireThat(
      validNativeCohort(currentCohort) &&
        Array.isArray(expectedImages) &&
        expectedImages.length > 0 &&
        expectedImages.length <= 20 &&
        new Set(expectedImages.map((v) => v.declared)).size ===
          expectedImages.length &&
        expectedImages.every(
          (v) =>
            typeof v.declared === "string" &&
            /^[A-Za-z0-9_.:/@-]{1,250}$/.test(v.declared) &&
            typeof v.image === "string" &&
            /^[a-z0-9./_-]+@sha256:[a-f0-9]{64}$/.test(v.image) &&
            v.platform === "linux/amd64"
        ) &&
        hash(receipt.cohort) === hash(currentCohort) &&
        hash(receipt.images) === hash(expectedImages) &&
        receipt.nodeObserved === currentCohort.nativeNodeVersion &&
        receipt.pnpmObserved === currentCohort.nativePnpmVersion,
      "incompatible-runtime-install-image-cohort"
    );
    const names = receipt.tests.map((entry) => entry.name);
    requireThat(
      new Set(names).size === expectedTests.length &&
        expectedTests.every((name) => names.includes(name)) &&
        receipt.tests.every((entry) => entry.status === "passed"),
      "incomplete-native-controls"
    );
    return { valid: true, runId: run.id, runAttempt: run.run_attempt };
  } catch (error) {
    return { valid: false, reason: error.message };
  }
}

/**
 * Look up TESTED evidence only. This cannot qualify a policy or authorize an
 * exemption; callers still require the exact reviewed BASE closure and images.
 * GitHub's documented job-log endpoint redirects to plain text, not a ZIP:
 * https://docs.github.com/en/rest/actions/workflow-jobs#download-job-logs-for-a-workflow-run
 */
export async function lookupNativeWitness({
  repository,
  base,
  policyDigest,
  fingerprint,
  workflowBlob,
  expectedTests,
  currentCohort,
  expectedImages,
  token,
  fetchImpl = fetch,
}) {
  if (
    !["cogni-dao/cogni", "cogni-test-org/cogni-monorepo"].includes(
      repository
    ) ||
    !sha(base) ||
    !token
  )
    return { valid: false, reason: "unavailable-native-witness" };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15_000);
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  const prefix = `https://api.github.com/repos/${repository}/actions/`;
  async function bounded(response, limit) {
    requireThat(
      response.status === 200 && response.body,
      "unavailable-witness-response"
    );
    const reader = response.body.getReader();
    const parts = [];
    let size = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        requireThat(size <= limit, "witness-response-budget");
        parts.push(value);
      }
    } finally {
      await reader.cancel();
    }
    return Buffer.concat(parts).toString("utf8");
  }
  async function metadata(path) {
    const response = await fetchImpl(prefix + path, {
      headers,
      redirect: "error",
      signal: controller.signal,
    });
    return JSON.parse(await bounded(response, 512 * 1024));
  }
  try {
    const census = await metadata(
      `workflows/ci.yaml/runs?event=push&branch=main&head_sha=${base}&per_page=10`
    );
    requireThat(
      Number.isSafeInteger(census.total_count) &&
        census.total_count > 0 &&
        census.total_count <= 10 &&
        Array.isArray(census.workflow_runs) &&
        census.workflow_runs.length === census.total_count,
      "incomplete-witness-run-census"
    );
    const candidates = census.workflow_runs
      .filter(
        (run) => run.status === "completed" && run.conclusion === "success"
      )
      .sort((a, b) => b.id - a.id);
    requireThat(candidates.length > 0, "no-successful-main-witness");
    const run = candidates[0];
    requireThat(
      Number.isSafeInteger(run.id) &&
        run.id > 0 &&
        Number.isSafeInteger(run.run_attempt) &&
        run.run_attempt > 0,
      "malformed-main-run"
    );
    requireThat(
      run.repository?.full_name?.toLowerCase() === repository &&
        run.event === "push" &&
        run.head_branch === "main" &&
        run.head_sha === base &&
        run.path === ".github/workflows/ci.yaml",
      "untrusted-main-run"
    );
    const jobs = await metadata(
      `runs/${run.id}/attempts/${run.run_attempt}/jobs?per_page=100`
    );
    requireThat(
      Number.isSafeInteger(jobs.total_count) &&
        jobs.total_count > 0 &&
        jobs.total_count <= 100 &&
        Array.isArray(jobs.jobs) &&
        jobs.jobs.length === jobs.total_count,
      "incomplete-witness-job-census"
    );
    const native = jobs.jobs.filter((job) => job.name === "native");
    requireThat(
      native.length === 1 &&
        Number.isSafeInteger(native[0].id) &&
        native[0].id > 0,
      "ambiguous-native-job"
    );
    const job = native[0];
    requireThat(
      job.run_id === run.id &&
        job.run_attempt === run.run_attempt &&
        job.status === "completed" &&
        job.conclusion === "success",
      "untrusted-native-job"
    );
    const redirect = await fetchImpl(`${prefix}jobs/${job.id}/logs`, {
      headers,
      redirect: "manual",
      signal: controller.signal,
    });
    requireThat(redirect.status === 302, "unavailable-native-log");
    const location = new URL(redirect.headers.get("location"));
    await redirect.body?.cancel();
    requireThat(
      location.protocol === "https:" &&
        location.username === "" &&
        location.password === "" &&
        (location.hostname.endsWith(".blob.core.windows.net") ||
          location.hostname === "pipelines.actions.githubusercontent.com"),
      "unsupported-native-log-host"
    );
    // No Authorization header is forwarded to signed object storage.
    const raw = await bounded(
      await fetchImpl(location.href, {
        redirect: "error",
        signal: controller.signal,
      }),
      4 * 1024 * 1024
    );
    const marker = "NATIVE_PROOF_RECEIPT ";
    const lines = raw.split("\n").filter((line) => line.includes(marker));
    requireThat(
      lines.length === 1 && Buffer.byteLength(lines[0]) <= 16 * 1024,
      "ambiguous-native-receipt"
    );
    const receipt = JSON.parse(
      lines[0].slice(lines[0].indexOf(marker) + marker.length)
    );
    return validateNativeWitness({
      repository,
      base,
      policyDigest,
      fingerprint,
      workflowBlob,
      run,
      job,
      receipt,
      expectedTests,
      currentCohort,
      expectedImages,
    });
  } catch {
    // Never emit remote error bodies, signed URLs or an authentication value.
    return { valid: false, reason: "unavailable-compatible-native-witness" };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Validate the existing target fragment against its exact producing attempt.
 * Sibling matrix legs may still be running: this never waits for the manifest.
 * A failed/cancelled producer or any incomplete identity is RED, never an old-pin fallback.
 */
export function validateNativeImageProducer({
  repository,
  sourceSha,
  event,
  expectedTag,
  run,
  job,
  artifact,
  fragment,
}) {
  try {
    const imageName =
      repository === "cogni-dao/cogni"
        ? "ghcr.io/cogni-dao/cogni-template"
        : repository === "cogni-test-org/cogni-monorepo"
          ? "ghcr.io/cogni-test-org/cogni-template"
          : undefined;
    requireThat(
      imageName &&
        sha(sourceSha) &&
        ["pull_request", "push", "merge_group"].includes(event),
      "unsupported-image-source"
    );
    requireThat(
      typeof expectedTag === "string" &&
        expectedTag.startsWith(`${imageName}:litellm-`) &&
        /^[a-f0-9]+$/.test(expectedTag.slice(`${imageName}:litellm-`.length)),
      "invalid-source-image-tag"
    );
    requireThat(
      run?.repository?.full_name === repository &&
        run.head_repository?.full_name === repository &&
        run.event === event &&
        run.head_sha === sourceSha &&
        run.path === ".github/workflows/pr-build.yml" &&
        run.name === "PR Build" &&
        Number.isSafeInteger(run.id) &&
        run.id > 0 &&
        Number.isSafeInteger(run.run_attempt) &&
        run.run_attempt > 0 &&
        ["in_progress", "completed"].includes(run.status) &&
        (run.status !== "completed" || run.conclusion === "success"),
      "untrusted-image-producer-run"
    );
    requireThat(
      job?.name === "build (litellm)" &&
        Number.isSafeInteger(job.id) &&
        job.id > 0 &&
        job.run_id === run.id &&
        job.run_attempt === run.run_attempt &&
        job.head_sha === sourceSha &&
        job.status === "completed" &&
        job.conclusion === "success",
      "failed-image-target-producer"
    );
    const uploaded = Date.parse(artifact?.created_at);
    const started = Date.parse(job.started_at);
    const completed = Date.parse(job.completed_at);
    requireThat(
      Number.isSafeInteger(artifact?.id) &&
        artifact.id > 0 &&
        artifact.expired === false &&
        artifact.name === `pr-build-fragment-litellm-${sourceSha}` &&
        artifact.workflow_run?.id === run.id &&
        artifact.workflow_run.head_sha === sourceSha &&
        artifact.workflow_run.repository_id === run.repository.id &&
        artifact.workflow_run.head_repository_id === run.repository.id &&
        Number.isSafeInteger(run.repository.id) &&
        run.repository.id > 0 &&
        Number.isFinite(started) &&
        Number.isFinite(completed) &&
        started <= uploaded &&
        uploaded <= completed &&
        Number.isSafeInteger(artifact.size_in_bytes) &&
        artifact.size_in_bytes > 0 &&
        artifact.size_in_bytes <= 65_536 &&
        /^sha256:[a-f0-9]{64}$/.test(artifact.digest),
      "incompatible-image-fragment-artifact"
    );
    requireThat(
      fragment?.image_name === imageName &&
        fragment.image_tag === `sha-${sourceSha}` &&
        fragment.platform === "linux/amd64" &&
        Array.isArray(fragment.targets) &&
        fragment.targets.length === 1,
      "incompatible-image-fragment"
    );
    const target = fragment.targets[0];
    requireThat(
      target?.target === "litellm" &&
        target.tag === expectedTag &&
        typeof target.digest === "string" &&
        target.digest.startsWith(`${imageName}@sha256:`) &&
        /^[a-f0-9]{64}$/.test(
          target.digest.slice(`${imageName}@sha256:`.length)
        ),
      "missing-immutable-image-fragment"
    );
    return {
      valid: true,
      image: target.digest,
      producer: {
        repository,
        sourceSha,
        event,
        workflow: run.path,
        runId: run.id,
        runAttempt: run.run_attempt,
        target: "litellm",
        jobId: job.id,
        artifactId: artifact.id,
        archiveDigest: artifact.digest,
        platform: fragment.platform,
        fragmentDigest: hash(fragment),
      },
    };
  } catch {
    // Remote metadata and fragment fields are never echoed as diagnostics.
    return { valid: false, reason: "unavailable-exact-native-image-producer" };
  }
}

/** Bounded exact-head target preparation. Unknown is RED, never a historical pin fallback. */
export async function awaitNativeImageProducer({
  repository,
  sourceSha,
  event,
  expectedTag,
  token,
  fetchImpl = fetch,
  now = Date.now,
  sleep = (milliseconds) =>
    new Promise((resolve) => setTimeout(resolve, milliseconds)),
}) {
  if (
    !["cogni-dao/cogni", "cogni-test-org/cogni-monorepo"].includes(
      repository
    ) ||
    !sha(sourceSha) ||
    !["pull_request", "push", "merge_group"].includes(event) ||
    !token
  )
    return { valid: false, reason: "unavailable-exact-native-image-producer" };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 300_000);
  const started = now();
  const deadline = started + 300_000;
  const prefix = `https://api.github.com/repos/${repository}/actions/`;
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  async function bytes(response, limit) {
    requireThat(
      response.status === 200 && response.body,
      "unavailable-producer-response"
    );
    const reader = response.body.getReader();
    const parts = [];
    let size = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        requireThat(size <= limit, "producer-response-budget");
        parts.push(value);
      }
    } finally {
      await reader.cancel();
    }
    return Buffer.concat(parts);
  }
  async function metadata(path) {
    return JSON.parse(
      (
        await bytes(
          await fetchImpl(prefix + path, {
            headers,
            redirect: "error",
            signal: controller.signal,
          }),
          512 * 1024
        )
      ).toString("utf8")
    );
  }
  function complete(value, key, limit) {
    requireThat(
      Number.isSafeInteger(value.total_count) &&
        value.total_count >= 0 &&
        value.total_count <= limit &&
        Array.isArray(value[key]) &&
        value[key].length === value.total_count,
      "incomplete-producer-census"
    );
    return value[key];
  }
  try {
    let selected;
    for (let poll = 0; poll < 60 && now() < deadline; poll++) {
      const runs = complete(
        await metadata(
          `workflows/pr-build.yml/runs?event=${event}&head_sha=${sourceSha}&per_page=5`
        ),
        "workflow_runs",
        5
      );
      const run = runs.sort((a, b) => b.id - a.id)[0];
      if (run) {
        requireThat(
          run.repository?.full_name === repository &&
            run.head_repository?.full_name === repository &&
            run.head_sha === sourceSha &&
            run.event === event &&
            run.path === ".github/workflows/pr-build.yml" &&
            run.name === "PR Build" &&
            Number.isSafeInteger(run.id) &&
            run.id > 0 &&
            Number.isSafeInteger(run.run_attempt) &&
            run.run_attempt > 0,
          "untrusted-producer-run"
        );
        if (!selected) selected = { id: run.id, attempt: run.run_attempt };
        requireThat(
          run.id === selected.id && run.run_attempt === selected.attempt,
          "producer-attempt-changed"
        );
        requireThat(
          run.status !== "completed" || run.conclusion === "success",
          "failed-producer-run"
        );
        const jobs = complete(
          await metadata(
            `runs/${run.id}/attempts/${run.run_attempt}/jobs?per_page=100`
          ),
          "jobs",
          100
        );
        const targets = jobs.filter((job) => job.name === "build (litellm)");
        requireThat(targets.length <= 1, "ambiguous-producer-target");
        const job = targets[0];
        if (job?.status === "completed") {
          requireThat(job.conclusion === "success", "failed-producer-target");
          const artifacts = complete(
            await metadata(`runs/${run.id}/artifacts?per_page=100`),
            "artifacts",
            100
          );
          const matches = artifacts.filter(
            (artifact) =>
              artifact.name === `pr-build-fragment-litellm-${sourceSha}`
          );
          requireThat(
            matches.length === 1,
            "missing-or-ambiguous-target-fragment"
          );
          const artifact = matches[0];
          // Check server identities before requesting even a signed archive URL.
          // Full validation below is authoritative. Artifact URL is constructed
          // only from a bounded integer; no metadata-provided URL is followed.
          requireThat(
            Number.isSafeInteger(artifact.id) &&
              artifact.id > 0 &&
              artifact.workflow_run?.id === run.id &&
              artifact.workflow_run.head_sha === sourceSha &&
              /^sha256:[a-f0-9]{64}$/.test(artifact.digest),
            "untrusted-fragment-artifact"
          );
          const redirect = await fetchImpl(
            `${prefix}artifacts/${artifact.id}/zip`,
            { headers, redirect: "manual", signal: controller.signal }
          );
          requireThat(redirect.status === 302, "unavailable-fragment-archive");
          const location = new URL(redirect.headers.get("location"));
          await redirect.body?.cancel();
          requireThat(
            location.protocol === "https:" &&
              !location.username &&
              !location.password &&
              (location.hostname.endsWith(".blob.core.windows.net") ||
                location.hostname ===
                  "pipelines.actions.githubusercontent.com"),
            "untrusted-fragment-storage"
          );
          const archive = await bytes(
            await fetchImpl(location.href, {
              redirect: "error",
              signal: controller.signal,
            }),
            65_536
          );
          requireThat(
            `sha256:${createHash("sha256").update(archive).digest("hex")}` ===
              artifact.digest,
            "fragment-archive-digest-mismatch"
          );
          const fragment = JSON.parse(
            execFileSync(
              "python3",
              [
                "-c",
                `import io,json,sys,zipfile
z=zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read(65537)))
m=z.infolist()
assert len(m)==1 and m[0].filename=='build-fragment-litellm.json' and 0<m[0].file_size<=16384
assert not m[0].is_dir() and not m[0].flag_bits&1
sys.stdout.buffer.write(z.read(m[0]))
`,
              ],
              {
                input: archive,
                encoding: "utf8",
                timeout: 5_000,
                maxBuffer: 16_384,
                stdio: ["pipe", "pipe", "pipe"],
              }
            )
          );
          const result = validateNativeImageProducer({
            repository,
            sourceSha,
            event,
            expectedTag,
            run,
            job,
            artifact,
            fragment,
          });
          requireThat(result.valid, "incompatible-exact-target-fragment");
          return { ...result, waitMilliseconds: now() - started };
        }
        requireThat(
          run.status !== "completed",
          "missing-required-producer-target"
        );
      }
      await sleep(5_000);
    }
  } catch {
    // Never emit response bodies, signed URLs, fragment text or credentials.
  } finally {
    clearTimeout(timer);
  }
  return { valid: false, reason: "unavailable-exact-native-image-producer" };
}
