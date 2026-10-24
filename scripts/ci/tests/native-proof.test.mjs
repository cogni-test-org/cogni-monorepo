// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// SPDX-FileCopyrightText: 2025 Cogni-DAO

/**
 * Module: `@scripts/ci/tests/native-proof`
 * Purpose: Falsify finite input drift and forged trusted-main execution evidence.
 * Scope: Owned Git repositories and public metadata fixtures; no network or Docker.
 * Invariants: Base-only dependency drift and every incomplete witness fail closed.
 * Side-effects: IO (owned temporary repositories removed after each test).
 * Links: scripts/ci/native-proof.mjs, task.5314
 * @internal
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import {
  compareNativeInputs,
  lookupNativeWitness,
  readNativeCohort,
  validateNativeImageProducer,
  validateNativeWitness,
} from "../native-proof.mjs";

test("shell per-file timing preserves each actual child exit code", () => {
  const source = readFileSync("scripts/ci/run-shell-tests.sh", "utf8");
  const body = source.match(/run_one\(\) \{[\s\S]*?\n\}/)?.[0];
  assert.ok(body);
  const directory = mkdtempSync(join(tmpdir(), "shell-timing-"));
  try {
    writeFileSync(join(directory, "success.test.sh"), "exit 0\n");
    writeFileSync(join(directory, "failure.test.sh"), "exit 23\n");
    execFileSync("bash", [
      "-c",
      `${body}\nTESTS_DIR="$1"; tmpdir="$1"; run_one success.test.sh; run_one failure.test.sh`,
      "owned-timing-control",
      directory,
    ]);
    for (const [name, expected] of [
      ["success", "0"],
      ["failure", "23"],
    ]) {
      assert.equal(
        readFileSync(join(directory, `${name}.test.sh.rc`), "utf8").trim(),
        expected
      );
      assert.match(
        readFileSync(join(directory, `${name}.test.sh.seconds`), "utf8").trim(),
        /^\d+$/
      );
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function fixture(run) {
  const cwd = mkdtempSync(join(tmpdir(), "native-proof-"));
  const git = (...args) =>
    execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  const put = (path, contents = "owned\n") => {
    mkdirSync(dirname(join(cwd, path)), { recursive: true });
    writeFileSync(join(cwd, path), contents);
  };
  const commit = () => {
    git("add", ".");
    git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "owned fixture");
    return git("rev-parse", "HEAD");
  };
  try {
    git("init", "-q");
    git("config", "user.name", "Owned fixture");
    git("config", "user.email", "fixture@example.invalid");
    put("scripts/native-helper.sh");
    put("package.json", "{}\n");
    put("tsconfig.json", "{}\n");
    const base = commit();
    const members = [
      "package.json",
      "scripts/native-helper.sh",
      "tsconfig.json",
    ].map((path) => {
      const [mode, kind, oid] = git("ls-tree", base, "--", path).split(/\s+/);
      return { path, mode, kind, oid };
    });
    const policy = {
      version: 1,
      members,
      absentSentinels: ["tests/tsconfig.json"],
    };
    run({ cwd, git, put, commit, base, policy });
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
}

test("matching reviewed inputs survive an unrelated source edit", () =>
  fixture(({ cwd, put, commit, base, policy }) => {
    put("packages/owned/src/value.ts", "export const value = 2;\n");
    assert.equal(
      compareNativeInputs({ base, tested: commit(), policy, cwd }).compatible,
      true
    );
  }));

test("merged base-only helper drift remains FULL for a later app-only change", () =>
  fixture(({ cwd, put, commit, policy }) => {
    put("scripts/native-helper.sh", "cat packages/owned/src/value.ts\n");
    const base = commit();
    put("packages/owned/src/value.ts", "changed\n");
    assert.deepEqual(
      compareNativeInputs({ base, tested: commit(), policy, cwd }),
      { compatible: false, reason: "base-input-membership-drift" }
    );
  }));

test("new loader config, package membership and absent-to-present inputs invalidate", () => {
  for (const path of [
    "packages/new/tsconfig.json",
    "packages/new/package.json",
    "tests/tsconfig.json",
    "config/new.json",
    "tests/ci-invariants/native/new.spec.ts",
    "infra/images/litellm/new-helper.py",
    "infra/catalog/new.yaml",
  ])
    fixture(({ cwd, put, commit, base, policy }) => {
      put(path, "{}\n");
      assert.deepEqual(
        compareNativeInputs({ base, tested: commit(), policy, cwd }),
        { compatible: false, reason: "tested-input-membership-drift" },
        path
      );
    });
});

test("native helper modes and symlinks cannot retain a regular-file certificate", () => {
  fixture(({ cwd, commit, base, policy }) => {
    chmodSync(join(cwd, "scripts/native-helper.sh"), 0o755);
    assert.equal(
      compareNativeInputs({ base, tested: commit(), policy, cwd }).compatible,
      false
    );
  });
  fixture(({ cwd, commit, base, policy }) => {
    rmSync(join(cwd, "scripts/native-helper.sh"));
    symlinkSync("../package.json", join(cwd, "scripts/native-helper.sh"));
    assert.deepEqual(
      compareNativeInputs({ base, tested: commit(), policy, cwd }),
      { compatible: false, reason: "unsupported-input-mode" }
    );
  });
});

test("unknown policy/object/path states remain FULL", () =>
  fixture(({ cwd, base, policy }) => {
    for (const patch of [
      { version: 0 },
      { members: [] },
      { absentSentinels: ["../outside"] },
      { absentSentinels: ["package.json"] },
    ])
      assert.equal(
        compareNativeInputs({
          base,
          tested: base,
          policy: { ...policy, ...patch },
          cwd,
        }).compatible,
        false
      );
    assert.equal(
      compareNativeInputs({ base, tested: "f".repeat(40), policy, cwd })
        .compatible,
      false
    );
  }));

function witness() {
  const base = "a".repeat(40);
  const policyDigest = "b".repeat(64);
  const fingerprint = "c".repeat(64);
  const workflowBlob = "d".repeat(40);
  const expectedTests = Array.from(
    { length: 6 },
    (_, index) => `owned native control ${index}`
  );
  const repository = "cogni-dao/cogni";
  const run = {
    repository: { full_name: repository },
    event: "push",
    head_branch: "main",
    head_sha: base,
    status: "completed",
    conclusion: "success",
    id: 17,
    run_attempt: 2,
    path: ".github/workflows/ci.yaml",
  };
  const job = {
    id: 19,
    name: "native",
    run_id: run.id,
    run_attempt: run.run_attempt,
    status: "completed",
    conclusion: "success",
  };
  const currentCohort = {
    runnerImageOS: "ubuntu24",
    runnerImageVersion: "20261019.1.0",
    runnerArch: "X64",
    nativeNodeVersion: "22.22.0",
    nativePnpmVersion: "9.12.2",
    docker: {
      client: "28.0.4",
      clientApi: "1.48",
      server: "28.0.4",
      serverApi: "1.48",
      kernel: "6.11.0-1018-azure",
      os: "linux",
      arch: "amd64",
    },
  };
  const expectedImages = [
    {
      declared: "owned/native-fixture",
      image: `ghcr.io/owned/image@sha256:${"e".repeat(64)}`,
      platform: "linux/amd64",
    },
  ];
  const receipt = {
    cohort: structuredClone(currentCohort),
    images: structuredClone(expectedImages),
    nodeObserved: "22.22.0",
    pnpmObserved: "9.12.2",
    version: 1,
    repository,
    sourceSha: base,
    event: "push",
    ref: "refs/heads/main",
    runId: run.id,
    runAttempt: run.run_attempt,
    workflowBlob,
    policyDigest,
    fingerprint,
    install: "pnpm install --frozen-lockfile --ignore-scripts",
    tests: expectedTests.map((name) => ({ name, status: "passed" })),
  };
  return {
    repository,
    base,
    policyDigest,
    fingerprint,
    workflowBlob,
    expectedTests,
    currentCohort,
    expectedImages,
    run,
    job,
    receipt,
  };
}

test("only exact successful main run/attempt and all six controls form a witness", () => {
  assert.deepEqual(validateNativeWitness(witness()), {
    valid: true,
    runId: 17,
    runAttempt: 2,
  });
  for (const patch of [
    { event: "pull_request" },
    { event: "merge_group" },
    { event: "workflow_dispatch" },
    { head_branch: "protected-fixture" },
    { head_sha: "f".repeat(40) },
    { run_attempt: 3 },
    { conclusion: "cancelled" },
    { conclusion: "failure" },
    { status: "in_progress" },
    { repository: { full_name: "foreign/repo" } },
    { path: ".github/workflows/foreign.yml" },
  ]) {
    const value = witness();
    Object.assign(value.run, patch);
    assert.equal(
      validateNativeWitness(value).valid,
      false,
      JSON.stringify(patch)
    );
  }
  for (const patch of [
    { name: "foreign" },
    { run_id: 18 },
    { run_attempt: 1 },
    { conclusion: "cancelled" },
    { conclusion: "failure" },
  ]) {
    const value = witness();
    Object.assign(value.job, patch);
    assert.equal(validateNativeWitness(value).valid, false);
  }
  for (const patch of [
    { sourceSha: "f".repeat(40) },
    { ref: "refs/pull/17/merge" },
    { fingerprint: "f".repeat(64) },
    { policyDigest: "f".repeat(64) },
    { workflowBlob: "f".repeat(40) },
    { install: "pnpm install --frozen-lockfile" },
    { tests: [] },
    { cohort: {} },
    { images: [] },
    { nodeObserved: "22.23.0" },
    { pnpmObserved: "9.13.0" },
  ]) {
    const value = witness();
    Object.assign(value.receipt, patch);
    assert.equal(validateNativeWitness(value).valid, false);
  }
  for (const status of ["skipped", "failed", "pending", "todo"]) {
    const value = witness();
    value.receipt.tests[0].status = status;
    assert.equal(validateNativeWitness(value).valid, false);
  }
  const duplicate = witness();
  duplicate.receipt.tests[0].name = duplicate.receipt.tests[1].name;
  assert.equal(validateNativeWitness(duplicate).valid, false);
  for (const missing of ["run", "job", "receipt"]) {
    const value = witness();
    delete value[missing];
    assert.equal(validateNativeWitness(value).valid, false);
  }
});

test("bounded main witness lookup never forwards credentials or falls back to another identity", async () => {
  const value = witness();
  function responses(patch = {}) {
    return [
      new Response(
        JSON.stringify({
          total_count: 1,
          workflow_runs: [value.run],
          ...patch.census,
        })
      ),
      new Response(
        JSON.stringify({ total_count: 1, jobs: [value.job], ...patch.jobs })
      ),
      new Response(null, {
        status: 302,
        headers: {
          location:
            patch.location ??
            "https://owned.blob.core.windows.net/owned-log?public-fixture-signature",
        },
      }),
      new Response(
        patch.log ??
          `2026-10-23T00:00:00Z NATIVE_PROOF_RECEIPT ${JSON.stringify(value.receipt)}\n`
      ),
    ];
  }
  async function invoke(patch = {}) {
    const queue = responses(patch);
    const calls = [];
    const result = await lookupNativeWitness({
      ...value,
      token: "owned-fixture-token",
      fetchImpl: async (url, options) => {
        calls.push({ url, options });
        if (patch.networkFailure)
          throw new Error("PRIVATE-SENTINEL-DO-NOT-LOG");
        assert.ok(queue.length);
        return queue.shift();
      },
    });
    return { result, calls };
  }
  const positive = await invoke();
  assert.equal(positive.result.valid, true);
  assert.equal(positive.calls.length, 4);
  assert.ok(
    positive.calls
      .slice(0, 3)
      .every(
        ({ url, options }) =>
          url.startsWith(
            "https://api.github.com/repos/cogni-dao/cogni/actions/"
          ) && options.headers.Authorization === "Bearer owned-fixture-token"
      )
  );
  assert.equal(positive.calls[3].options.headers, undefined);
  assert.equal(positive.calls[3].options.redirect, "error");
  for (const patch of [
    { census: { total_count: 11 } },
    { census: { workflow_runs: [{ ...value.run, event: "pull_request" }] } },
    { census: { workflow_runs: [{ ...value.run, conclusion: "cancelled" }] } },
    { jobs: { total_count: 2 } },
    { jobs: { jobs: [{ ...value.job, conclusion: "failure" }] } },
    { location: "https://foreign.invalid/private" },
    { location: "https://user:password@owned.blob.core.windows.net/log" },
    { log: "no native receipt" },
    {
      log: `NATIVE_PROOF_RECEIPT ${JSON.stringify(value.receipt)}\nNATIVE_PROOF_RECEIPT ${JSON.stringify(value.receipt)}\n`,
    },
    { networkFailure: true },
  ]) {
    const negative = await invoke(patch);
    assert.deepEqual(negative.result, {
      valid: false,
      reason: "unavailable-compatible-native-witness",
    });
    assert.ok(!JSON.stringify(negative.result).includes("PRIVATE-SENTINEL"));
  }
  let requested = false;
  assert.equal(
    (
      await lookupNativeWitness({
        ...value,
        fetchImpl: () => {
          requested = true;
        },
      })
    ).valid,
    false
  );
  assert.equal(requested, false);
});

test("native uses only the exact successful target fragment and producing attempt", () => {
  const sourceSha = "a".repeat(40);
  const repository = "cogni-dao/cogni";
  const image = "ghcr.io/cogni-dao/cogni-template";
  const value = {
    repository,
    sourceSha,
    event: "pull_request",
    expectedTag: `${image}:litellm-123abc`,
    run: {
      repository: { full_name: repository, id: 123 },
      head_repository: { full_name: repository },
      name: "PR Build",
      event: "pull_request",
      head_sha: sourceSha,
      path: ".github/workflows/pr-build.yml",
      id: 456,
      run_attempt: 2,
      status: "in_progress",
      conclusion: null,
    },
    job: {
      id: 789,
      name: "build (litellm)",
      run_id: 456,
      run_attempt: 2,
      head_sha: sourceSha,
      status: "completed",
      conclusion: "success",
      started_at: "2026-10-23T00:00:10Z",
      completed_at: "2026-10-23T00:00:30Z",
    },
    artifact: {
      id: 900,
      expired: false,
      name: `pr-build-fragment-litellm-${sourceSha}`,
      created_at: "2026-10-23T00:00:25Z",
      size_in_bytes: 400,
      digest: `sha256:${"b".repeat(64)}`,
      workflow_run: {
        id: 456,
        head_sha: sourceSha,
        repository_id: 123,
        head_repository_id: 123,
      },
    },
    fragment: {
      image_name: image,
      image_tag: `sha-${sourceSha}`,
      platform: "linux/amd64",
      targets: [
        {
          target: "litellm",
          tag: `${image}:litellm-123abc`,
          digest: `${image}@sha256:${"c".repeat(64)}`,
        },
      ],
    },
  };
  const positive = validateNativeImageProducer(value);
  assert.equal(positive.valid, true);
  assert.equal(positive.image, value.fragment.targets[0].digest);
  assert.equal(positive.producer.runAttempt, 2);
  const mutate = (change) => {
    const copy = structuredClone(value);
    change(copy);
    return copy;
  };
  for (const change of [
    (v) => {
      v.repository = "foreign/repo";
    },
    (v) => {
      v.run.head_repository.full_name = "foreign/fork";
    },
    (v) => {
      v.run.event = "workflow_dispatch";
    },
    (v) => {
      v.run.head_sha = "d".repeat(40);
    },
    (v) => {
      v.run.path = ".github/workflows/foreign.yml";
    },
    (v) => {
      v.run.status = "completed";
      v.run.conclusion = "cancelled";
    },
    (v) => {
      v.job.run_attempt = 1;
    },
    (v) => {
      v.job.head_sha = "d".repeat(40);
    },
    (v) => {
      v.job.name = "build (operator)";
    },
    (v) => {
      v.job.conclusion = "failure";
    },
    (v) => {
      v.artifact.created_at = "2026-10-23T00:00:05Z";
    },
    (v) => {
      v.artifact.expired = true;
    },
    (v) => {
      v.artifact.workflow_run.head_repository_id = 999;
    },
    (v) => {
      v.artifact.workflow_run.head_sha = "d".repeat(40);
    },
    (v) => {
      v.artifact.digest = "";
    },
    (v) => {
      v.fragment.platform = "linux/arm64";
    },
    (v) => {
      v.fragment.image_tag = `sha-${"d".repeat(40)}`;
    },
    (v) => {
      v.fragment.targets = [];
    },
    (v) => {
      v.fragment.targets.push(v.fragment.targets[0]);
    },
    (v) => {
      v.fragment.targets[0].digest = "";
    },
    (v) => {
      v.fragment.targets[0].digest = `${image}:old-mutable-tag`;
    },
    (v) => {
      v.fragment.targets[0].tag = `${image}:litellm-old`;
    },
    (v) => {
      v.expectedTag = "ghcrXio/cogni-dao/cogni-template:litellm-123abc";
      v.fragment.targets[0].tag = v.expectedTag;
    },
  ])
    assert.deepEqual(validateNativeImageProducer(mutate(change)), {
      valid: false,
      reason: "unavailable-exact-native-image-producer",
    });
});

test("producer emits invocation digest A even when a mutable tag would resolve B", () => {
  const directory = mkdtempSync(join(tmpdir(), "build-output-race-"));
  const digestA = `sha256:${"a".repeat(64)}`;
  const digestB = `sha256:${"b".repeat(64)}`;
  try {
    for (const path of ["lib", "bin", "infra/catalog", "tmp"])
      mkdirSync(join(directory, path), { recursive: true });
    writeFileSync(
      join(directory, "build.sh"),
      readFileSync("scripts/ci/build-and-push-images.sh")
    );
    writeFileSync(
      join(directory, "lib/image-tags.sh"),
      `is_infra_target() { return 0; }\ninfra_image_tag() { printf '%s' 'ghcr.io/owned/fixture:litellm-abc'; }\n`
    );
    writeFileSync(
      join(directory, "infra/catalog/litellm.yaml"),
      "owned fixture\n"
    );
    writeFileSync(
      join(directory, "bin/yq"),
      `#!/usr/bin/env bash\ncase "$*" in *dockerfile*) echo Dockerfile;; *build_context*) echo .;; *type*) echo infra;; *) exit 91;; esac\n`
    );
    writeFileSync(
      join(directory, "bin/docker"),
      `#!/usr/bin/env bash
set -eu
if [ "$*" = 'buildx version' ]; then exit 0; fi
if [ "\${1:-}" = buildx ] && [ "\${2:-}" = imagetools ]; then
  echo MUTABLE_TAG_LOOKUP_CALLED >> "$OWNED_CALL_LOG"
  printf '%s\\n' '${digestB}'
  exit 0
fi
[ "\${1:-}" = buildx ] && [ "\${2:-}" = build ] || exit 92
shift 2
metadata=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = --metadata-file ]; then shift; metadata="$1"; fi
  shift
done
[ -n "$metadata" ] || exit 93
printf '%s' "$OWNED_METADATA" > "$metadata"
`
    );
    for (const name of ["yq", "docker"])
      chmodSync(join(directory, "bin", name), 0o755);
    const env = {
      ...process.env,
      PATH: `${join(directory, "bin")}:${process.env.PATH}`,
      TARGETS: "litellm",
      IMAGE_NAME: "ghcr.io/owned/fixture",
      IMAGE_TAG: `sha-${"c".repeat(40)}`,
      BUILD_SHA: "c".repeat(40),
      GITHUB_REPOSITORY: "owned/fixture",
      SHOULD_PUSH: "true",
      GHCR_TOKEN: "",
      GHCR_USERNAME: "",
      RUNNER_TEMP: join(directory, "tmp"),
      OUTPUT_FILE: join(directory, "fragment.json"),
      GITHUB_OUTPUT: "",
      GITHUB_STEP_SUMMARY: "",
      OWNED_CALL_LOG: join(directory, "calls.log"),
    };
    const invoke = (metadata, push = "true") => {
      rmSync(env.OUTPUT_FILE, { force: true });
      return execFileSync("bash", [join(directory, "build.sh")], {
        cwd: directory,
        env: { ...env, SHOULD_PUSH: push, OWNED_METADATA: metadata },
        stdio: ["ignore", "pipe", "pipe"],
      });
    };
    invoke(JSON.stringify({ "containerimage.digest": digestA }));
    assert.equal(
      JSON.parse(readFileSync(env.OUTPUT_FILE)).targets[0].digest,
      `ghcr.io/owned/fixture@${digestA}`
    );
    assert.equal(existsSync(env.OWNED_CALL_LOG), false);
    for (const metadata of [
      "{}",
      "not json",
      JSON.stringify({ "containerimage.digest": `${digestB}extra` }),
      `{"containerimage.digest":"${digestA}","containerimage.digest":"${digestB}"}`,
    ]) {
      assert.throws(() => invoke(metadata));
      assert.equal(existsSync(env.OUTPUT_FILE), false);
    }
    invoke("{}", "false");
    assert.equal(
      JSON.parse(readFileSync(env.OUTPUT_FILE)).targets[0].digest,
      ""
    );
    assert.deepEqual(readdirSync(join(directory, "tmp")), []);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("current actual runner/image/tool facts must match the witnessed cohort", () => {
  const env = {
    GITHUB_ACTIONS: "true",
    RUNNER_OS: "Linux",
    RUNNER_ARCH: "X64",
    ImageOS: "ubuntu24",
    ImageVersion: "20261019.1.0",
  };
  const version = {
    Client: { Version: "28.0.4", ApiVersion: "1.48" },
    Server: {
      Version: "28.0.4",
      ApiVersion: "1.48",
      KernelVersion: "6.11.0-1018-azure",
      Os: "linux",
      Arch: "amd64",
    },
  };
  const calls = [];
  const read = (patch = {}) =>
    readNativeCohort({
      nativeNodeVersion: "22.22.0",
      nativePnpmVersion: "9.12.2",
      env,
      command: (...args) => {
        calls.push(args);
        return JSON.stringify(version);
      },
      ...patch,
    });
  assert.equal(read().compatible, true);
  assert.deepEqual(calls[0].slice(0, 2), [
    "docker",
    ["version", "--format", "{{json .}}"],
  ]);
  for (const patch of [
    { nativeNodeVersion: "22" },
    { nativePnpmVersion: "latest" },
    { env: { ...env, ImageVersion: "" } },
    { env: { ...env, RUNNER_OS: "macOS" } },
    {
      command: () => {
        throw new Error("PRIVATE-SENTINEL");
      },
    },
    { command: () => "{}" },
  ])
    assert.deepEqual(read(patch), {
      compatible: false,
      reason: "unavailable-current-native-cohort",
    });
  for (const change of [
    (v) => {
      v.currentCohort.runnerImageVersion = "20261020.1.0";
    },
    (v) => {
      v.currentCohort.docker.server = "29.0.0";
    },
    (v) => {
      v.currentCohort = {};
    },
    (v) => {
      v.expectedImages[0].image = "ghcr.io/owned/image:mutable";
    },
    (v) => {
      v.receipt.images[0].image = `ghcr.io/owned/image@sha256:${"f".repeat(64)}`;
    },
  ]) {
    const value = witness();
    change(value);
    assert.equal(validateNativeWitness(value).valid, false);
  }
});
