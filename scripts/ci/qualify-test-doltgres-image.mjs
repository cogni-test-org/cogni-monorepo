// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// SPDX-FileCopyrightText: 2025 Cogni-DAO
/**
 * Module: `@scripts/ci/qualify-test-doltgres-image`
 * Purpose: Qualify the existing TEST-owned same-binary Doltgres mirror before consumption.
 * Scope: Fixed TEST repository CI and immutable reviewed images; does not change registry policy or runtime.
 * Invariants: Exact source, platform, base layers, binary recipe and config; canonical pin unchanged.
 * Side-effects: IO, process.env
 * Links: infra/images/doltgres/Dockerfile, subtask.5021, task.5314
 * @internal
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

export const image =
  "ghcr.io/cogni-test-org/cogni-template@sha256:96889c2c105f6bc3dba63d06374662e2e32c661d36498dbc9188dd59016071f8";
export const runtimeBase =
  "dolthub/doltgresql:0.57.3@sha256:1eccbe3a4a65564b62b4bd90ed8265c2e9452687dfac47061bf0c7212bd8ae31";
const producer = "d0678db88ded712e60c2ffa472bc9be1fff45900";

export function verifyLoadedFixture(base, mirror) {
  for (const inspected of [base, mirror]) {
    assert.equal(inspected.Os, "linux");
    assert.equal(inspected.Architecture, "amd64");
    assert.match(inspected.Id, /^sha256:[a-f0-9]{64}$/);
    assert.equal(inspected.RootFS.Type, "layers");
    assert(
      inspected.RootFS.Layers.every((layer) =>
        /^sha256:[a-f0-9]{64}$/.test(layer)
      )
    );
    for (const field of ["Variant", "OsVersion"]) {
      assert(
        inspected[field] === undefined || typeof inspected[field] === "string",
        "Unknown image platform field type"
      );
    }
  }
  // Only absent and empty strings are equivalent. Declared platform values
  // remain binding even though Docker exposes them outside image.Config.
  assert.equal(
    mirror.Variant === undefined ? "" : mirror.Variant,
    base.Variant === undefined ? "" : base.Variant
  );
  assert.equal(
    mirror.OsVersion === undefined ? "" : mirror.OsVersion,
    base.OsVersion === undefined ? "" : base.OsVersion
  );
  assert.equal(mirror.RootFS.Layers.length, base.RootFS.Layers.length + 1);
  assert.deepEqual(mirror.RootFS.Layers.slice(0, -1), base.RootFS.Layers);
  const { Labels: baseLabels, ...baseConfig } = base.Config;
  const { Labels: mirrorLabels, ...mirrorConfig } = mirror.Config;
  assert(
    isDeepStrictEqual(mirrorConfig, baseConfig),
    "TEST fixture runtime configuration mismatch"
  );
  assert.match(
    mirrorLabels["org.opencontainers.image.created"],
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/
  );
  assert(
    isDeepStrictEqual(mirrorLabels, {
      ...baseLabels,
      "org.opencontainers.image.source":
        "https://github.com/cogni-test-org/cogni-monorepo",
      "org.opencontainers.image.revision": producer,
      "org.opencontainers.image.created":
        mirrorLabels["org.opencontainers.image.created"],
    }),
    "TEST fixture producer labels mismatch"
  );
  return {
    fixtureOnly: true,
    image,
    runtimeBase,
    producer,
    imageId: mirror.Id,
    baseImageId: base.Id,
    os: mirror.Os,
    architecture: mirror.Architecture,
    variant: mirror.Variant === undefined ? "" : mirror.Variant,
    osVersion: mirror.OsVersion === undefined ? "" : mirror.OsVersion,
    baseLayers: base.RootFS.Layers,
    replacementLayer: mirror.RootFS.Layers.at(-1),
    executionConfigSha256: createHash("sha256")
      .update(JSON.stringify(baseConfig))
      .digest("hex"),
    expectedBinarySha256:
      "8ecc5f8a764fe5a70ca3cac76452dc17377bc446136891478c7ee19a5a9eb2b9",
    limitation:
      "OCI index and producer labels/attestations differ; actual binary assertion remains in current migrator suite.",
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  let phase = "admission";
  try {
    assert.equal(
      process.env.GITHUB_REPOSITORY,
      "cogni-test-org/cogni-monorepo"
    );
    const fixedBaseRef = "test/task5314-native-current-6884";
    const shaPattern = /^[a-f0-9]{40}$/;
    const event = JSON.parse(
      readFileSync(process.env.GITHUB_EVENT_PATH, "utf8")
    );
    assert.equal(event.repository.full_name, "cogni-test-org/cogni-monorepo");
    if (process.env.GITHUB_EVENT_NAME === "push") {
      assert.equal(process.env.GITHUB_REF, `refs/heads/${fixedBaseRef}`);
      assert.equal(event.ref, process.env.GITHUB_REF);
      assert.match(process.env.GITHUB_SHA, shaPattern);
      assert.equal(event.after, process.env.GITHUB_SHA);
      assert.equal(
        execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
        process.env.GITHUB_SHA
      );
    } else {
      assert.equal(process.env.GITHUB_EVENT_NAME, "pull_request");
      assert.equal(process.env.GITHUB_BASE_REF, fixedBaseRef);
      assert.equal(event.pull_request.base.ref, fixedBaseRef);
      assert.equal(
        event.pull_request.head.repo.full_name,
        "cogni-test-org/cogni-monorepo"
      );
      assert.equal(
        event.pull_request.base.repo.full_name,
        "cogni-test-org/cogni-monorepo"
      );
      assert.match(event.pull_request.base.sha, shaPattern);
      assert.equal(
        event.pull_request.base.sha,
        process.env.FIXTURE_EVENT_BASE_SHA
      );
      const base = event.pull_request.base.sha;
      assert.equal(
        execFileSync("git", ["rev-parse", `${base}^{commit}`], {
          encoding: "utf8",
        }).trim(),
        base
      );
      execFileSync("git", ["merge-base", "--is-ancestor", base, "HEAD"], {
        stdio: "ignore",
      });
    }
    const recipe = readFileSync("infra/images/doltgres/Dockerfile", "utf8");
    assert(
      recipe.endsWith(
        "FROM " +
          runtimeBase +
          "\nCOPY --from=build /out/doltgres /usr/local/bin/doltgres\n"
      )
    );
    const inspected = [];
    for (const reference of [runtimeBase, image]) {
      phase =
        reference === runtimeBase
          ? "pull-reviewed-runtime-base"
          : "pull-fixed-TEST-mirror";
      execFileSync("docker", ["pull", "--platform", "linux/amd64", reference], {
        timeout: 120_000,
        stdio: "ignore",
      });
      const values = JSON.parse(
        execFileSync("docker", ["image", "inspect", reference], {
          timeout: 10_000,
          maxBuffer: 1024 * 1024,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        })
      );
      assert.equal(values.length, 1);
      inspected.push(values[0]);
    }
    phase = "loaded-configuration-verification";
    console.info(JSON.stringify(verifyLoadedFixture(...inspected)));
  } catch {
    // Never print inspected Config/Env or a child-process stderr buffer.
    console.error(
      JSON.stringify({ fixtureOnly: true, result: "failed", phase })
    );
    process.exitCode = 1;
  }
}
