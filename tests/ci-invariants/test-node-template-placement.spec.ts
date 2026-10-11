// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// SPDX-FileCopyrightText: 2025 Cogni-DAO

/**
 * Module: `@tests/ci-invariants/test-node-template-placement`
 * Purpose: Keeps the test-parent node-template fixture on the renderer that consumes its exact-set app + workflow-worker bundle.
 * Scope: Test-parent catalog policy only; does not change canonical placement, which remains owned by Cogni-DAO/cogni.
 * Invariants:
 *   NODE_TEMPLATE_WORKER_USES_EXACT_SET_RENDERER: candidate-a uses Akash/Crossplane, never the node-app-only k3s overlay.
 *   TEST_OWNER_USES_TEST_WRITER: the fixture stays in cogni-test-org so owner-based actuator routing selects the isolated test account.
 * Side-effects: IO (reads infra/catalog/node-template.yaml)
 * Links: task.5233, story.5076, docs/spec/node-baas-architecture.md, docs/spec/temporal-patterns.md
 * @public
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import yaml from "yaml";

const REPO_ROOT = path.resolve(__dirname, "../..");

interface NodeTemplateCatalog {
  source_repo?: string;
  envs?: string[];
  deployment_provider?: Record<string, string>;
  compute_api?: Record<string, string>;
  lease_generation?: Record<string, number>;
  compute_egress_cidrs?: Array<{ cidr?: string }>;
}

const row = yaml.parse(
  readFileSync(path.join(REPO_ROOT, "infra/catalog/node-template.yaml"), "utf8")
) as NodeTemplateCatalog;

describe("test-parent node-template workflow placement (task.5233)", () => {
  it("renders the candidate app and private workflow worker as one Crossplane exact set", () => {
    expect(row.envs).toContain("candidate-a");
    expect(row.deployment_provider?.["candidate-a"]).toBe("akash");
    expect(row.compute_api?.["candidate-a"]).toBe("crossplane");
    expect(row.lease_generation?.["candidate-a"]).toBe(0);
    expect(
      row.compute_egress_cidrs?.some(({ cidr }) => cidr === "80.200.246.35/32")
    ).toBe(true);
  });

  it("keeps the candidate fixture on the isolated test actuator owner", () => {
    expect(new URL(row.source_repo ?? "").hostname).toBe("github.com");
    expect(new URL(row.source_repo ?? "").pathname.toLowerCase()).toBe(
      "/cogni-test-org/node-template.git"
    );
  });
});
