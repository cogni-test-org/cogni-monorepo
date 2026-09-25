// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// SPDX-FileCopyrightText: 2026 Cogni-DAO

import { describe, expect, it } from "vitest";

import { formatComputeWorkloadDiagnostic } from "./compute-workload-diagnostic";

describe("formatComputeWorkloadDiagnostic", () => {
  it("summarizes phase, serving, failure, resource, bootEpoch and conditions", () => {
    const out = formatComputeWorkloadDiagnostic({
      status: {
        phase: "Failed",
        serving: false,
        bootEpoch: 3,
        observedBundle: { ref: "img@sha256:abc" },
        failure: { reason: "PlacementFailed", message: "no bids received" },
        resource: {
          state: "closed",
          id: "dseq-123",
          endpoints: ["https://x"],
        },
        conditions: [
          {
            type: "Synced",
            status: "False",
            reason: "ReconcileError",
            message: "provider-http fail-closed",
          },
          { type: "Ready", status: "False", reason: "Creating", message: "" },
        ],
      },
    });
    expect(out).toContain("phase: Failed");
    expect(out).toContain("serving: false");
    expect(out).toContain("bootEpoch: 3");
    expect(out).toContain('observedBundle: {"ref":"img@sha256:abc"}');
    expect(out).toContain("failure.reason: PlacementFailed");
    expect(out).toContain("failure.message: no bids received");
    expect(out).toContain("resource.state: closed");
    expect(out).toContain("resource.id: dseq-123");
    expect(out).toContain(
      "type=Synced status=False reason=ReconcileError message=provider-http fail-closed"
    );
    expect(out).toContain("type=Ready status=False reason=Creating");
  });

  it("handles a missing status without throwing", () => {
    expect(formatComputeWorkloadDiagnostic({})).toContain("no status");
    expect(formatComputeWorkloadDiagnostic(null)).toContain("no status");
  });

  it("marks absent scalar fields and empty condition lists", () => {
    const out = formatComputeWorkloadDiagnostic({
      status: { phase: "Creating" },
    });
    expect(out).toContain("phase: Creating");
    expect(out).toContain("serving: (absent)");
    expect(out).toContain("failure: (absent)");
    expect(out).toContain("resource: (absent)");
    expect(out).toContain("conditions: (none)");
  });
});
