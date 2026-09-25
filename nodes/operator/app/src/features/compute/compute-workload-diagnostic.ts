// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// SPDX-FileCopyrightText: 2026 Cogni-DAO

type JsonRecord = Readonly<Record<string, unknown>>;

/**
 * Pure, logging-only summary of a live (X)ComputeWorkload's diagnostic status.
 *
 * The verify gate already fetches the full live composite (status included) to
 * assess readiness, but only logs the terse verdict reason. When a composition
 * renders no lease it emits no create/bid to Loki, so the ONLY on-cluster signal
 * for "why no lease" lives in the composite's own `status.conditions`,
 * `status.failure`, and `status.resource` — none of which reach the flight log.
 * This surfaces exactly those fields (no verdict-logic change) so the root cause
 * appears in the run log on the first poll instead of an opaque timeout.
 */
export function formatComputeWorkloadDiagnostic(live: unknown): string {
  const root = asRecord(live);
  const status = asRecord(root?.status);
  if (!status) {
    return "[compute-workload-diagnostic] no status on live composite";
  }
  const failure = asRecord(status.failure);
  const resource = asRecord(status.resource);
  const conditions = Array.isArray(status.conditions) ? status.conditions : [];

  const lines: string[] = ["[compute-workload-diagnostic] live status:"];
  lines.push(`  phase: ${scalar(status.phase)}`);
  lines.push(`  serving: ${scalar(status.serving)}`);
  lines.push(`  bootEpoch: ${scalar(status.bootEpoch)}`);
  lines.push(`  observedBundle: ${compact(status.observedBundle)}`);
  if (failure) {
    lines.push(
      `  failure.reason: ${scalar(failure.reason)}  failure.message: ${scalar(failure.message)}`
    );
  } else {
    lines.push(`  failure: ${scalar(status.failure)}`);
  }
  if (resource) {
    lines.push(
      `  resource.state: ${scalar(resource.state)}  resource.id: ${scalar(resource.id)}  resource.endpoints: ${compact(resource.endpoints)}`
    );
  } else {
    lines.push(`  resource: ${scalar(status.resource)}`);
  }
  if (conditions.length === 0) {
    lines.push("  conditions: (none)");
  } else {
    lines.push("  conditions:");
    for (const value of conditions) {
      const condition = asRecord(value);
      lines.push(
        `    - type=${scalar(condition?.type)} status=${scalar(condition?.status)} reason=${scalar(condition?.reason)} message=${scalar(condition?.message)}`
      );
    }
  }
  return lines.join("\n");
}

function asRecord(value: unknown): JsonRecord | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : undefined;
}

function scalar(value: unknown): string {
  if (value === undefined) return "(absent)";
  if (value === null) return "null";
  if (typeof value === "string") return value.length > 0 ? value : "(empty)";
  return String(value);
}

function compact(value: unknown): string {
  if (value === undefined) return "(absent)";
  try {
    return JSON.stringify(value);
  } catch {
    return "(unserializable)";
  }
}
