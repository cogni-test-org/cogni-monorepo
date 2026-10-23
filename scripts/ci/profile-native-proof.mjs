// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// SPDX-FileCopyrightText: 2025 Cogni-DAO

/**
 * Module: `@scripts/ci/profile-native-proof`
 * Purpose: Observe lifecycle phases around the unchanged native acceptance command in TEST.
 * Scope: Read-only disposable runner Docker events; no exec events or Docker mutation.
 * Invariants: Filter before serialization; bounded output; preserve native exit; join observer.
 * Side-effects: IO (bounded sanitized trace and awaited native child process).
 * Links: task.5314, operator-ci-proof-lanes Checkpoint0
 * @internal
 */
import { spawn } from "node:child_process";
import { appendFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import { constants } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const containerActions = new Set([
  "create",
  "start",
  "stop",
  "die",
  "destroy",
  "pause",
  "unpause",
  "health_status: healthy",
  "health_status: unhealthy",
]);
const reference = (value) =>
  typeof value === "string" && /^[a-zA-Z0-9_./@:-]{1,256}$/.test(value)
    ? value
    : "";

export function safeEvent(event) {
  if (event.Type !== "container" && event.Type !== "image") return null;
  if (event.Type === "container" && !containerActions.has(event.Action))
    return null;
  if (event.Type === "image" && event.Action !== "pull") return null;
  const id = event.Actor?.ID ?? event.id;
  if (typeof id !== "string" || !/^(sha256:)?[a-f0-9]{12,64}$/.test(id))
    return null;
  if (!Number.isFinite(event.timeNano) || event.timeNano < 0) return null;
  return {
    action: event.Action,
    timeNano: String(event.timeNano),
    id,
    image: reference(event.Actor?.Attributes?.image),
    project: reference(event.Actor?.Attributes?.["com.docker.compose.project"]),
  };
}

export async function profileNative({ socketPath, output, command, args }) {
  const maxBytes = 1_048_576;
  const maxRecords = 5_000;
  let bytes = 0,
    records = 0,
    inconclusive = false,
    stopping = false,
    stream,
    child,
    signal;
  writeFileSync(output, "", { mode: 0o600 });
  const record = (value) => {
    const line = `${JSON.stringify(value)}\n`;
    if (++records > maxRecords || bytes + Buffer.byteLength(line) > maxBytes) {
      inconclusive = true;
      return false;
    }
    bytes += Buffer.byteLength(line);
    appendFileSync(output, line);
    return true;
  };
  const phase = (action) => record({ action, time: new Date().toISOString() });
  let joinedResolve;
  const joined = new Promise((resolve) => {
    joinedResolve = resolve;
  });
  const filters = {
    type: ["container", "image"],
    event: [
      "create",
      "start",
      "stop",
      "die",
      "destroy",
      "pause",
      "unpause",
      "health_status",
      "pull",
    ],
  };
  const since = Math.floor(Date.now() / 1000);
  let readyResolve;
  const ready = new Promise((resolve) => {
    readyResolve = resolve;
  });
  const request = http.get({
    socketPath,
    path: `/events?since=${since}&filters=${encodeURIComponent(JSON.stringify(filters))}`,
  });
  const abandon = () => {
    inconclusive = true;
    readyResolve(false);
    request.destroy();
    stream?.destroy();
  };
  const timer = setTimeout(abandon, 10_000);
  request.on("error", () => {
    if (!stopping) inconclusive = true;
    readyResolve(false);
    joinedResolve();
  });
  request.on("close", () => {
    if (!stream) joinedResolve();
  });
  request.on("response", (response) => {
    stream = response;
    clearTimeout(timer);
    response.on("error", () => {
      if (!stopping) inconclusive = true;
    });
    response.on("close", () => {
      if (!stopping) inconclusive = true;
      joinedResolve();
    });
    if (response.statusCode !== 200) {
      abandon();
      return;
    }
    let buffer = "";
    response.setEncoding("utf8");
    response.on("data", (chunk) => {
      buffer += chunk;
      if (Buffer.byteLength(buffer) > 65_536) {
        abandon();
        return;
      }
      while (buffer.includes("\n")) {
        const end = buffer.indexOf("\n");
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 1);
        if (!line) continue;
        try {
          const selected = safeEvent(JSON.parse(line));
          if (selected && !record(selected)) {
            abandon();
            return;
          }
        } catch {
          abandon();
          return;
        }
      }
    });
    phase("observer-ready");
    readyResolve(true);
  });
  const forward = (name) => {
    signal = name;
    if (child?.pid) {
      try {
        process.kill(
          process.platform === "win32" ? child.pid : -child.pid,
          name
        );
      } catch {
        /* Child already exited. */
      }
    } else abandon();
  };
  const handlers = Object.fromEntries(
    ["SIGINT", "SIGTERM"].map((name) => [name, () => forward(name)])
  );
  for (const [name, handler] of Object.entries(handlers))
    process.on(name, handler);
  let exit = 1;
  try {
    const observed = await ready;
    clearTimeout(timer);
    if (!observed) phase("observer-unavailable");
    if (signal) {
      exit = 128 + (constants.signals[signal] ?? 0);
      return exit;
    }
    phase("native-start");
    child = spawn(command, args, {
      stdio: "inherit",
      detached: process.platform !== "win32",
    });
    exit = await new Promise((resolve) => {
      child.once("error", () => resolve(127));
      child.once("close", (code, name) =>
        resolve(code ?? 128 + (constants.signals[name] ?? 0))
      );
    });
    phase("native-end");
    return exit;
  } finally {
    clearTimeout(timer);
    stopping = true;
    request.destroy();
    stream?.destroy();
    await joined;
    for (const [name, handler] of Object.entries(handlers))
      process.off(name, handler);
    // No raw Docker event is ever serialized. Summary remains bounded as well.
    record({
      action: inconclusive ? "profiling-inconclusive" : "observer-joined",
      nativeExit: exit,
    });
  }
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  if (
    process.env.GITHUB_REPOSITORY !== "cogni-test-org/cogni-monorepo" ||
    process.platform !== "linux"
  ) {
    throw new Error(
      "Native profiling is limited to the disposable Linux TEST job"
    );
  }
  const supplied = process.argv.slice(2);
  if (
    supplied.join(" ") !== "--config scripts/vitest/vitest.native.config.mts"
  ) {
    throw new Error(
      "Only the unchanged exact native configuration is accepted"
    );
  }
  process.exitCode = await profileNative({
    socketPath: "/var/run/docker.sock",
    output: path.join(process.env.RUNNER_TEMP, "native-profile.ndjson"),
    command: "pnpm",
    args: ["exec", "vitest", "run", ...supplied],
  });
}
