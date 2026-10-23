// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// SPDX-FileCopyrightText: 2025 Cogni-DAO

/**
 * Module: `@scripts/ci/tests/profile-native-proof`
 * Purpose: Prove sanitized observation, bounded streams, and native exit preservation.
 * Scope: Owned local HTTP socket and child processes only; no Docker.
 * Invariants: No exec or raw attribute serialization; observer joined before return.
 * Side-effects: IO (temporary owned socket/trace and awaited child processes).
 * Links: task.5314
 * @internal
 */
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { profileNative, safeEvent } from "../profile-native-proof.mjs";

const event = (Action) => ({
  Type: "container",
  Action,
  timeNano: 123456789,
  Actor: {
    ID: "a".repeat(64),
    Attributes: {
      image: "postgres:15",
      "com.docker.compose.project": "cogni-litellm-owned",
      env: "SECRET",
      command: "SECRET",
    },
  },
});
test("allowlist is applied before serialization, excludes exec and full attributes", () => {
  const chosen = safeEvent(event("start"));
  assert.deepEqual(Object.keys(chosen), [
    "action",
    "timeNano",
    "id",
    "image",
    "project",
  ]);
  assert.ok(!JSON.stringify(chosen).includes("SECRET"));
  for (const action of [
    "exec_create:SECRET",
    "exec_start",
    "exec_die",
    "attach",
    "rename",
  ])
    assert.equal(safeEvent(event(action)), null);
  assert.equal(safeEvent({ ...event("start"), Actor: { ID: "SECRET" } }), null);
});
test("observer ready precedes native, joins and preserves native failure exactly", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "native-profile-"));
  const socketPath = path.join(dir, "docker.sock");
  const output = path.join(dir, "events.ndjson");
  const server = http.createServer((req, res) => {
    assert.ok(!req.url.includes("exec"));
    res.writeHead(200);
    res.flushHeaders();
    res.write(`${JSON.stringify(event("exec_create:SECRET"))}\n`);
    res.write(`${JSON.stringify(event("start"))}\n`);
  });
  await new Promise((resolve) => server.listen(socketPath, resolve));
  try {
    const code = await profileNative({
      socketPath,
      output,
      command: process.execPath,
      args: ["-e", "setTimeout(()=>process.exit(7),30)"],
    });
    assert.equal(code, 7);
    const text = readFileSync(output, "utf8");
    assert.ok(!text.includes("SECRET"));
    const rows = text.trim().split("\n").map(JSON.parse);
    assert.equal(rows[0].action, "observer-ready");
    assert.ok(rows.findIndex((x) => x.action === "native-start") > 0);
    assert.equal(rows.at(-1).action, "observer-joined");
    assert.equal(rows.at(-1).nativeExit, 7);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});
test("unavailable observer cannot mask native exit and output remains capped", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "native-profile-"));
  const socketPath = path.join(dir, "absent.sock");
  const output = path.join(dir, "events.ndjson");
  try {
    assert.equal(
      await profileNative({
        socketPath,
        output,
        command: process.execPath,
        args: ["-e", "process.exit(9)"],
      }),
      9
    );
    assert.match(readFileSync(output, "utf8"), /profiling-inconclusive/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
test("event flood is bounded and malformed/nonready streams are inconclusive", async () => {
  for (const mode of ["flood", "status"]) {
    const dir = mkdtempSync(path.join(tmpdir(), "native-profile-"));
    const socketPath = path.join(dir, "docker.sock");
    const output = path.join(dir, "events.ndjson");
    const server = http.createServer((_req, res) => {
      res.on("error", () => {});
      res.writeHead(mode === "status" ? 503 : 200);
      res.flushHeaders();
      if (mode === "status") {
        res.end();
        return;
      }
      res.write("x".repeat(70000));
    });
    await new Promise((resolve) => server.listen(socketPath, resolve));
    try {
      assert.equal(
        await profileNative({
          socketPath,
          output,
          command: process.execPath,
          args: ["-e", "setTimeout(()=>process.exit(0),40)"],
        }),
        0
      );
      const text = readFileSync(output, "utf8");
      assert.ok(Buffer.byteLength(text) <= 1048576);
      assert.ok(!text.includes("SECRET"));
      assert.ok(!text.includes("observer-joined"));
    } finally {
      await new Promise((resolve) => server.close(resolve));
      rmSync(dir, { recursive: true, force: true });
    }
  }
});
