// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// SPDX-FileCopyrightText: 2025 Cogni-DAO

/**
 * Module: `@scripts/ci/tests/profile-native-proof`
 * Purpose: Prove sanitized observation, bounded streams, and native exit preservation.
 * Scope: Owned local HTTP socket and child processes. Does not access Docker.
 * Invariants: No exec or raw attribute serialization; observer joined before return.
 * Side-effects: IO (temporary owned socket/trace and awaited child processes).
 * Links: task.5314
 * @internal
 */
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
test("image pull names, tags and digests use a separate narrow reference allowlist", () => {
  for (const id of [
    "alpine",
    "alpine:latest",
    "ghcr.io/cogni-test-org/image:v1",
    `registry.local:5000/team/image@sha256:${"a".repeat(64)}`,
  ]) {
    const selected = safeEvent({
      ...event("pull"),
      Type: "image",
      Actor: { ID: id, Attributes: { name: id, env: "SECRET" } },
    });
    assert.equal(selected?.id, id);
    assert.equal(selected?.image, id);
    assert.equal(selected?.project, "");
    assert.ok(!JSON.stringify(selected).includes("SECRET"));
  }
  for (const id of [
    "https://registry/image",
    "user:password@registry/image",
    "image?token=SECRET",
    "image\nSECRET",
    "image@sha256:bad",
    "../image",
  ]) {
    assert.equal(
      safeEvent({ ...event("pull"), Type: "image", Actor: { ID: id } }),
      null
    );
  }
  assert.equal(
    safeEvent({ ...event("start"), Actor: { ID: "alpine:latest" } }),
    null
  );
});

test("valid event floods retain a bounded mandatory summary at count and byte limits", async () => {
  for (const mode of ["count", "bytes"]) {
    const dir = mkdtempSync(path.join(tmpdir(), "native-profile-"));
    const socketPath = path.join(dir, "docker.sock");
    const output = path.join(dir, "events.ndjson");
    const stopped = path.join(dir, "observer-stopped");
    const sample = event("start");
    sample.Actor.Attributes =
      mode === "count"
        ? {}
        : {
            image: "a".repeat(256),
            "com.docker.compose.project": "b".repeat(256),
          };
    const server = http.createServer((_req, res) => {
      res.on("error", () => {});
      res.on("close", () => writeFileSync(stopped, "joined"));
      res.writeHead(200);
      res.flushHeaders();
      res.write(`${JSON.stringify(sample)}\n`.repeat(6000));
    });
    await new Promise((resolve) => server.listen(socketPath, resolve));
    try {
      assert.equal(
        await profileNative({
          socketPath,
          output,
          command: process.execPath,
          args: [
            "-e",
            "const fs=require('node:fs');const end=Date.now()+2000;const timer=setInterval(()=>{if(fs.existsSync(process.argv[1])||Date.now()>end){clearInterval(timer);process.exit(7)}},5)",
            stopped,
          ],
        }),
        7
      );
      const text = readFileSync(output, "utf8");
      const rows = text.trim().split("\n").map(JSON.parse);
      assert.ok(Buffer.byteLength(text) <= 1048576);
      assert.ok(rows.length <= 5000);
      assert.deepEqual(
        rows.at(-1),
        { action: "profiling-inconclusive", nativeExit: 7 },
        `${mode}: ${rows.length} rows ${Buffer.byteLength(text)} bytes`
      );
      assert.ok(
        rows.filter((row) => row.action === "start").length >
          (mode === "count" ? 4900 : 1000)
      );
      if (mode === "bytes") assert.ok(rows.length < 4900);
    } finally {
      await new Promise((resolve) => server.close(resolve));
      rmSync(dir, { recursive: true, force: true });
    }
  }
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
