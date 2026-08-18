#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const config = JSON.parse(
  readFileSync(join(here, "candidate-parent-sync.json"), "utf8")
);
const root = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();
const git = (...args) =>
  execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();

git("cat-file", "-e", `${config.upstream.sha}^{commit}`);

const [sourceMerge, ...sourceParents] = git(
  "rev-list",
  "--parents",
  "-n",
  "1",
  config.upstream.sha
).split(" ");
const expectedSourceParents = config.upstream.sourceHeads.map(({ sha }) => sha);
if (
  sourceMerge !== config.upstream.sha ||
  sourceParents.length !== expectedSourceParents.length ||
  sourceParents.some((sha, index) => sha !== expectedSourceParents[index])
) {
  console.error(
    `Reviewed source merge ${config.upstream.sha} must bind exact parents ${expectedSourceParents.join(
      ", "
    )}`
  );
  process.exit(1);
}

const changed = git(
  "diff",
  "--name-only",
  "--no-renames",
  config.upstream.sha,
  "--"
)
  .split("\n")
  .filter(Boolean);
const allowed = new Set(config.allowedDivergencePaths);
const unexpected = changed.filter((path) => !allowed.has(path));

if (unexpected.length > 0) {
  console.error("Candidate parent drifted from its reviewed canonical source:");
  for (const path of unexpected) console.error(`  ${path}`);
  process.exit(1);
}

if (process.argv.includes("--require-merge-parent")) {
  const [head, firstParent, secondParent, ...extraParents] = git(
    "rev-list",
    "--parents",
    "-n",
    "1",
    "HEAD"
  ).split(" ");
  if (
    !head ||
    !firstParent ||
    secondParent !== config.upstream.sha ||
    extraParents.length
  ) {
    console.error(
      `Expected a two-parent sync commit whose second parent is ${config.upstream.sha}`
    );
    process.exit(1);
  }
}

console.log(
  `PASS: ${changed.length} reviewed candidate-local path(s); all other content matches ${config.upstream.repo}@${config.upstream.sha}`
);
