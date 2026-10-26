import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const workflow = readFileSync(
  new URL("../.github/workflows/dependabot-auto-merge.yml", import.meta.url),
  "utf8",
);
const scriptMatch = workflow.match(/node --input-type=module <<'NODE'\r?\n([\s\S]*?)^[ \t]*NODE\r?$/m);
assert.ok(scriptMatch, "The auto-merge eligibility script must be present.");
const eligibilityScript = scriptMatch[1].replace(
  /^[ \t]*import \{ appendFileSync \} from "node:fs";\r?\n/m,
  "",
);
const conditionMatch = workflow.match(/^    if: >-\r?\n((?:      [^\r\n]+\r?\n)+)/m);
assert.ok(conditionMatch, "The auto-merge job condition must be present.");
const jobCondition = conditionMatch[1].trim();

function dependency(overrides = {}) {
  return {
    dependencyName: "wrangler",
    dependencyType: "direct:development",
    updateType: "version-update:semver-patch",
    packageEcosystem: "npm_and_yarn",
    directory: "/",
    ...overrides,
  };
}

function evaluateEligibility(metadata) {
  let output = "";
  const messages = [];
  vm.runInNewContext(eligibilityScript, {
    process: {
      env: {
        UPDATED_DEPENDENCIES: metadata,
        GITHUB_OUTPUT: "github-output",
      },
    },
    appendFileSync(path, value) {
      assert.equal(path, "github-output");
      output += value;
    },
    console: { log: (message) => messages.push(message) },
  });
  return { output, messages };
}

const updateCases = [
  ["Wrangler patch", [dependency()], true],
  ["Playwright minor", [dependency({
    dependencyName: "@playwright/test",
    updateType: "version-update:semver-minor",
  })], true],
  ["grouped patch and minor", [
    dependency(),
    dependency({ dependencyName: "@playwright/test", updateType: "version-update:semver-minor" }),
  ], true],
  ["major update", [dependency({ updateType: "version-update:semver-major" })], false],
  ["group containing a major", [
    dependency(),
    dependency({ dependencyName: "@playwright/test", updateType: "version-update:semver-major" }),
  ], false],
  ["another npm package", [dependency({ dependencyName: "another-package" })], false],
  ["group containing another package", [
    dependency(),
    dependency({ dependencyName: "another-package" }),
  ], false],
  ["production dependency", [dependency({ dependencyType: "direct:production" })], false],
  ["indirect dependency", [dependency({ dependencyType: "indirect" })], false],
  ["group containing a production dependency", [
    dependency(),
    dependency({ dependencyName: "@playwright/test", dependencyType: "direct:production" }),
  ], false],
  ["GitHub Actions update", [dependency({ packageEcosystem: "github_actions" })], false],
  ["another directory", [dependency({ directory: "/another-project" })], false],
  ["missing update type", [dependency({ updateType: undefined })], false],
  ["missing package name", [dependency({ dependencyName: undefined })], false],
];

for (const [name, updates, eligible] of updateCases) {
  test(`Dependabot eligibility: ${name}`, () => {
    const { output, messages } = evaluateEligibility(JSON.stringify(updates));
    assert.equal(output, `eligible=${eligible}\n`);
    assert.equal(messages.length, 1);
    assert.match(messages[0], eligible ? /enabling auto-merge/ : /Skipping auto-merge/);
  });
}

for (const metadata of ["[]", "{}", "null"]) {
  test(`Dependabot rejects invalid metadata: ${metadata}`, () => {
    assert.throws(() => evaluateEligibility(metadata), /Expected at least one verified Dependabot/);
  });
}

test("Dependabot rejects malformed JSON", () => {
  assert.throws(() => evaluateEligibility("not JSON"), { name: "SyntaxError" });
});

function eventContext() {
  return {
    repository: "luberan/nslookup",
    event: {
      repository: { default_branch: "main" },
      pull_request: {
        user: { login: "dependabot[bot]" },
        head: { repo: { full_name: "luberan/nslookup" } },
        base: { ref: "main" },
        draft: false,
      },
    },
  };
}

const eventCases = [
  ["Dependabot in this repository", () => {}, true],
  ["human author", (github) => { github.event.pull_request.user.login = "contributor"; }, false],
  ["fork branch", (github) => { github.event.pull_request.head.repo.full_name = "contributor/nslookup"; }, false],
  ["another base branch", (github) => { github.event.pull_request.base.ref = "another-branch"; }, false],
  ["draft pull request", (github) => { github.event.pull_request.draft = true; }, false],
];

for (const [name, modify, eligible] of eventCases) {
  test(`Dependabot job guard: ${name}`, () => {
    const github = eventContext();
    modify(github);
    assert.equal(vm.runInNewContext(jobCondition, { github }), eligible);
  });
}

test("Dependabot auto-merge uses verified metadata without checking out PR code or bypassing checks", () => {
  assert.match(workflow, /pull_request_target:/);
  assert.match(workflow, /uses: dependabot\/fetch-metadata@[0-9a-f]{40}\s/);
  assert.doesNotMatch(workflow, /uses:\s*actions\/checkout@/);
  assert.doesNotMatch(workflow, /skip-(?:commit-)?verification:/);
  assert.match(workflow, /if: steps\.eligibility\.outputs\.eligible == 'true'/);
  assert.match(workflow, /gh pr merge --auto --squash --match-head-commit "\$PR_HEAD_SHA" "\$PR_URL"/);
  assert.doesNotMatch(workflow, /--admin\b/);
});
