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
const commitScriptMatch = workflow.match(/node --input-type=module <<'PR_VALIDATION'\r?\n([\s\S]*?)^[ \t]*PR_VALIDATION\r?$/m);
assert.ok(commitScriptMatch, "The current-PR verification script must be present.");
const commitScript = commitScriptMatch[1].replace(
  /^[ \t]*import \{ (?:appendFileSync|execFileSync) \} from "node:(?:fs|child_process)";\r?\n/gm,
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

function verifiedCommit() {
  return {
    sha: "dependabot-head",
    author: { login: "dependabot[bot]" },
    commit: { verification: { verified: true } },
  };
}

function evaluateCurrentPr({
  commits = [verifiedCommit()],
  pr = {},
  eventSha = "dependabot-head",
  commands = [],
  commitError = null,
} = {}) {
  let output = "";
  const messages = [];
  const prUrl = "https://github.com/luberan/nslookup/pull/1";
  const endpoint = "repos/luberan/nslookup/pulls/1/commits?per_page=2";
  vm.runInNewContext(commitScript, {
    process: {
      env: {
        GITHUB_REPOSITORY: "luberan/nslookup",
        GITHUB_OUTPUT: "github-output",
        PR_URL: prUrl,
        PR_NUMBER: "1",
        PR_HEAD_SHA: eventSha,
        DEFAULT_BRANCH: "main",
      },
    },
    execFileSync(command, args) {
      assert.equal(command, "gh");
      commands.push(Array.from(args));
      if (args[0] === "pr" && args[1] === "view") {
        return JSON.stringify({
          autoMergeRequest: {},
          baseRefName: "main",
          headRefOid: "dependabot-head",
          isDraft: false,
          ...pr,
        });
      }
      if (args[0] === "pr" && args[1] === "merge") {
        assert.deepEqual(Array.from(args), ["pr", "merge", "--disable-auto", prUrl]);
        return "";
      }
      assert.deepEqual(Array.from(args), ["api", endpoint]);
      if (commitError) throw commitError;
      return JSON.stringify(commits);
    },
    appendFileSync(path, value) {
      assert.equal(path, "github-output");
      output += value;
    },
    console: { log: (message) => messages.push(message) },
  });
  return { output, messages, commands };
}

test("Dependabot verifies the complete current PR and revokes the previous decision first", () => {
  const { output, commands } = evaluateCurrentPr();
  assert.equal(output, "verified=true\n");
  assert.deepEqual(commands[1].slice(0, 3), ["pr", "merge", "--disable-auto"]);
  assert.equal(commands[2][0], "api");
});

test("Dependabot does not try to revoke auto-merge when it is already disabled", () => {
  const { output, commands } = evaluateCurrentPr({ pr: { autoMergeRequest: null } });
  assert.equal(output, "verified=true\n");
  assert.equal(commands.length, 2);
  assert.equal(commands[1][0], "api");
});

test("Dependabot revokes auto-merge when a human commit follows a verified bot commit", () => {
  const { output, commands, messages } = evaluateCurrentPr({
    commits: [
      verifiedCommit(),
      { ...verifiedCommit(), sha: "human-head", author: { login: "maintainer" } },
    ],
    pr: { headRefOid: "human-head" },
    eventSha: "human-head",
  });
  assert.equal(output, "verified=false\n");
  assert.deepEqual(commands[1].slice(0, 3), ["pr", "merge", "--disable-auto"]);
  assert.equal(commands[2][0], "api");
  assert.match(messages.at(-1), /::notice::Skipping auto-merge/);
});

const invalidPrCases = [
  ["multiple verified bot commits", { commits: [verifiedCommit(), verifiedCommit()] }],
  ["unverified signature", { commits: [{
    ...verifiedCommit(), commit: { verification: { verified: false } },
  }] }],
  ["human commit author", { commits: [{
    ...verifiedCommit(), author: { login: "maintainer" },
  }] }],
  ["missing commit author", { commits: [{ ...verifiedCommit(), author: null }] }],
  ["stale event head", { eventSha: "older-head" }],
  ["commit does not match the PR head", { commits: [{ ...verifiedCommit(), sha: "different-head" }] }],
  ["draft PR", { pr: { isDraft: true } }],
  ["another base branch", { pr: { baseRefName: "another-branch" } }],
  ["empty commit list", { commits: [] }],
];

for (const [name, options] of invalidPrCases) {
  test(`Dependabot current-PR verification: ${name}`, () => {
    const { output, messages } = evaluateCurrentPr(options);
    assert.equal(output, "verified=false\n");
    assert.match(messages.at(-1), /::notice::Skipping auto-merge/);
  });
}

test("Dependabot revokes auto-merge before a commit API error", () => {
  const commands = [];
  assert.throws(() => evaluateCurrentPr({
    commands, commitError: new Error("Commit API unavailable"),
  }), /Commit API unavailable/);
  assert.deepEqual(commands[1].slice(0, 3), ["pr", "merge", "--disable-auto"]);
});

test("Dependabot rejects an invalid commit API response after revoking auto-merge", () => {
  const commands = [];
  assert.throws(() => evaluateCurrentPr({ commits: {}, commands }), /Expected the current PR commit list/);
  assert.deepEqual(commands[1].slice(0, 3), ["pr", "merge", "--disable-auto"]);
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
  ["another base still revokes an old decision", (github) => { github.event.pull_request.base.ref = "another-branch"; }, true],
  ["draft PR still revokes an old decision", (github) => { github.event.pull_request.draft = true; }, true],
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
  assert.match(workflow, /converted_to_draft, edited/);
  assert.match(workflow, /if: steps\.commit\.outputs\.verified == 'true'/);
  assert.match(workflow, /if: steps\.eligibility\.outputs\.eligible == 'true'/);
  assert.match(workflow, /gh pr merge --auto --squash --match-head-commit "\$PR_HEAD_SHA" "\$PR_URL"/);
  assert.doesNotMatch(workflow, /--admin\b/);
});
