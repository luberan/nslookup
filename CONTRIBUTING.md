# Contributing

Thanks for your interest in improving the DNS Lookup Tool! This document
describes how to set up the project locally, the conventions used in the
codebase, and the process for submitting changes.

## Project overview

This repository contains a single Cloudflare Worker (`worker.js`) that performs
DNS analysis via DNS-over-HTTPS and renders both a JSON API and an HTML UI.
There is intentionally no build step and no `node_modules` checked in — the
whole worker is a single file using the Modules syntax.

See [README.md](README.md) for the feature list and API reference.

## Prerequisites

- [Node.js](https://nodejs.org/) 18 or newer (for `npx wrangler`).
- A [Cloudflare account](https://dash.cloudflare.com/) if you want to deploy.
- [Wrangler](https://developers.cloudflare.com/workers/wrangler/) — invoked via
  `npx`, no global install required.

## Local development

Clone the repository, install dev dependencies, and start the worker locally:

```bash
git clone https://github.com/luberan/nslookup.git
cd nslookup
npm install
npm run dev
```

Wrangler prints a local URL (typically <http://127.0.0.1:8787>). Open it in a
browser for the UI, or query the JSON API:

```bash
curl "http://127.0.0.1:8787/api/dns?name=example.com"
```

> `wrangler.toml` is committed but contains no secrets. Keep your personal
> `account_id` and private routes out of it — use the Cloudflare dashboard or
> the `CLOUDFLARE_ACCOUNT_ID` env var so they are never pushed.

## Deployment

```bash
npm run deploy
```

You need to be authenticated against your Cloudflare account (`npx wrangler
login`). The committed `wrangler.toml` already provides `name` / `main`.

## How to contribute

1. **Open an issue first** for non-trivial changes (new features, breaking
   changes, large refactors) so the design can be discussed before you invest
   time in a pull request.
2. **Fork** the repository and create a topic branch from `main`:
   ```bash
   git checkout -b feat/short-description
   ```
3. **Make your change** in `worker.js` (and update `README.md` if behavior or
   the API surface changes).
4. **Test manually** with `npx wrangler dev` against a few representative
   domains — see [Testing](#testing) below.
5. **Commit** using a [Conventional Commits](https://www.conventionalcommits.org/)
   style prefix (see below).
6. **Open a pull request** against `main` and describe the motivation,
   approach, and how you tested the change.

### Commit message style

Use Conventional Commits. Examples:

- `feat: add DNAME record lookup`
- `fix: handle empty TXT records without crashing`
- `docs: clarify MTA-STS policy parsing`
- `refactor: extract DoH helper`
- `chore: bump security headers`

Keep the subject line under 72 characters and write it in the imperative mood.

### Pull request checklist

- [ ] The change is focused — one logical change per PR.
- [ ] `README.md` is updated if the API, UI, or deployment story changes.
- [ ] No secrets, API tokens, or personal domains are committed.
- [ ] Security-relevant code paths (input validation, SSRF guards, security
      headers) keep their existing safeguards.
- [ ] You tested the change locally with `npx wrangler dev`.

## Coding conventions

- **One file.** Keep the worker in `worker.js`. Do not introduce a bundler or
  a `src/` tree unless there is a strong reason and it has been agreed in an
  issue.
- **No runtime dependencies.** The worker should run on Cloudflare's standard
  runtime without `node_modules`. Use platform APIs (`fetch`, `URL`,
  `TextEncoder`, `AbortController`, etc.).
- **Style.** Match the surrounding code: 2-space indent, double quotes,
  semicolons, `const`/`let` (never `var`), early returns, small helpers.
- **Naming.** `camelCase` for variables and functions, `UPPER_SNAKE_CASE` only
  for true constants.
- **HTML / CSS in the worker.** Keep template strings readable; prefer small
  helper functions over giant interpolations.

## Security considerations

This worker is a network tool that issues outbound DNS and HTTPS requests on
behalf of user input. When changing it, please keep the following in mind:

- **Validate input** before using it in URLs or DNS queries (length, label
  rules, punycode conversion via the `URL` parser).
- **Preserve SSRF protections** around the MTA-STS policy fetch:
  re-validation, timeout, streamed response size limit, `redirect: "manual"`
  (report but never follow redirects), `Content-Type` check.
- **Do not weaken security headers** (`Content-Security-Policy`, `HSTS`,
  `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`).
- **Propagate the DNSSEC AD bit** for any new DoH-based lookup, and surface
  failures in the UI.

If you find a vulnerability, please follow [SECURITY.md](SECURITY.md) instead
of opening a public issue or PR.

## Testing

There is no automated test suite. Please perform at least the following manual
checks against your local `wrangler dev` instance before opening a PR:

1. A well-configured domain (e.g. `microsoft.com`) returns all expected
   records.
2. An NXDOMAIN (e.g. `this-domain-does-not-exist.example`) is reported
   cleanly.
3. An IDN domain (e.g. `háčkydomény.cz`) is accepted and converted to
   punycode.
4. Invalid input (empty, too long, label starting with `-`, single label) is
   rejected with a clear error.
5. The `/api/dns` endpoint returns valid JSON and the documented fields.
6. The HTML UI renders without console errors and the security headers are
   present in the response (check DevTools → Network).

## License

By contributing, you agree that your contributions will be licensed under the
same license as the rest of this repository — see [LICENSE](LICENSE).
