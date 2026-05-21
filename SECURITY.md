# Security Policy

## Supported Versions

Only the latest version deployed from the `main` branch is supported. There are no
long-term support branches.

| Version | Supported |
| ------- | --------- |
| `main` (latest) | ✅ |
| older commits   | ❌ |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, **please do not open a
public GitHub issue**. Instead, report it privately so the issue can be fixed
before it becomes publicly known.

Preferred channels (pick one):

1. **GitHub Private Vulnerability Reporting** — open
   <https://github.com/luberan/nslookup/security/advisories/new> and submit a
   private report.
2. **Email** — send the details to the maintainer via the email address listed
   on the GitHub profile <https://github.com/luberan>.

Please include as much of the following as possible:

- A clear description of the vulnerability and its impact.
- Steps to reproduce (request payload, domain used, expected vs. actual
  behavior).
- The affected commit hash or deployment URL.
- Any proof-of-concept code, logs, or screenshots.
- Your name / handle if you would like to be credited.

### What to expect

- **Acknowledgement** within **3 business days** of receiving the report.
- **Initial assessment** (valid / not applicable / needs more info) within
  **7 business days**.
- A coordinated fix and disclosure timeline agreed with the reporter. For most
  issues the fix is deployed within **30 days** of confirmation.
- Public credit in the release notes (if desired).

### Scope

In scope:

- The Cloudflare Worker source code in this repository (`worker.js`).
- The HTTP API exposed by the deployed worker (`/api/dns`, `/`).
- Security headers, input validation, and SSRF hardening around the MTA-STS
  policy fetch.

Out of scope:

- Vulnerabilities in Cloudflare's platform itself — please report those to
  Cloudflare directly.
- Vulnerabilities in third-party domains queried via the tool.
- Reports based purely on missing "best-practice" headers without a concrete
  exploit scenario.
- Denial-of-service via volumetric traffic (rate limiting is a deployment
  concern, see `README.md`).

### Safe harbor

Good-faith security research that respects user privacy, avoids degradation of
service for other users, and follows this policy will not result in legal
action from the maintainer.

## Security-relevant design notes

For background on the existing hardening (CSP, HSTS, SSRF protections for the
MTA-STS fetch, DNSSEC handling, input validation), see the **Security** section
of [README.md](README.md).
