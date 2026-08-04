# DNS Lookup Tool

Cloudflare Worker for comprehensive DNS analysis of a domain, with a focus on email security and DNSSEC validation.

## Features

### Basic DNS records
- **NS** — domain nameservers
- **A / AAAA** — IPv4 and IPv6 addresses
- **MX** — mail exchange records (sorted by priority)
- **SPF** — Sender Policy Framework (extracted from TXT)
- **Null MX** detection (RFC 7505) — domain explicitly does not accept email
- **IDN** support — Unicode domains (e.g. `háčkydomény.cz`) are automatically converted to A-label (punycode)

### Email security
| Record | DNS query | Description |
|---|---|---|
| **DKIM** | `<selector>._domainkey.<domain>` (CNAME + TXT) | Defaults to the Microsoft 365 selectors `selector1` / `selector2`. Override with `?selectors=` (comma-separated, max 5). Each selector is queried as **CNAME** (Microsoft 365 delegation) and **TXT** (direct keys, e.g. Google Workspace, Mailgun). |
| **DMARC** | RFC 9989 DNS Tree Walk | Checks the Author Domain first, then walks toward the root (max 8 queries) to discover inherited Organizational Domain or Public Suffix Domain policy. Reports `p`, `sp`, `np`, `psd`, and `t` effects. |
| **MTA-STS TXT** | `_mta-sts.<domain>` | MTA Strict Transport Security identifier |
| **MTA-STS Policy** | `https://mta-sts.<domain>/.well-known/mta-sts.txt` | Fetch and parse the MTA-STS policy (mode, max_age, mx) |
| **TLS-RPT** | `_smtp._tls.<domain>` | SMTP TLS Reporting |
| **BIMI** | `default._bimi.<domain>` | Brand Indicators for Message Identification |
| **DANE / TLSA** | `_25._tcp.<mx-host>` for each MX | DNS-based Authentication of Named Entities (with DNSSEC validation). MX hosts are sorted by priority and capped at 15; coverage metadata makes truncation explicit. Domains with no MX but a valid A/AAAA record use the RFC 5321 implicit MX. |

### DNSSEC
Every DoH query uses the `do=1` flag and propagates the **AD bit** (Authenticated Data) from the response. Each relevant UI panel distinguishes **DNSSEC authenticated** from **DNSSEC not authenticated**. The latter is informational for ordinary DNS records; an unauthenticated TLSA record is explicitly marked untrusted because DANE depends on DNSSEC.

### Configuration validation
The UI warns about common configuration mistakes:
- Multiple SPF / DMARC / MTA-STS / TLS-RPT records (RFC violation)
- Inherited DMARC policy, its policy domain, test mode, and requested versus effective policy
- Invalid MTA-STS discovery records and policy files
- TLSA records without DNSSEC validation
- A truncated DANE scan when more than 15 unique MX hosts are published
- Null MX (informational)
- NXDOMAIN — the entire domain does not exist

For protocols that are only discovered, the UI says **Found**, not **OK**.
Only configurations that the tool fully validates (currently MTA-STS and the
DNSSEC trust state for TLSA) receive a **Valid** / **DNSSEC OK** indicator.
Resolver failures are shown as lookup errors and never as missing records.

## API

```
GET /api/dns?name=example.com
```

Returns JSON with all results. DNS queries run in parallel via DNS-over-HTTPS (`cloudflare-dns.com`).

**Optional query parameters:**
- `selectors` — comma-separated DKIM selectors to look up **instead of** the default Microsoft 365 selectors (`selector1`, `selector2`). Each is validated as DNS label(s), deduplicated and capped at 5. Example: `?name=example.com&selectors=google,20221208`.

### Example response

```json
{
  "domain": "example.com",
  "ns": [{ "data": "ns1.example.com", "ttl": 3600 }],
  "a": [{ "data": "93.184.216.34", "ttl": 300 }],
  "aaaa": [],
  "mx": [{ "preference": 10, "exchange": "mail.example.com", "ttl": 3600 }],
  "nullMx": false,
  "spf": ["v=spf1 include:_spf.google.com ~all"],
  "dkim": [
    { "selector": "selector1", "cname": [{ "data": "selector1-example-com._domainkey.example.onmicrosoft.com", "ttl": 3600 }], "txt": [] },
    { "selector": "selector2", "cname": [], "txt": [] }
  ],
  "dkimCustom": false,
  "dmarc": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
  "dmarcDiscovery": { "found": true, "valid": true, "policyDomain": "example.com", "source": "author", "inherited": false, "requestedPolicy": "reject", "effectivePolicy": "reject", "testing": false, "dnssec": true },
  "mtaSts": ["v=STSv1; id=20240101000000Z"],
  "mtaStsValidation": { "found": true, "valid": true, "record": "v=STSv1; id=20240101000000Z", "id": "20240101000000Z" },
  "mtaStsPolicy": { "found": true, "valid": true, "policy": { "version": "STSv1", "mode": "enforce", "max_age": "604800", "mx": ["*.example.com"] } },
  "tlsRpt": ["v=TLSRPTv1; rua=mailto:tlsrpt@example.com"],
  "bimi": ["v=BIMI1; l=https://example.com/logo.svg"],
  "dane": [{ "mx": "mail.example.com", "preference": 10, "implicit": false, "tlsa": [], "dnssec": true, "status": 0 }],
  "daneMeta": { "candidates": 1, "checked": 1, "truncated": false, "limit": 15, "implicitMx": false },
  "dnssec": { "ns": true, "a": true, "aaaa": true, "mx": true, "txt": true, "dmarc": true, "mtaStsTxt": true, "tlsRpt": true, "bimi": true },
  "status":  { "ns": 0, "a": 0, "aaaa": 0, "mx": 0, "txt": 0, "dmarc": 0, "mtaStsTxt": 0, "tlsRpt": 0, "bimi": 0 },
  "errors":  { "ns": null, "a": null, "aaaa": null, "mx": null, "txt": null, "dmarc": null, "mtaStsTxt": null, "tlsRpt": null, "bimi": null }
}
```

DoH `Status` codes: `0` = OK, `2` = SERVFAIL, `3` = NXDOMAIN.
Non-zero resolver statuses and transport failures are also exposed in
`errors`. If all five base DNS queries fail, the API returns `502` instead of
a misleading empty `200` response.

### Input validation
- Max 253 characters total, max 63 characters per label
- A label must not start or end with a hyphen
- At least 2 labels (TLD + SLD)
- Unicode → punycode via the `URL` parser
- Domain-only input: URL components, credentials, ports, paths, IP literals,
  whitespace and backslashes are rejected rather than silently normalized
- DKIM `selectors` (optional): each validated as DNS label(s), deduplicated, capped at 5 (invalid input → `400`)

### CORS
The endpoint returns `Access-Control-Allow-Origin: *` and supports preflight `OPTIONS`.
Only `GET` is accepted; other methods return `405 Method Not Allowed` with an `Allow: GET, OPTIONS` header.

## UI

The root path (`/`) returns an HTML page with a search form. Results are displayed in panels with colored indicators:
- **Found** — a matching record was discovered but not fully validated
- **Valid / DNSSEC authenticated** — the configuration or DNS response was validated
- **Missing / Invalid** — a record was not found or failed validation
- **Warning / Lookup failed** — duplicate records, unauthenticated TLSA, resolver errors, null MX, etc.

Starting a new lookup aborts the previous browser request and ignores any stale
response that finishes later, so older results cannot replace the latest query.

## Security

The worker sends a complete set of security headers:
- `Content-Security-Policy` with exact SHA-256 sources for the inline script and style (no `'unsafe-inline'`), `object-src 'none'`, and restricted image/connect/form/frame sources
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`

The UI remains a single Worker file. A regression test recalculates both CSP
hashes from the returned HTML, so changing inline CSS or JavaScript without
updating the corresponding policy fails CI instead of silently blocking the UI.

**MTA-STS policy fetch** is hardened against SSRF / abuse:
- Performed only after one syntactically valid `_mta-sts` discovery TXT record
  with a valid `id` is found
- Domain re-validated before being used in the URL
- 5s timeout (`AbortController`)
- 64 KB limit (RFC 8461), enforced while streaming so an oversized body is never fully buffered
- `redirect: "manual"` — redirects are reported but never followed (RFC 8461 §3.3; prevents redirect-based SSRF to an arbitrary target)
- Strict `Content-Type: text/plain`, version, mode, `max_age` and MX-pattern validation
- `cache: "no-store"` — RFC 8461 forbids HTTP caching by policy clients

### Production rate limiting

The production deployment is protected by an active Cloudflare rate limiting
rule configured in **Security rules → Rate limiting rules**:

- Match expression: `(http.request.uri.path eq "/api/dns")`
- Counting characteristic: source IP
- Threshold: 10 requests per 10 seconds
- Action: block for 10 seconds
- Execution order: first

This is dashboard-managed infrastructure and is therefore not represented in
`wrangler.toml` or automatically inherited by forks and separate deployments.
Operators of another deployment should recreate an equivalent rule in their
own Cloudflare zone.

Cloudflare rate limiting rules are zone-scoped. This repository currently has
`workers_dev = true`, which also exposes a public `*.workers.dev` URL. When the
production API is served on a custom domain, disable that alternate route with
`workers_dev = false` or restrict it with Cloudflare Access so it cannot bypass
the custom domain's zone-level rate limit.

### Request resource bounds

Workers Free allows 50 subrequests per invocation. User-controlled fan-out is
bounded to 5 DKIM selectors (10 DNS queries), 15 TLSA hosts, and 8 DMARC Tree
Walk queries. Together with fixed DNS and optional MTA-STS policy requests, the
worst case is 42 subrequests, leaving headroom below the platform limit.

## Caching

- **HTML** template — `Cache-Control: public, max-age=3600`
- **JSON API** — `Cache-Control: public, max-age=60` (successful responses)
- **DoH queries** — `cf: { cacheTtl: 60, cacheEverything: true }` (Cloudflare edge cache)
- **MTA-STS policy** — never HTTP-cached (`cache: "no-store"`)

## Deployment

The development toolchain requires **Node.js 24 LTS** (also recorded in
`.nvmrc` and `package.json`). The repository ships a lockfile and a
ready-to-use `wrangler.toml` (no secrets). Install, test, and deploy with:

```bash
npm ci
npm run ci
npm run deploy
```

Or, without `npm install`:

```bash
npx wrangler deploy worker.js
```

`npm run ci` performs a syntax check, runs the dependency-free Node test suite,
and verifies Wrangler packaging with `deploy --dry-run`. The same command runs
in GitHub Actions on Node.js 24.

## Forking / running your own instance

A few personal touches are baked into `worker.js`. If you are deploying your
own instance you will probably want to change them:

- **Favicon redirect** (`/favicon.ico` → `https://www.lukasberan.cz/img/logo.png`)
  and the `<link rel="icon">` in the HTML template. Replace with your own URL
  or remove the redirect entirely.
- **Footer link** in the HTML template ("Created by Lukas Beran").
- **`img-src` in the Content-Security-Policy** — currently allows
  `https://www.lukasberan.cz`. Update it to match whatever host serves your
  favicon / images, or drop it if you remove the external image.
- **`<meta name="robots" content="noindex, nofollow">`** in the HTML
  template prevents search engines from indexing the UI. Remove it if you
  want your public instance to be indexable.
- **`name` in `wrangler.toml`** — currently `nslookup`. If you deploy via
  Cloudflare Workers Builds, make sure it matches the Worker you connected
  (or rename both); add your own `routes` / `account_id` there if needed.

## Technologies

- [Cloudflare Workers](https://workers.cloudflare.com/) (Modules syntax)
- [DNS-over-HTTPS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/) via `cloudflare-dns.com`
