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
| **DKIM** | `selector1._domainkey.<domain>`, `selector2._domainkey.<domain>` | DKIM CNAME records for Exchange Online |
| **DMARC** | `_dmarc.<domain>` | Domain-based Message Authentication |
| **MTA-STS TXT** | `_mta-sts.<domain>` | MTA Strict Transport Security identifier |
| **MTA-STS Policy** | `https://mta-sts.<domain>/.well-known/mta-sts.txt` | Fetch and parse the MTA-STS policy (mode, max_age, mx) |
| **TLS-RPT** | `_smtp._tls.<domain>` | SMTP TLS Reporting |
| **BIMI** | `default._bimi.<domain>` | Brand Indicators for Message Identification |
| **DANE / TLSA** | `_25._tcp.<mx-host>` for each MX | DNS-based Authentication of Named Entities (with DNSSEC validation) |

### DNSSEC
Every DoH query uses the `do=1` flag and propagates the **AD bit** (Authenticated Data) from the response. The UI shows:
- ✅ DNSSEC validation OK for individual records
- ⚠️ Warning for **DANE/TLSA without DNSSEC** (an unsigned TLSA record is untrustworthy)

### Configuration validation
The UI warns about common configuration mistakes:
- Multiple SPF / DMARC / MTA-STS / TLS-RPT records (RFC violation)
- TLSA records without DNSSEC validation
- Null MX (informational)
- NXDOMAIN — the entire domain does not exist

## API

```
GET /api/dns?name=example.com
```

Returns JSON with all results. DNS queries run in parallel via DNS-over-HTTPS (`cloudflare-dns.com`).

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
    { "selector": "selector1", "records": [{ "data": "selector1-example-com._domainkey.example.onmicrosoft.com", "ttl": 3600 }] },
    { "selector": "selector2", "records": [] }
  ],
  "dmarc": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
  "mtaSts": ["v=STSv1; id=20240101000000Z"],
  "mtaStsPolicy": { "found": true, "policy": { "version": "STSv1", "mode": "enforce", "max_age": "604800", "mx": ["*.example.com"] } },
  "tlsRpt": ["v=TLSRPTv1; rua=mailto:tlsrpt@example.com"],
  "bimi": ["v=BIMI1; l=https://example.com/logo.svg"],
  "dane": [{ "mx": "mail.example.com", "tlsa": [], "dnssec": true, "status": 0 }],
  "dnssec": { "ns": true, "a": true, "aaaa": true, "mx": true, "txt": true, "dmarc": true, "mtaStsTxt": true, "tlsRpt": true, "bimi": true },
  "status":  { "ns": 0, "a": 0, "aaaa": 0, "mx": 0, "txt": 0, "dmarc": 0, "mtaStsTxt": 0, "tlsRpt": 0, "bimi": 0 }
}
```

DoH `Status` codes: `0` = OK, `2` = SERVFAIL, `3` = NXDOMAIN.

### Input validation
- Max 253 characters total, max 63 characters per label
- A label must not start or end with a hyphen
- At least 2 labels (TLD + SLD)
- Unicode → punycode via the `URL` parser

### CORS
The endpoint returns `Access-Control-Allow-Origin: *` and supports preflight `OPTIONS`.

## UI

The root path (`/`) returns an HTML page with a search form. Results are displayed in panels with colored indicators:
- 🟢 **OK** — record found / DNSSEC validated
- 🔴 **Missing** — record not found
- 🟡 **Warning** — duplicate record, missing DNSSEC, null MX, etc.

## Security

The worker sends a complete set of security headers:
- `Content-Security-Policy` (script/style `'self' 'unsafe-inline'`, img `'self' data: lukasberan.cz`)
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`

**MTA-STS policy fetch** is hardened against SSRF / abuse:
- Domain re-validated before being used in the URL
- 5s timeout (`AbortController`)
- 64 KB limit (RFC 8461)
- `redirect: "error"` (RFC 8461 §3.3 forbids following redirects)
- `Content-Type: text/plain` check

**Recommendation for production deployment:**
- Configure rate limiting in the Cloudflare Dashboard (Security rules → Rate limiting rules) — e.g. `10 req / 10 s per IP` for `/api/dns`.

## Caching

- **HTML** template — `Cache-Control: public, max-age=3600`
- **JSON API** — `Cache-Control: public, max-age=60` (successful responses)
- **DoH queries** — `cf: { cacheTtl: 60, cacheEverything: true }` (Cloudflare edge cache)
- **MTA-STS policy** — `cf: { cacheTtl: 300 }`

## Deployment

```bash
npx wrangler deploy worker.js
```

## Technologies

- [Cloudflare Workers](https://workers.cloudflare.com/) (Modules syntax)
- [DNS-over-HTTPS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/) via `cloudflare-dns.com`
