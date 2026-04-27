# DNS Lookup Tool

Cloudflare Worker pro komplexní DNS analýzu domény s důrazem na zabezpečení e-mailu a DNSSEC validaci.

## Funkce

### Základní DNS záznamy
- **NS** — nameservery domény
- **A / AAAA** — IPv4 a IPv6 adresy
- **MX** — mail exchange záznamy (seřazené podle priority)
- **SPF** — Sender Policy Framework (extrahováno z TXT)
- Detekce **null MX** (RFC 7505) — doména explicitně nepřijímá e-mail
- **IDN** podpora — unicode domény (např. `háčkydomény.cz`) jsou automaticky převedeny na A-label (punycode)

### Zabezpečení e-mailu
| Záznam | DNS dotaz | Popis |
|---|---|---|
| **DKIM** | `selector1._domainkey.<domain>`, `selector2._domainkey.<domain>` | DKIM CNAME záznamy pro Exchange Online |
| **DMARC** | `_dmarc.<domain>` | Domain-based Message Authentication |
| **MTA-STS TXT** | `_mta-sts.<domain>` | MTA Strict Transport Security identifikátor |
| **MTA-STS Policy** | `https://mta-sts.<domain>/.well-known/mta-sts.txt` | Stažení a parsování MTA-STS policy (mode, max_age, mx) |
| **TLS-RPT** | `_smtp._tls.<domain>` | SMTP TLS Reporting |
| **BIMI** | `default._bimi.<domain>` | Brand Indicators for Message Identification |
| **DANE / TLSA** | `_25._tcp.<mx-host>` pro každý MX | DNS-based Authentication of Named Entities (s DNSSEC validací) |

### DNSSEC
Každý DoH dotaz používá `do=1` flag a propaguje **AD bit** (Authenticated Data) z odpovědi. UI zobrazuje:
- ✅ DNSSEC validace OK u jednotlivých záznamů
- ⚠️ Varování u **DANE/TLSA bez DNSSEC** (TLSA bez podpisu je nedůvěryhodné)

### Validace konfigurace
UI varuje při běžných chybách konfigurace:
- Více SPF / DMARC / MTA-STS / TLS-RPT záznamů (porušení RFC)
- TLSA záznamy bez DNSSEC validace
- Null MX (informativní)
- NXDOMAIN — celá doména neexistuje

## API

```
GET /api/dns?name=example.com
```

Vrací JSON se všemi výsledky. DNS dotazy probíhají paralelně přes DNS-over-HTTPS (`cloudflare-dns.com`).

### Příklad odpovědi

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

DoH `Status` kódy: `0` = OK, `2` = SERVFAIL, `3` = NXDOMAIN.

### Validace vstupu
- Max 253 znaků celkem, max 63 znaků na label
- Label nesmí začínat ani končit pomlčkou
- Min. 2 labely (TLD + SLD)
- Unicode → punycode přes `URL` parser

### CORS
Endpoint vrací `Access-Control-Allow-Origin: *` a podporuje preflight `OPTIONS`.

## UI

Kořenová cesta (`/`) vrací HTML stránku s vyhledávacím formulářem. Výsledky se zobrazují v panelech s barevnými indikátory:
- 🟢 **OK** — záznam nalezen / DNSSEC validováno
- 🔴 **Chybí** — záznam nenalezen
- 🟡 **Varování** — duplicitní záznam, chybí DNSSEC, null MX apod.

## Bezpečnost

Worker odesílá kompletní sadu bezpečnostních hlaviček:
- `Content-Security-Policy` (script/style `'self' 'unsafe-inline'`, img `'self' data: lukasberan.cz`)
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`

**MTA-STS policy fetch** je zabezpečen proti SSRF / abuse:
- Doména znovu validována před použitím v URL
- 5s timeout (`AbortController`)
- Limit 64 KB (RFC 8461)
- `redirect: "error"` (RFC 8461 §3.3 zakazuje následovat redirecty)
- Kontrola `Content-Type: text/plain`

**Doporučení pro produkční nasazení:**
- Nastav rate limiting v Cloudflare Dashboard (Security rules → Rate limiting rules) — např. `10 req / 10 s na IP` pro `/api/dns`.

## Cachování

- **HTML** šablona — `Cache-Control: public, max-age=3600`
- **JSON API** — `Cache-Control: public, max-age=60` (úspěšné odpovědi)
- **DoH dotazy** — `cf: { cacheTtl: 60, cacheEverything: true }` (Cloudflare edge cache)
- **MTA-STS policy** — `cf: { cacheTtl: 300 }`

## Nasazení

```bash
npx wrangler deploy worker.js
```

## Technologie

- [Cloudflare Workers](https://workers.cloudflare.com/) (Modules syntax)
- [DNS-over-HTTPS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/) via `cloudflare-dns.com`
