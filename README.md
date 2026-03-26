# DNS Lookup Tool

Cloudflare Worker pro komplexní DNS analýzu domény s důrazem na zabezpečení e-mailu.

## Funkce

### Základní DNS záznamy
- **NS** — nameservery domény
- **A / AAAA** — IPv4 a IPv6 adresy
- **MX** — mail exchange záznamy (seřazené podle priority)
- **SPF** — Sender Policy Framework (extrahováno z TXT)

### Zabezpečení e-mailu
| Záznam | DNS dotaz | Popis |
|---|---|---|
| **DKIM** | `selector1._domainkey.<domain>`, `selector2._domainkey.<domain>` | DKIM CNAME záznamy pro Exchange Online |
| **DMARC** | `_dmarc.<domain>` | Domain-based Message Authentication |
| **MTA-STS TXT** | `_mta-sts.<domain>` | MTA Strict Transport Security identifikátor |
| **MTA-STS Policy** | `https://mta-sts.<domain>/.well-known/mta-sts.txt` | Stažení a parsování MTA-STS policy (mode, max_age, mx) |
| **TLS-RPT** | `_smtp._tls.<domain>` | SMTP TLS Reporting |
| **BIMI** | `default._bimi.<domain>` | Brand Indicators for Message Identification |
| **DANE / TLSA** | `_25._tcp.<mx-host>` pro každý MX | DNS-based Authentication of Named Entities |

## API

```
GET /api/dns?name=example.com
```

Vrací JSON se všemi výsledky. Všechny DNS dotazy probíhají paralelně přes DNS-over-HTTPS (`cloudflare-dns.com`).

### Příklad odpovědi

```json
{
  "domain": "example.com",
  "ns": [{ "data": "ns1.example.com", "ttl": 3600 }],
  "a": [{ "data": "93.184.216.34", "ttl": 300 }],
  "aaaa": [],
  "mx": [{ "preference": 10, "exchange": "mail.example.com", "ttl": 3600 }],
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
  "dane": [{ "mx": "mail.example.com", "tlsa": [] }]
}
```

## UI

Kořenová cesta (`/`) vrací HTML stránku s vyhledávacím formulářem. Výsledky se zobrazují v panelech s barevnými indikátory:
- 🟢 **OK** — záznam nalezen
- 🔴 **Chybí** — záznam nenalezen

## Nasazení

```bash
npx wrangler deploy worker.js
```

## Technologie

- [Cloudflare Workers](https://workers.cloudflare.com/) (Modules syntax)
- [DNS-over-HTTPS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/) via `cloudflare-dns.com`
