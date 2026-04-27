// worker.js — v8 (NS + A/AAAA + MX/SPF + DKIM + DMARC + MTA-STS + TLS-RPT + BIMI + DANE/TLSA)
// Cloudflare Worker (Modules syntax). DNS-over-HTTPS: cloudflare-dns.com

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Preflight CORS
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    // Favicon — přesměruj na externí obrázek (s cache), zabrání 404 spamům v logu
    if (url.pathname === "/favicon.ico") {
      return Response.redirect("https://www.lukasberan.cz/img/logo.png", 301);
    }

    if (url.pathname === "/api/dns") {
      const rawName = (url.searchParams.get("name") || "").trim().toLowerCase();

      if (!rawName) return json({ error: "Chybí parametr ?name" }, 400);

      // IDN → A-label (punycode). URL hostname parser udaje automaticky
      // převede unicode jména (např. `lukasberan.cz`) na ASCII (`xn--...`).
      let name;
      try {
        name = new URL(`http://${rawName}`).hostname;
      } catch {
        return json({ error: "Neplatný název domény." }, 400);
      }
      if (!isValidDomain(name)) {
        return json({ error: "Neplatný název domény." }, 400);
      }

      const baseTypes = ["NS", "A", "AAAA", "MX", "TXT"];
      const results = {};

      await Promise.all(
        baseTypes.map(async (type) => {
          results[type] = await dohQuery(name, type);
        })
      );

      // SPF (z TXT)
      const spf = (results.TXT?.answers || [])
        .map((rr) => normalizeTxt(rr.data))
        .filter((txt) => /(^|\s)v=spf1\b/i.test(txt));

      // Email-security queries (paralelně)
      // RFC 7505: "null MX" (preference 0, exchange ".") — doména explicitně nepřijímá mail.
      const mxHosts = (results.MX?.answers || [])
        .map((r) => r.exchange)
        .filter((h) => h && h !== "." && h !== "");

      const [dmarcQ, mtaStsQ, tlsRptQ, bimiQ, dkim1Q, dkim2Q, mtaStsPolicy, ...tlsaResults] =
        await Promise.all([
          dohQuery(`_dmarc.${name}`, "TXT"),
          dohQuery(`_mta-sts.${name}`, "TXT"),
          dohQuery(`_smtp._tls.${name}`, "TXT"),
          dohQuery(`default._bimi.${name}`, "TXT"),
          dohQuery(`selector1._domainkey.${name}`, "CNAME"),
          dohQuery(`selector2._domainkey.${name}`, "CNAME"),
          fetchMtaStsPolicy(name),
          ...mxHosts.map((mx) => dohQuery(`_25._tcp.${mx}`, "TLSA")),
        ]);

      const dmarc = (dmarcQ.answers || [])
        .map((rr) => normalizeTxt(rr.data))
        .filter((txt) => /^v=DMARC1\b/i.test(txt));

      const mtaSts = (mtaStsQ.answers || [])
        .map((rr) => normalizeTxt(rr.data))
        .filter((txt) => /^v=STSv1\b/i.test(txt));

      const tlsRpt = (tlsRptQ.answers || [])
        .map((rr) => normalizeTxt(rr.data))
        .filter((txt) => /^v=TLSRPTv1\b/i.test(txt));

      const bimi = (bimiQ.answers || [])
        .map((rr) => normalizeTxt(rr.data))
        .filter((txt) => /^v=BIMI1\b/i.test(txt));

      const dkim = [
        { selector: "selector1", records: dkim1Q.answers || [] },
        { selector: "selector2", records: dkim2Q.answers || [] },
      ];

      const dane = mxHosts.map((mx, i) => ({
        mx,
        tlsa: tlsaResults[i]?.answers || [],
        // DANE bez DNSSEC nemá smysl — propagujeme AD bit z DoH odpovědi
        dnssec: !!tlsaResults[i]?.ad,
        status: tlsaResults[i]?.status,
      }));

      // Null MX detekce (RFC 7505)
      const nullMx = (results.MX?.answers || []).some(
        (r) => r.preference === 0 && (r.exchange === "." || r.exchange === "")
      );

      return json({
        domain: name,
        ns: results.NS?.answers || [],
        a: results.A?.answers || [],
        aaaa: results.AAAA?.answers || [],
        mx: results.MX?.answers || [],
        nullMx,
        spf,
        dkim,
        dmarc,
        mtaSts,
        mtaStsPolicy,
        tlsRpt,
        bimi,
        dane,
        // Souhrn DNSSEC stavu pro základní dotazy (AD bit z DoH)
        dnssec: {
          ns: !!results.NS?.ad,
          a: !!results.A?.ad,
          aaaa: !!results.AAAA?.ad,
          mx: !!results.MX?.ad,
          txt: !!results.TXT?.ad,
          dmarc: !!dmarcQ.ad,
          mtaStsTxt: !!mtaStsQ.ad,
          tlsRpt: !!tlsRptQ.ad,
          bimi: !!bimiQ.ad,
        },
        // Stavy DoH (3 = NXDOMAIN, 2 = SERVFAIL, 0 = OK)
        status: {
          ns: results.NS?.status,
          a: results.A?.status,
          aaaa: results.AAAA?.status,
          mx: results.MX?.status,
          txt: results.TXT?.status,
          dmarc: dmarcQ.status,
          mtaStsTxt: mtaStsQ.status,
          tlsRpt: tlsRptQ.status,
          bimi: bimiQ.status,
        },
      });
    }

    // Root page – UI
    return new Response(HTML, { headers: htmlHeaders() });
  },
};

// ---------- Validation ----------

function isValidDomain(name) {
  if (!name || name.length > 253) return false;
  // Trailing dot tolerated, then trimmed for label check
  const n = name.endsWith(".") ? name.slice(0, -1) : name;
  const label = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/i;
  const labels = n.split(".");
  if (labels.length < 2) return false;
  return labels.every((l) => label.test(l));
}

// ---------- Headers ----------

function corsHeaders() {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, OPTIONS",
    "access-control-allow-headers": "content-type",
    "access-control-max-age": "86400",
  };
}

function securityHeaders() {
  return {
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
  };
}

function htmlHeaders() {
  return {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "public, max-age=3600",
    "content-security-policy":
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: https://www.lukasberan.cz; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "x-frame-options": "DENY",
    ...securityHeaders(),
  };
}

// DNS-over-HTTPS JSON dotaz na cloudflare-dns.com
// `do=1` — žádáme, aby resolver vrátil AD (Authenticated Data) bit pro DNSSEC.
async function dohQuery(qname, type) {
  const endpoint =
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(qname)}` +
    `&type=${encodeURIComponent(type)}&do=1`;
  const res = await fetch(endpoint, {
    headers: { Accept: "application/dns-json" },
    cf: { cacheTtl: 60, cacheEverything: true },
  });
  if (!res.ok) return { error: `DoH ${type} ${res.status}` };
  const data = await res.json();
  const answers = (data.Answer || [])
    // Filtrujeme RRSIG (typ 46) — nezobrazujeme syrové podpisy v UI
    .filter((a) => a.type !== 46)
    .map((a) => simplifyAnswer(type, a));
  return {
    status: data.Status,
    ad: !!data.AD,
    nxdomain: data.Status === 3,
    answers,
  };
}

async function fetchMtaStsPolicy(domain) {
  // Defense-in-depth: domain is already validated, but re-check before use in URL
  if (!isValidDomain(domain)) return { found: false, error: "invalid domain" };

  const MAX_BYTES = 64 * 1024; // RFC 8461: policy SHOULD be <= 64KB
  const TIMEOUT_MS = 5000;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(
      `https://mta-sts.${domain}/.well-known/mta-sts.txt`,
      {
        headers: { Accept: "text/plain" },
        // RFC 8461 §3.3: HTTP redirects MUST NOT be followed when fetching policy
        redirect: "error",
        signal: ctrl.signal,
        cf: { cacheTtl: 300, cacheEverything: true },
      }
    );
    if (!res.ok) return { found: false };

    const ct = (res.headers.get("content-type") || "").toLowerCase();
    if (!ct.startsWith("text/plain")) {
      return { found: false, error: "unexpected content-type" };
    }

    const buf = await res.arrayBuffer();
    if (buf.byteLength > MAX_BYTES) {
      return { found: false, error: "policy too large" };
    }
    const raw = new TextDecoder("utf-8", { fatal: false }).decode(buf);

    const policy = {};
    for (const line of raw.split(/\r?\n/)) {
      const m = /^(\w+)\s*:\s*(.+)$/.exec(line.trim());
      if (m) {
        const key = m[1].toLowerCase();
        if (key === "mx") {
          (policy.mx || (policy.mx = [])).push(m[2].trim());
        } else {
          policy[key] = m[2].trim();
        }
      }
    }
    return { found: true, policy, raw };
  } catch {
    return { found: false };
  } finally {
    clearTimeout(timer);
  }
}

function simplifyAnswer(type, a) {
  if (type === "MX") {
    const m = /^([0-9]+)\s+(.+)$/.exec(a.data);
    if (m) return { preference: Number(m[1]), exchange: trimDot(m[2]), ttl: a.TTL };
  }
  if (type === "TLSA") {
    const p = (a.data || "").trim().split(/\s+/);
    if (p.length < 4) {
      // Poškozená / nekompletní TLSA data — vrať raw payload pro debug
      return { error: "malformed TLSA", raw: a.data, ttl: a.TTL };
    }
    return {
      usage: Number(p[0]),
      selector: Number(p[1]),
      matchingType: Number(p[2]),
      certData: p.slice(3).join(""),
      ttl: a.TTL,
    };
  }
  if (type === "TXT") return { data: a.data, ttl: a.TTL };
  return { data: trimDot(a.data), ttl: a.TTL };
}

function trimDot(s) {
  return typeof s === "string" && s.endsWith(".") ? s.slice(0, -1) : s;
}

// Normalizuje DoH TXT data:
// DoH JSON vrací více-stringový TXT jako sekvenci uvozovaných řetězců
// oddělených mezerou, např. `"v=spf1 ..." "include:_spf.example.com ~all"`.
// Uvnitř mohou být escapované znaky (\" a \\). Pokud vstup neobsahuje
// žádné uvozovky, vrátíme ho beze změny (některé resolvery vrací plain text).
function normalizeTxt(txt) {
  if (!txt) return "";
  if (!txt.includes('"')) return txt;
  let out = "";
  const re = /"((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = re.exec(txt)) !== null) {
    out += m[1].replace(/\\(.)/g, "$1");
  }
  return out;
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": status === 200 ? "public, max-age=60" : "no-store",
      ...corsHeaders(),
      ...securityHeaders(),
    },
  });
}

// ---------- HTML šablona (inline UI) ----------

const HTML = `<!doctype html>
<html lang="cs">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex, nofollow" />
  <title>DNS Lookup Tool</title>
  <link rel="icon" type="image/png" href="https://www.lukasberan.cz/img/logo.png" />
  <style>
    :root { --bg:#0b1020; --card:#121934; --muted:#8aa0ff; --text:#e7ecff; --accent:#6ea2ff; }
    *{ box-sizing:border-box; }
    body{ margin:0; font-family: ui-sans-serif,system-ui,Segoe UI,Roboto,Helvetica,Arial; background:linear-gradient(120deg,#0b1020,#0d1b3a); color:var(--text); min-height:100vh; display:grid; place-items:center; padding:24px; }
    .wrap{ width:100%; max-width:980px; }
    .card{ background:linear-gradient(180deg,rgba(255,255,255,0.04),rgba(255,255,255,0.02)); border:1px solid rgba(255,255,255,0.08); backdrop-filter: blur(8px); border-radius:20px; padding:24px; box-shadow:0 10px 30px rgba(0,0,0,0.35); }
    h1{ margin:0 0 12px; font-size:28px; letter-spacing:.2px; }
    p{ margin:0 0 18px; color:#c8d1ff; }
    form{ display:flex; gap:12px; flex-wrap:wrap; }
    input[type=text]{ flex:1 1 320px; padding:12px 14px; border-radius:12px; border:1px solid rgba(255,255,255,0.15); background:#0e1630; color:var(--text); outline:none; font-size:16px; }
    button{ padding:12px 16px; border-radius:12px; border:0; background:linear-gradient(135deg,#5d8bff,#6ae3ff); color:#0c1224; font-weight:700; cursor:pointer; }
    .muted{ color:#9fb1ff; font-size:14px; }
    .grid{ display:grid; grid-template-columns: 1fr; gap:16px; margin-top:18px; }
    @media(min-width:980px){ .grid{ grid-template-columns: repeat(2, 1fr);} }
    .panel{ background:var(--card); border:1px solid rgba(255,255,255,0.08); border-radius:16px; padding:16px; }
    .panel h3{ margin:0 0 8px; font-size:16px; color:var(--muted); }
    ul{ margin:0; padding-left:20px; }
    li{ margin:4px 0; }
    .footer{ margin-top:16px; font-size:12px; color:#95a3ff; opacity:.9; }
    code{ background:#0e1630; padding:2px 6px; border-radius:6px; word-break:break-all; }
    .err{ color:#ffb0b0; }
    .rowspan{ grid-column: 1 / -1; }
    a{ color:#c8d1ff; text-decoration: none; }
    .badge{ display:inline-block; padding:2px 8px; border-radius:6px; font-size:12px; font-weight:600; margin-left:8px; }
    .badge-warn{ background:rgba(255,200,80,0.18); color:#ffd166; }
    .badge-ok{ background:rgba(92,255,138,0.15); color:#5cff8a; }
    .badge-err{ background:rgba(255,107,107,0.15); color:#ff6b6b; }
    .notice{ margin:8px 0; padding:10px 12px; border-radius:10px; font-size:13px; }
    .notice-warn{ background:rgba(255,200,80,0.10); border:1px solid rgba(255,200,80,0.35); color:#ffd166; }
    .notice-err{ background:rgba(255,107,107,0.10); border:1px solid rgba(255,107,107,0.35); color:#ffb0b0; }
    .section-title{ font-size:13px; color:#7b8ec9; text-transform:uppercase; letter-spacing:1px; margin:20px 0 4px; grid-column:1/-1; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>DNS lookup</h1>
      <p class="muted">NS, A, AAAA, MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI a DANE/TLSA.</p>
      <form id="f">
        <input id="name" type="text" inputmode="url" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="lukasberan.cz" required />
        <button type="submit">Vyhledat</button>
      </form>

      <div id="out" class="grid"></div>
      <div class="footer">Powered by Cloudflare Workers | Pro DNS dotazy používá DNS-over-HTTPS na <code>cloudflare-dns.com</code> | Vytvořil <a href="https://www.lukasberan.cz/"><strong>Lukáš Beran</strong></a></div>
    </div>
  </div>

  <script>
    const f = document.getElementById('f');
    const nameEl = document.getElementById('name');
    const out = document.getElementById('out');

    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      out.innerHTML = '<p class="muted">Dotazuji DNS…</p>';
      const name = nameEl.value.trim();
      try {
        const url = '/api/dns?name=' + encodeURIComponent(name);
        const res = await fetch(url);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Neznámá chyba');
        render(data);
      } catch (err) {
        out.innerHTML = '<p class="err">' + err.message + '</p>';
      }
    });

    const TLSA_USAGE = ['PKIX-TA (0)','PKIX-EE (1)','DANE-TA (2)','DANE-EE (3)'];
    const TLSA_SEL  = ['Full cert (0)','SPKI (1)'];
    const TLSA_MATCH = ['Exact (0)','SHA-256 (1)','SHA-512 (2)'];

    function badge(ok, yes, no) {
      return ok
        ? '<span class="badge badge-ok">' + yes + '</span>'
        : '<span class="badge badge-err">' + no + '</span>';
    }

    function badgeWarn(text) {
      return '<span class="badge badge-warn">' + text + '</span>';
    }

    function panel(title, items, full) {
      return '<div class="panel' + (full ? ' rowspan' : '') + '"><h3>' + title + '</h3><ul>' + items + '</ul></div>';
    }

    function li(arr, fn) {
      if (!arr || !arr.length) return '<li>—</li>';
      return arr.map(r => '<li>' + fn(r) + '</li>').join('');
    }

    function ttl(r) { return ' <span class="muted">(TTL ' + r.ttl + 's)</span>'; }

    function esc(s){
      return ('' + s).replace(/[&<>"']/g, function(c){ return ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]); });
    }

    function render(data){
      const d = data.domain;
      const st = data.status || {};
      const ds = data.dnssec || {};

      // NXDOMAIN — doména neexistuje (NS dotaz vrátil status 3)
      if (st.ns === 3) {
        out.innerHTML = '<div class="notice notice-err rowspan">Doména <code>' + esc(d) + '</code> neexistuje (NXDOMAIN).</div>';
        return;
      }

      const ns   = li(data.ns, r => esc(r.data) + ttl(r));
      const a    = li(data.a, r => esc(r.data) + ttl(r));
      const aaaa = li(data.aaaa, r => esc(r.data) + ttl(r));
      const mx   = li((data.mx||[]).sort((x,y)=>(x.preference||0)-(y.preference||0)),
                       r => r.preference + ' ' + esc(r.exchange || '.') + ttl(r));
      const spf   = li(data.spf, s => '<code>' + esc(s) + '</code>');
      const dmarc = li(data.dmarc, s => '<code>' + esc(s) + '</code>');
      const mtaSts = li(data.mtaSts, s => '<code>' + esc(s) + '</code>');
      const tlsRpt = li(data.tlsRpt, s => '<code>' + esc(s) + '</code>');
      const bimi   = li(data.bimi, s => '<code>' + esc(s) + '</code>');

      // DKIM (Exchange Online selectors)
      let dkimHtml = '<li>—</li>';
      if (data.dkim && data.dkim.length > 0) {
        let dkItems = '';
        data.dkim.forEach(sel => {
          const name = sel.selector + '._domainkey.' + d;
          if (sel.records.length === 0) {
            dkItems += '<li><code>' + esc(name) + '</code> — nenalezen</li>';
          } else {
            sel.records.forEach(r => {
              dkItems += '<li><code>' + esc(name) + '</code> → <code>' + esc(r.data) + '</code>' + ttl(r) + '</li>';
            });
          }
        });
        dkimHtml = dkItems;
      }

      // MTA-STS Policy
      let mtaStsPol = '<li>—</li>';
      const pol = data.mtaStsPolicy;
      if (pol && pol.found && pol.policy) {
        const p = pol.policy;
        let items = '';
        if (p.version) items += '<li>version: <code>' + esc(p.version) + '</code></li>';
        if (p.mode) items += '<li>mode: <code>' + esc(p.mode) + '</code></li>';
        if (p.max_age) items += '<li>max_age: <code>' + esc(p.max_age) + '</code></li>';
        if (p.mx) p.mx.forEach(m => { items += '<li>mx: <code>' + esc(m) + '</code></li>'; });
        mtaStsPol = items || '<li>—</li>';
      }

      // DANE/TLSA
      let daneHtml = '<li>—</li>';
      if (data.dane && data.dane.length > 0) {
        let ditems = '';
        data.dane.forEach(entry => {
          const dnssecBadge = entry.tlsa.length
            ? (entry.dnssec ? badge(true, 'DNSSEC OK', '') : badgeWarn('DNSSEC chybí — TLSA nedůvěryhodné'))
            : '';
          if (entry.tlsa.length === 0) {
            ditems += '<li><strong>' + esc(entry.mx) + '</strong> — žádný TLSA záznam</li>';
          } else {
            entry.tlsa.forEach(t => {
              if (t.error) {
                ditems += '<li><strong>' + esc(entry.mx) + '</strong> ' + dnssecBadge
                  + ' — neplatná TLSA data: <code>' + esc(t.raw || '') + '</code>' + ttl(t) + '</li>';
                return;
              }
              ditems += '<li><strong>' + esc(entry.mx) + '</strong> ' + dnssecBadge + ': '
                + (TLSA_USAGE[t.usage] || t.usage) + ', '
                + (TLSA_SEL[t.selector] || t.selector) + ', '
                + (TLSA_MATCH[t.matchingType] || t.matchingType)
                + '<br><code>' + esc(t.certData) + '</code>'
                + ttl(t) + '</li>';
            });
          }
        });
        daneHtml = ditems;
      }

      const nullMxNotice = data.nullMx
        ? '<div class="notice notice-warn rowspan">Doména deklaruje <strong>null MX</strong> (RFC 7505) — explicitně nepřijímá e-mail.</div>'
        : '';

      out.innerHTML =
        panel('NS' + (ds.ns ? badge(true,'DNSSEC','') : ''), ns, true) +
        panel('A', a) + panel('AAAA', aaaa) +
        panel('MX', mx) +
        nullMxNotice +
        panel('SPF (TXT)' + badge(data.spf && data.spf.length, 'OK', 'Chybí') + (data.spf && data.spf.length > 1 ? badgeWarn('Více SPF záznamů — chyba konfigurace') : ''), spf) +
        '<div class="section-title">Zabezpečení e-mailu</div>' +
        panel('DKIM — Exchange Online' + badge(data.dkim && data.dkim.some(d2 => d2.records.length), 'OK', 'Chybí'), dkimHtml, true) +
        panel('DMARC (_dmarc.' + esc(d) + ')' + badge(data.dmarc && data.dmarc.length, 'OK', 'Chybí') + (data.dmarc && data.dmarc.length > 1 ? badgeWarn('Více DMARC záznamů') : ''), dmarc, true) +
        panel('MTA-STS TXT (_mta-sts.' + esc(d) + ')' + badge(data.mtaSts && data.mtaSts.length, 'OK', 'Chybí') + (data.mtaSts && data.mtaSts.length > 1 ? badgeWarn('Více MTA-STS záznamů') : ''), mtaSts) +
        panel('MTA-STS Policy' + badge(pol && pol.found, 'OK', 'Chybí'), mtaStsPol) +
        panel('TLS-RPT (_smtp._tls.' + esc(d) + ')' + badge(data.tlsRpt && data.tlsRpt.length, 'OK', 'Chybí') + (data.tlsRpt && data.tlsRpt.length > 1 ? badgeWarn('Více TLS-RPT záznamů') : ''), tlsRpt) +
        panel('BIMI (default._bimi.' + esc(d) + ')' + badge(data.bimi && data.bimi.length, 'OK', 'Chybí'), bimi) +
        panel('DANE / TLSA' + badge(data.dane && data.dane.some(e => e.tlsa.length), 'OK', 'Chybí') + (data.dane && data.dane.some(e => e.tlsa.length && !e.dnssec) ? badgeWarn('Bez DNSSEC') : ''), daneHtml, true);
    }
  </script>
</body>
</html>`;
