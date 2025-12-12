// worker.js — v6 (NS + A/AAAA + MX/SPF + DMARC) — bez DKIM, bez CAA
// Cloudflare Worker (Modules syntax). DNS-over-HTTPS: cloudflare-dns.com

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/api/dns") {
      const name = (url.searchParams.get("name") || "").trim();

      if (!name) return json({ error: "Chybí parametr ?name" }, 400);
      if (!/^([A-Za-z0-9-]+\.)+[A-Za-z0-9-]{2,}$/.test(name)) {
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

      // DMARC: _dmarc.<domain> TXT
      const dmarcQ = await dohQuery(`_dmarc.${name}`, "TXT");
      const dmarc = (dmarcQ.answers || [])
        .map((rr) => normalizeTxt(rr.data))
        .filter((txt) => /^v=DMARC1\b/i.test(txt));

      return json({
        domain: name,
        ns: results.NS?.answers || [],
        a: results.A?.answers || [],
        aaaa: results.AAAA?.answers || [],
        mx: results.MX?.answers || [],
        spf,
        dmarc,
      });
    }

    // Root page – UI
    return new Response(renderHtml(), {
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  },
};

// DNS-over-HTTPS JSON dotaz na cloudflare-dns.com
async function dohQuery(qname, type) {
  const endpoint = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(
    qname
  )}&type=${encodeURIComponent(type)}`;
  const res = await fetch(endpoint, { headers: { Accept: "application/dns-json" } });
  if (!res.ok) return { error: `DoH ${type} ${res.status}` };
  const data = await res.json();
  const answers = (data.Answer || []).map((a) => simplifyAnswer(type, a));
  return { status: data.Status, answers };
}

function simplifyAnswer(type, a) {
  if (type === "MX") {
    const m = /^([0-9]+)\s+(.+)$/.exec(a.data);
    if (m) return { preference: Number(m[1]), exchange: trimDot(m[2]), ttl: a.TTL };
  }
  if (type === "TXT") return { data: a.data, ttl: a.TTL };
  return { data: trimDot(a.data), ttl: a.TTL };
}

function trimDot(s) {
  return typeof s === "string" && s.endsWith(".") ? s.slice(0, -1) : s;
}

function normalizeTxt(txt) {
  return (txt || "").replace(/^"|"$/g, "");
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function renderHtml() {
  return `<!doctype html>
<html lang="cs">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DNS Lookup Tool</title>
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
    code{ background:#0e1630; padding:2px 6px; border-radius:6px; }
    .err{ color:#ffb0b0; }
    .rowspan{ grid-column: 1 / -1; }
    a{ margin:0 0 18px; color:#c8d1ff; text-decoration: none; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>DNS lookup</h1>
      <p class="muted">NS, A, AAAA, MX, SPF a DMARC.</p>
      <form id="f">
        <input id="name" type="text" placeholder="lukasberan.cz" required />
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

    function render(data){
      const ns   = (data.ns||[]).map(r => '<li>' + escapeHtml(r.data) + ' <span class="muted">(TTL ' + r.ttl + 's)</span></li>').join('') || '<li>—</li>';
      const a    = (data.a||[]).map(r => '<li>' + escapeHtml(r.data) + ' <span class="muted">(TTL ' + r.ttl + 's)</span></li>').join('') || '<li>—</li>';
      const aaaa = (data.aaaa||[]).map(r => '<li>' + escapeHtml(r.data) + ' <span class="muted">(TTL ' + r.ttl + 's)</span></li>').join('') || '<li>—</li>';
      const mx   = (data.mx||[]).sort((x,y)=> (x.preference||0)-(y.preference||0)).map(r => '<li>' + r.preference + ' ' + escapeHtml(r.exchange) + ' <span class="muted">(TTL ' + r.ttl + 's)</span></li>').join('') || '<li>—</li>';
      const spf  = (data.spf||[]).map(s => '<li><code>' + escapeHtml(s) + '</code></li>').join('') || '<li>—</li>';
      const dmarc = (data.dmarc||[]).map(s => '<li><code>' + escapeHtml(s) + '</code></li>').join('') || '<li>—</li>';

      out.innerHTML =
        // 1. řada: NS přes celou šířku
        '<div class="panel rowspan"><h3>NS</h3><ul>' + ns + '</ul></div>' +
        // 2. řada: A + AAAA
        '<div class="panel"><h3>A</h3><ul>' + a + '</ul></div>' +
        '<div class="panel"><h3>AAAA</h3><ul>' + aaaa + '</ul></div>' +
        // 3. řada: MX + SPF
        '<div class="panel"><h3>MX</h3><ul>' + mx + '</ul></div>' +
        '<div class="panel"><h3>SPF (TXT)</h3><ul>' + spf + '</ul></div>' +
        // 4. řada: DMARC přes celou šířku
        '<div class="panel rowspan"><h3>DMARC (_dmarc.' + escapeHtml(data.domain) + ')</h3><ul>' + dmarc + '</ul></div>';
    }

    function escapeHtml(s){
      return ('' + s).replace(/[&<>\\"]/g, function(c){ return ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]); });
    }
  </script>
</body>
</html>`;
}
