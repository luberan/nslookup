// DNS Lookup Tool — Cloudflare Worker (Modules syntax).
// DNS-over-HTTPS resolver: cloudflare-dns.com
// See README.md for the full list of records and the API contract.

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Preflight CORS
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    // Favicon — redirect to an external image (with cache); avoids 404 spam in the log
    if (url.pathname === "/favicon.ico") {
      return Response.redirect("https://www.lukasberan.cz/img/logo.png", 301);
    }

    if (url.pathname === "/api/dns") {
      // Only GET is meaningful for this read-only endpoint (OPTIONS handled above).
      if (request.method !== "GET") {
        return json({ error: "Method not allowed. Use GET." }, 405, { allow: "GET, OPTIONS" });
      }

      const rawName = (url.searchParams.get("name") || "").trim();

      if (!rawName) return json({ error: "Missing ?name parameter" }, 400);

      const name = normalizeDomain(rawName);
      if (!name) {
        return json({ error: "Invalid domain name." }, 400);
      }

      // Optional custom DKIM selectors (comma-separated). Defaults to the
      // Microsoft 365 selectors. Validated & capped to bound subrequests.
      const rawSelectors = (url.searchParams.get("selectors") || "").trim();
      const dkimSelectors = parseDkimSelectors(rawSelectors);
      if (dkimSelectors === null) {
        return json({ error: "Invalid DKIM selector(s)." }, 400);
      }
      const dkimCustom = rawSelectors !== "";

      const baseTypes = ["NS", "A", "AAAA", "MX", "TXT"];
      const results = {};

      await Promise.all(
        baseTypes.map(async (type) => {
          results[type] = await dohQuery(name, type);
        })
      );

      if (baseTypes.every((type) => results[type].error)) {
        return json({
          error: "DNS resolver lookup failed.",
          details: Object.fromEntries(
            baseTypes.map((type) => [type.toLowerCase(), results[type].error])
          ),
        }, 502);
      }

      // SPF (from TXT)
      const spf = (results.TXT?.answers || [])
        .map((rr) => normalizeTxt(rr.data))
        .filter((txt) => /(^|\s)v=spf1\b/i.test(txt));

      // Email-security queries (in parallel)
      // RFC 7505: "null MX" (preference 0, exchange ".") — domain explicitly does not accept mail.
      // De-duplicate and cap the MX list: bounds the number of parallel TLSA
      // subrequests (Workers subrequest limit) and avoids the worker being
      // abused as a traffic-reflection amplifier toward many MX hosts.
      const mxHosts = [...new Set(
        (results.MX?.answers || [])
          .map((r) => r.exchange)
          .filter((h) => h && h !== "." && h !== "")
      )].slice(0, 20);

      // DKIM: query each selector as both CNAME (Microsoft 365 delegation)
      // and TXT (most other providers publish the key directly as TXT).
      const dkimJobs = dkimSelectors.flatMap((sel) => [
        dohQuery(`${sel}._domainkey.${name}`, "CNAME"),
        dohQuery(`${sel}._domainkey.${name}`, "TXT"),
      ]);
      const tlsaJobs = mxHosts.map((mx) => dohQuery(`_25._tcp.${mx}`, "TLSA"));

      const [dmarcQ, mtaStsQ, tlsRptQ, bimiQ, ...rest] =
        await Promise.all([
          dohQuery(`_dmarc.${name}`, "TXT"),
          dohQuery(`_mta-sts.${name}`, "TXT"),
          dohQuery(`_smtp._tls.${name}`, "TXT"),
          dohQuery(`default._bimi.${name}`, "TXT"),
          ...dkimJobs,
          ...tlsaJobs,
        ]);
      // Two variable-length tails share one Promise.all — split by job count.
      const dkimRes = rest.slice(0, dkimJobs.length);
      const tlsaResults = rest.slice(dkimJobs.length);

      const dmarc = (dmarcQ.answers || [])
        .map((rr) => normalizeTxt(rr.data))
        .filter((txt) => /^v=DMARC1\b/i.test(txt));

      const mtaStsRecords = (mtaStsQ.answers || []).map((rr) => normalizeTxt(rr.data));
      const mtaSts = mtaStsRecords.filter((txt) => /^v=STSv1(?:\s*;|$)/.test(txt));
      const mtaStsValidation = validateMtaStsTxt(mtaStsRecords);
      const mtaStsPolicy = mtaStsQ.error
        ? {
            found: false,
            valid: false,
            skipped: true,
            reason: `MTA-STS TXT lookup failed: ${mtaStsQ.error}`,
          }
        : mtaStsValidation.valid
          ? await fetchMtaStsPolicy(name)
          : {
              found: false,
              valid: false,
              skipped: true,
              reason: `policy not fetched: ${mtaStsValidation.reason}`,
            };

      const tlsRpt = (tlsRptQ.answers || [])
        .map((rr) => normalizeTxt(rr.data))
        .filter((txt) => /^v=TLSRPTv1\b/i.test(txt));

      const bimi = (bimiQ.answers || [])
        .map((rr) => normalizeTxt(rr.data))
        .filter((txt) => /^v=BIMI1\b/i.test(txt));

      const dkim = dkimSelectors.map((selector, i) => {
        const cnameQ = dkimRes[i * 2] || {};
        const txtQ = dkimRes[i * 2 + 1] || {};
        const cname = cnameQ.answers || [];
        const txt = (txtQ.answers || [])
          .map((rr) => ({ data: normalizeTxt(rr.data), ttl: rr.ttl }))
          // Keep only TXT that looks like a DKIM key, not the CNAME-chain
          // hostname a TXT query also returns for delegated (M365) selectors.
          .filter((rr) => /(^|;|\s)(v=DKIM1|k=|p=)/i.test(rr.data));
        return {
          selector,
          cname,
          txt,
          dnssec: { cname: !!cnameQ.ad, txt: !!txtQ.ad },
          status: { cname: cnameQ.status ?? null, txt: txtQ.status ?? null },
          errors: { cname: cnameQ.error || null, txt: txtQ.error || null },
        };
      });

      const dane = mxHosts.map((mx, i) => ({
        mx,
        tlsa: tlsaResults[i]?.answers || [],
        // DANE without DNSSEC is meaningless — propagate the AD bit from the DoH response
        dnssec: !!tlsaResults[i]?.ad,
        status: tlsaResults[i]?.status ?? null,
        error: tlsaResults[i]?.error || null,
      }));

      // Null MX detection (RFC 7505)
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
        dkimCustom,
        dmarc,
        mtaSts,
        mtaStsValidation,
        mtaStsPolicy,
        tlsRpt,
        bimi,
        dane,
        // Summary of DNSSEC status for the basic queries (AD bit from DoH)
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
        // DoH status codes (3 = NXDOMAIN, 2 = SERVFAIL, 0 = OK)
        status: {
          ns: results.NS?.status ?? null,
          a: results.A?.status ?? null,
          aaaa: results.AAAA?.status ?? null,
          mx: results.MX?.status ?? null,
          txt: results.TXT?.status ?? null,
          dmarc: dmarcQ.status ?? null,
          mtaStsTxt: mtaStsQ.status ?? null,
          tlsRpt: tlsRptQ.status ?? null,
          bimi: bimiQ.status ?? null,
        },
        errors: {
          ns: results.NS?.error || null,
          a: results.A?.error || null,
          aaaa: results.AAAA?.error || null,
          mx: results.MX?.error || null,
          txt: results.TXT?.error || null,
          dmarc: dmarcQ.error || null,
          mtaStsTxt: mtaStsQ.error || null,
          tlsRpt: tlsRptQ.error || null,
          bimi: bimiQ.error || null,
        },
      });
    }

    // Root page – UI
    return new Response(HTML, { headers: htmlHeaders() });
  },
};

// ---------- Validation ----------

function normalizeDomain(raw) {
  // The URL hostname parser provides IDN -> A-label conversion, but the API
  // accepts a domain only, not URL syntax that could silently change its host.
  if (/[%@/:?#\\\s]/.test(raw)) return null;
  try {
    const hostname = new URL(`http://${raw}`).hostname.toLowerCase().replace(/\.$/, "");
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return null;
    return isValidDomain(hostname) ? hostname : null;
  } catch {
    return null;
  }
}

function isValidDomain(name) {
  if (!name || name.length > 253) return false;
  // Trailing dot tolerated, then trimmed for label check
  const n = name.endsWith(".") ? name.slice(0, -1) : name;
  const label = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/i;
  const labels = n.split(".");
  if (labels.length < 2) return false;
  return labels.every((l) => label.test(l));
}

// Parses the optional `selectors` query param (comma-separated DKIM selectors).
// Returns the Microsoft 365 defaults when empty, null when any selector is
// invalid, otherwise the validated list (deduplicated, capped at 5).
function parseDkimSelectors(raw) {
  const DEFAULTS = ["selector1", "selector2"];
  if (!raw) return DEFAULTS;
  const list = [
    ...new Set(raw.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean)),
  ];
  if (!list.length) return DEFAULTS;
  const label = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/i;
  const valid = list.every(
    (s) => s.length <= 253 && s.split(".").every((l) => label.test(l))
  );
  if (!valid) return null;
  return list.slice(0, 5);
}

function validateMtaStsTxt(records) {
  const found = records.length > 0;
  const candidates = records.filter((record) => /^v=STSv1\s*;/.test(record));
  if (candidates.length !== 1) {
    return {
      found,
      valid: false,
      reason: candidates.length
        ? "multiple valid-version MTA-STS TXT records"
        : "valid-version MTA-STS TXT record not found",
    };
  }

  const record = candidates[0];
  const fields = record.split(";");
  if (fields.at(-1)?.trim() === "") fields.pop();
  if (fields.shift()?.trim() !== "v=STSv1" || fields.some((field) => !field.trim())) {
    return { found: true, valid: false, reason: "invalid MTA-STS TXT syntax", record };
  }

  let id = null;
  for (const rawField of fields) {
    const field = rawField.trim();
    const match = /^([A-Za-z0-9][A-Za-z0-9_.-]{0,31})=([\x21-\x3A\x3C\x3E-\x7E]+)$/.exec(field);
    if (!match) return { found: true, valid: false, reason: "invalid MTA-STS TXT field", record };
    if (match[1] === "id") {
      if (id !== null || !/^[A-Za-z0-9]{1,32}$/.test(match[2])) {
        return { found: true, valid: false, reason: "invalid or duplicate MTA-STS id", record };
      }
      id = match[2];
    }
  }

  return id === null
    ? { found: true, valid: false, reason: "MTA-STS TXT record is missing id", record }
    : { found: true, valid: true, record, id };
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

const DNS_TYPE_CODES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  TLSA: 52,
};

const DNS_STATUS_NAMES = {
  1: "FORMERR",
  2: "SERVFAIL",
  4: "NOTIMP",
  5: "REFUSED",
};

function dnsStatusError(status) {
  if (status === 0 || status === 3) return null;
  return `DNS ${DNS_STATUS_NAMES[status] || `status ${status}`} (${status})`;
}

// DNS-over-HTTPS JSON query against cloudflare-dns.com
// `do=1` — request that the resolver returns the AD (Authenticated Data) bit for DNSSEC.
async function dohQuery(qname, type) {
  const endpoint =
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(qname)}` +
    `&type=${encodeURIComponent(type)}&do=1`;
  try {
    const res = await fetch(endpoint, {
      headers: { Accept: "application/dns-json" },
      cf: { cacheTtl: 60, cacheEverything: true },
    });
    if (!res.ok) {
      return { status: null, ad: false, error: `DoH ${type} HTTP ${res.status}`, answers: [] };
    }
    const data = await res.json();
    if (!Number.isInteger(data.Status) || (data.Answer && !Array.isArray(data.Answer))) {
      throw new Error(`Invalid DoH ${type} response`);
    }
    const answers = (data.Answer || [])
      // A JSON DoH response can include a CNAME chain before the requested
      // records. Keep only the requested RR type so the API shape stays true.
      .filter((answer) => Number(answer.type) === DNS_TYPE_CODES[type])
      .map((a) => simplifyAnswer(type, a));
    return {
      status: data.Status,
      ad: !!data.AD,
      nxdomain: data.Status === 3,
      answers,
      error: dnsStatusError(data.Status),
    };
  } catch (err) {
    // Network / JSON errors must not reject the surrounding Promise.all and
    // turn the whole request into an uncaught 500.
    return {
      status: null,
      ad: false,
      error: err?.message || `DoH ${type} fetch error`,
      answers: [],
    };
  }
}

async function fetchMtaStsPolicy(domain) {
  // Defense-in-depth: domain is already validated, but re-check before use in URL
  if (!isValidDomain(domain)) return { found: false, valid: false, reason: "invalid domain" };

  const MAX_BYTES = 64 * 1024; // RFC 8461: policy SHOULD be <= 64KB
  const TIMEOUT_MS = 5000;
  const policyHost = `mta-sts.${domain}`;
  if (!isValidDomain(policyHost)) {
    return { found: false, valid: false, reason: "MTA-STS policy hostname is too long" };
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  const url = `https://${policyHost}/.well-known/mta-sts.txt`;

  try {
    // RFC 8461 §3.3 forbids following redirects when retrieving an MTA-STS
    // policy. We use `manual` so an attacker-controlled `mta-sts.<domain>`
    // cannot redirect us to an arbitrary target (SSRF / open-proxy hardening);
    // a redirect is reported instead of followed.
    const res = await fetch(url, {
      headers: {
        Accept: "text/plain",
        "User-Agent": "Mozilla/5.0 (compatible; DNSLookupTool/1.0; +https://www.lukasberan.cz/)",
      },
      redirect: "manual",
      signal: ctrl.signal,
      cache: "no-store",
    });

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location") || "";
      return {
        found: false,
        valid: false,
        reason: "policy uses an HTTP redirect (RFC 8461 forbids following it)",
        url,
        redirect: location,
      };
    }

    if (res.status !== 200) {
      return {
        found: res.status >= 200 && res.status < 300,
        valid: false,
        reason: `HTTP ${res.status} (expected 200)`,
        url,
      };
    }

    const ct = (res.headers.get("content-type") || "").toLowerCase();
    const ctOk = ct.split(";", 1)[0].trim() === "text/plain";
    if (!ctOk) {
      return {
        found: true,
        valid: false,
        reason: "invalid Content-Type (expected text/plain)",
        url,
        contentType: ct,
      };
    }

    // Enforce the size cap up front (Content-Length) and again while streaming,
    // so a hostile server can never make us buffer an unbounded body in memory
    // (the previous code read the entire body before checking its size).
    const lenHeader = res.headers.get("content-length");
    if (lenHeader && Number(lenHeader) > MAX_BYTES) {
      return { found: true, valid: false, reason: "policy too large (> 64KB)", url };
    }
    const raw = await readCapped(res, MAX_BYTES);
    if (raw === null) {
      return { found: true, valid: false, reason: "policy too large (> 64KB)", url };
    }

    const parsed = parseMtaStsPolicy(raw);
    if (!parsed.valid) {
      return {
        found: true,
        valid: false,
        reason: parsed.reason,
        url,
        raw,
        contentType: ct,
      };
    }

    return {
      found: true,
      valid: true,
      policy: parsed.policy,
      raw,
      url,
      contentType: ct,
      contentTypeOk: true,
    };
  } catch (err) {
    return {
      found: false,
      valid: false,
      reason: err?.name === "AbortError" ? "timeout" : (err?.message || "fetch error"),
      url,
    };
  } finally {
    clearTimeout(timer);
  }
}

function parseMtaStsPolicy(raw) {
  const lines = raw.split(/\r?\n/);
  if (lines.at(-1) === "") lines.pop();
  if (!lines.length || lines.some((line) => !line)) {
    return { valid: false, reason: "invalid blank line in MTA-STS policy" };
  }

  const policy = Object.create(null);
  for (const line of lines) {
    const match = /^([A-Za-z0-9][A-Za-z0-9_.-]{0,31}):[ \t]*(\S(?:.*\S)?)$/.exec(line);
    if (!match || /[\u0000-\u001f\u007f]/.test(match[2])) {
      return { valid: false, reason: "invalid MTA-STS policy field" };
    }
    const [, key, value] = match;
    if (key === "mx") {
      (policy.mx || (policy.mx = [])).push(value);
    } else if (!Object.hasOwn(policy, key)) {
      policy[key] = value;
    }
  }

  if (policy.version !== "STSv1") {
    return { valid: false, reason: "MTA-STS policy version must be STSv1" };
  }
  if (!new Set(["enforce", "testing", "none"]).has(policy.mode)) {
    return { valid: false, reason: "invalid MTA-STS policy mode" };
  }
  if (!/^\d{1,10}$/.test(policy.max_age || "") || Number(policy.max_age) > 31557600) {
    return { valid: false, reason: "invalid MTA-STS policy max_age" };
  }
  if (policy.mode !== "none" && (!policy.mx || !policy.mx.length)) {
    return { valid: false, reason: "MTA-STS policy requires at least one mx" };
  }
  if ((policy.mx || []).some((pattern) => {
    const hostname = pattern.startsWith("*.") ? pattern.slice(2) : pattern;
    return !isValidDomain(hostname) || (pattern.includes("*") && !pattern.startsWith("*."));
  })) {
    return { valid: false, reason: "invalid MTA-STS mx pattern" };
  }

  return { valid: true, policy };
}

// Reads a response body as UTF-8 text, aborting once `maxBytes` is exceeded so
// an oversized or hostile response can never be fully buffered into memory.
// Returns null when the cap is exceeded.
async function readCapped(res, maxBytes) {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks = [];
  let received = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock?.();
  }
  const buf = new Uint8Array(received);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(buf);
}

function simplifyAnswer(type, a) {
  if (type === "MX") {
    const m = /^([0-9]+)\s+(.+)$/.exec(a.data);
    if (m) return { preference: Number(m[1]), exchange: trimDot(m[2]), ttl: a.TTL };
  }
  if (type === "TLSA") {
    const p = (a.data || "").trim().split(/\s+/);
    const certData = p.slice(3).join("");
    const valid = p.length >= 4
      && /^[0-3]$/.test(p[0])
      && /^[0-1]$/.test(p[1])
      && /^[0-2]$/.test(p[2])
      && /^(?:[0-9a-f]{2})+$/i.test(certData)
      && (p[2] !== "1" || certData.length === 64)
      && (p[2] !== "2" || certData.length === 128);
    if (!valid) {
      // Malformed / incomplete TLSA data — return raw payload for debugging
      return { error: "malformed TLSA", raw: a.data, ttl: a.TTL };
    }
    return {
      usage: Number(p[0]),
      selector: Number(p[1]),
      matchingType: Number(p[2]),
      certData,
      ttl: a.TTL,
    };
  }
  if (type === "TXT") return { data: a.data, ttl: a.TTL };
  return { data: trimDot(a.data), ttl: a.TTL };
}

function trimDot(s) {
  return typeof s === "string" && s.endsWith(".") ? s.slice(0, -1) : s;
}

// Normalizes DoH TXT data:
// DoH JSON returns a multi-string TXT as a sequence of quoted strings
// separated by spaces, e.g. `"v=spf1 ..." "include:_spf.example.com ~all"`.
// They may contain escaped characters (\" and \\). If the input contains
// no quotes, return it unchanged (some resolvers return plain text).
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

function json(obj, status = 200, extraHeaders) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": status === 200 ? "public, max-age=60" : "no-store",
      ...corsHeaders(),
      ...securityHeaders(),
      ...extraHeaders,
    },
  });
}

// ---------- HTML template (inline UI) ----------

const HTML = `<!doctype html>
<html lang="en">
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
    details.adv{ flex:1 1 100%; margin-top:2px; }
    details.adv summary{ cursor:pointer; color:#9fb1ff; font-size:14px; user-select:none; }
    details.adv input{ margin-top:10px; width:100%; }
    details.adv .muted{ display:block; margin-top:6px; }
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
    .badge-info{ background:rgba(110,162,255,0.18); color:#a9c5ff; }
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
      <p class="muted">NS, A, AAAA, MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI and DANE/TLSA.</p>
      <form id="f">
        <input id="name" type="text" inputmode="url" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="lukasberan.cz" required />
        <button type="submit">Look up</button>
        <details class="adv">
          <summary>Advanced — custom DKIM selectors</summary>
          <input id="selectors" type="text" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="selector1, selector2 (default — Microsoft 365)" />
          <span class="muted">Comma-separated. Overrides the default Microsoft 365 selectors (max 5).</span>
        </details>
      </form>

      <div id="out" class="grid"></div>
      <div class="footer">Powered by Cloudflare Workers | Uses DNS-over-HTTPS at <code>cloudflare-dns.com</code> | Created by <a href="https://www.lukasberan.cz/"><strong>Lukáš Beran</strong></a></div>
    </div>
  </div>

  <script>
    const f = document.getElementById('f');
    const nameEl = document.getElementById('name');
    const selectorsEl = document.getElementById('selectors');
    const out = document.getElementById('out');

    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      out.innerHTML = '<p class="muted">Querying DNS…</p>';
      const name = nameEl.value.trim();
      const selectors = (selectorsEl.value || '').trim();
      try {
        let url = '/api/dns?name=' + encodeURIComponent(name);
        if (selectors) url += '&selectors=' + encodeURIComponent(selectors);
        const res = await fetch(url);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Unknown error');
        render(data);
      } catch (err) {
        out.innerHTML = '<p class="err">' + esc(err.message) + '</p>';
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

    function badgeInfo(text) {
      return '<span class="badge badge-info">' + text + '</span>';
    }

    function recordBadge(records, status, error) {
      if (lookupError(status, error)) return badgeWarn('Lookup failed');
      return records && records.length ? badgeInfo('Found') : badge(false, '', 'Missing');
    }

    function panel(title, items, full) {
      return '<div class="panel' + (full ? ' rowspan' : '') + '"><h3>' + title + '</h3><ul>' + items + '</ul></div>';
    }

    function li(arr, fn) {
      if (!arr || !arr.length) return '<li>—</li>';
      return arr.map(r => '<li>' + fn(r) + '</li>').join('');
    }

    function lookupError(status, error) {
      if (error) return error;
      if (status !== null && status !== undefined && status !== 0 && status !== 3) {
        return 'DNS status ' + status;
      }
      return '';
    }

    function queryItems(items, status, error) {
      const problem = lookupError(status, error);
      return problem
        ? '<li class="err">Lookup failed: <code>' + esc(problem) + '</code></li>'
        : items;
    }

    function ttl(r) { return ' <span class="muted">(TTL ' + r.ttl + 's)</span>'; }

    function esc(s){
      return ('' + s).replace(/[&<>"']/g, function(c){ return ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]); });
    }

    function render(data){
      const d = data.domain;
      const st = data.status || {};
      const ds = data.dnssec || {};
      const errors = data.errors || {};

      // NXDOMAIN — domain does not exist (NS query returned status 3)
      if (st.ns === 3) {
        out.innerHTML = '<div class="notice notice-err rowspan">Domain <code>' + esc(d) + '</code> does not exist (NXDOMAIN).</div>';
        return;
      }

      const ns = queryItems(li(data.ns, r => esc(r.data) + ttl(r)), st.ns, errors.ns);
      const a = queryItems(li(data.a, r => esc(r.data) + ttl(r)), st.a, errors.a);
      const aaaa = queryItems(li(data.aaaa, r => esc(r.data) + ttl(r)), st.aaaa, errors.aaaa);
      const mx = queryItems(
        li((data.mx||[]).sort((x,y)=>(x.preference||0)-(y.preference||0)),
          r => r.preference + ' ' + esc(r.exchange || '.') + ttl(r)),
        st.mx,
        errors.mx
      );
      const spf = queryItems(li(data.spf, s => '<code>' + esc(s) + '</code>'), st.txt, errors.txt);
      const dmarc = queryItems(li(data.dmarc, s => '<code>' + esc(s) + '</code>'), st.dmarc, errors.dmarc);
      const stsValidation = data.mtaStsValidation || {};
      const mtaStsValidationItem = !errors.mtaStsTxt && stsValidation.found && !stsValidation.valid && stsValidation.reason
        ? '<li class="err">Validation: ' + esc(stsValidation.reason) + '</li>'
        : '';
      const mtaSts = queryItems(
        li(data.mtaSts, s => '<code>' + esc(s) + '</code>') + mtaStsValidationItem,
        st.mtaStsTxt,
        errors.mtaStsTxt
      );
      const tlsRpt = queryItems(li(data.tlsRpt, s => '<code>' + esc(s) + '</code>'), st.tlsRpt, errors.tlsRpt);
      const bimi = queryItems(li(data.bimi, s => '<code>' + esc(s) + '</code>'), st.bimi, errors.bimi);

      // DKIM — each selector may resolve as a CNAME (Microsoft 365 delegation)
      // and/or a TXT key (most other providers).
      let dkimHtml = '<li>—</li>';
      if (data.dkim && data.dkim.length > 0) {
        let dkItems = '';
        data.dkim.forEach(sel => {
          const qname = sel.selector + '._domainkey.' + d;
          const cname = sel.cname || [];
          const txt = sel.txt || [];
          const selStatus = sel.status || {};
          const selErrors = sel.errors || {};
          const cnameError = lookupError(selStatus.cname, selErrors.cname);
          const txtError = lookupError(selStatus.txt, selErrors.txt);
          if (cnameError) {
            dkItems += '<li class="err"><code>' + esc(qname) + '</code> CNAME lookup failed: ' + esc(cnameError) + '</li>';
          }
          if (txtError) {
            dkItems += '<li class="err"><code>' + esc(qname) + '</code> TXT lookup failed: ' + esc(txtError) + '</li>';
          }
          if (!cname.length && !txt.length && !cnameError && !txtError) {
            dkItems += '<li><code>' + esc(qname) + '</code> — not found</li>';
          } else {
            cname.forEach(r => {
              dkItems += '<li><code>' + esc(qname) + '</code> <span class="muted">(CNAME)</span> → <code>' + esc(r.data) + '</code>' + ttl(r) + '</li>';
            });
            txt.forEach(r => {
              dkItems += '<li><code>' + esc(qname) + '</code> <span class="muted">(TXT)</span> → <code>' + esc(r.data) + '</code>' + ttl(r) + '</li>';
            });
          }
        });
        dkimHtml = dkItems;
      }

      // MTA-STS Policy
      let mtaStsPol = '<li>—</li>';
      const pol = data.mtaStsPolicy;
      if (pol && pol.valid && pol.policy) {
        const p = pol.policy;
        let items = '';
        if (p.version) items += '<li>version: <code>' + esc(p.version) + '</code></li>';
        if (p.mode) items += '<li>mode: <code>' + esc(p.mode) + '</code></li>';
        if (p.max_age) items += '<li>max_age: <code>' + esc(p.max_age) + '</code></li>';
        if (p.mx) p.mx.forEach(m => { items += '<li>mx: <code>' + esc(m) + '</code></li>'; });
        mtaStsPol = items || '<li>—</li>';
      } else if (pol && pol.reason) {
        mtaStsPol = '<li class="' + (pol.found ? 'err' : 'muted') + '">' + esc(pol.reason) + (pol.url ? ' — <code>' + esc(pol.url) + '</code>' : '') + '</li>';
      }

      // DANE/TLSA
      let daneHtml = '<li>—</li>';
      if (data.dane && data.dane.length > 0) {
        let ditems = '';
        data.dane.forEach(entry => {
          const queryError = lookupError(entry.status, entry.error);
          if (queryError) {
            ditems += '<li class="err"><strong>' + esc(entry.mx) + '</strong> — lookup failed: ' + esc(queryError) + '</li>';
            return;
          }
          const dnssecBadge = entry.tlsa.length
            ? (entry.dnssec ? badge(true, 'DNSSEC OK', '') : badgeWarn('DNSSEC missing — TLSA untrusted'))
            : '';
          if (entry.tlsa.length === 0) {
            ditems += '<li><strong>' + esc(entry.mx) + '</strong> — no TLSA record</li>';
          } else {
            entry.tlsa.forEach(t => {
              if (t.error) {
                ditems += '<li><strong>' + esc(entry.mx) + '</strong> ' + dnssecBadge
                  + ' — invalid TLSA data: <code>' + esc(t.raw || '') + '</code>' + ttl(t) + '</li>';
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
        ? '<div class="notice notice-warn rowspan">Domain declares <strong>null MX</strong> (RFC 7505) — explicitly does not accept email.</div>'
        : '';

      const dkimFound = data.dkim && data.dkim.some(d2 => (d2.cname && d2.cname.length) || (d2.txt && d2.txt.length));
      const dkimError = data.dkim && data.dkim.some(d2 => d2.errors && (d2.errors.cname || d2.errors.txt));
      const dkimBadge = dkimError
        ? badgeWarn('Lookup issue')
        : badgeInfo(dkimFound ? 'Found' : 'Not found for selectors');
      const stsTxtBadge = lookupError(st.mtaStsTxt, errors.mtaStsTxt)
        ? badgeWarn('Lookup failed')
        : stsValidation.valid
          ? badge(true, 'Valid', '')
          : stsValidation.found
            ? badge(false, '', 'Invalid')
            : badge(false, '', 'Missing');
      const stsPolicyBadge = pol && pol.valid
        ? badge(true, 'Valid', '')
        : pol && pol.found
          ? badge(false, '', 'Invalid')
          : pol && pol.skipped
            ? badgeInfo('Not fetched')
            : badgeWarn('Unavailable');
      const daneLookupIssue = data.dane && data.dane.some(entry => lookupError(entry.status, entry.error));
      const daneFound = data.dane && data.dane.some(entry => entry.tlsa && entry.tlsa.length);
      const daneBadge = daneLookupIssue
        ? badgeWarn('Lookup issue')
        : data.dane && data.dane.length
          ? (daneFound ? badgeInfo('Found') : badge(false, '', 'Missing'))
          : badgeInfo('Not checked');

      out.innerHTML =
        panel('NS' + (ds.ns ? badge(true,'DNSSEC','') : ''), ns, true) +
        panel('A', a) + panel('AAAA', aaaa) +
        panel('MX', mx) +
        nullMxNotice +
        panel('SPF (TXT)' + recordBadge(data.spf, st.txt, errors.txt) + (data.spf && data.spf.length > 1 ? badgeWarn('Multiple SPF records — misconfiguration') : ''), spf) +
        '<div class="section-title">Email security</div>' +
        panel('DKIM — ' + (data.dkimCustom ? 'custom selectors' : 'Microsoft 365') + dkimBadge, dkimHtml, true) +
        panel('DMARC (_dmarc.' + esc(d) + ')' + recordBadge(data.dmarc, st.dmarc, errors.dmarc) + (data.dmarc && data.dmarc.length > 1 ? badgeWarn('Multiple DMARC records') : ''), dmarc, true) +
        panel('MTA-STS TXT (_mta-sts.' + esc(d) + ')' + stsTxtBadge, mtaSts) +
        panel('MTA-STS Policy' + stsPolicyBadge, mtaStsPol) +
        panel('TLS-RPT (_smtp._tls.' + esc(d) + ')' + recordBadge(data.tlsRpt, st.tlsRpt, errors.tlsRpt) + (data.tlsRpt && data.tlsRpt.length > 1 ? badgeWarn('Multiple TLS-RPT records') : ''), tlsRpt) +
        panel('BIMI (default._bimi.' + esc(d) + ')' + recordBadge(data.bimi, st.bimi, errors.bimi), bimi) +
        panel('DANE / TLSA' + daneBadge + (data.dane && data.dane.some(e => e.tlsa.length && !e.dnssec) ? badgeWarn('No DNSSEC') : ''), daneHtml, true);
    }
  </script>
</body>
</html>`;
