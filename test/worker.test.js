import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import vm from "node:vm";

import worker from "../worker.js";

async function withFetch(fetchImpl, callback) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = fetchImpl;
  try {
    return await callback();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function lookup(name = "example.com", selectors = null) {
  const url = new URL("https://local.test/api/dns");
  url.searchParams.set("name", name);
  if (selectors) url.searchParams.set("selectors", selectors);
  const response = await worker.fetch(new Request(url));
  return { response, body: await response.json() };
}

function createFetch({ answers = {}, statuses = {}, policy = null } = {}) {
  const calls = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(String(input));
    calls.push({ url: url.href, init });
    if (url.hostname === "cloudflare-dns.com") {
      const key = `${url.searchParams.get("name")}|${url.searchParams.get("type")}`;
      return new Response(JSON.stringify({
        Status: statuses[key] ?? 0,
        AD: false,
        Answer: answers[key] || [],
      }), {
        status: 200,
        headers: { "content-type": "application/dns-json" },
      });
    }
    if (url.hostname.startsWith("mta-sts.") && policy) {
      return new Response(policy.body, {
        status: policy.status ?? 200,
        headers: { "content-type": policy.contentType || "text/plain" },
      });
    }
    return new Response("", { status: 404 });
  };
  fetchImpl.calls = calls;
  return fetchImpl;
}

function extractInlineBlock(html, tag) {
  const openingTag = `<${tag}>`;
  const closingTag = `</${tag}>`;
  const start = html.indexOf(openingTag);
  const end = html.indexOf(closingTag, start + openingTag.length);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  return html.slice(start + openingTag.length, end);
}

test("domain input rejects URL syntax and keeps IDN conversion", async () => {
  let fetchCalled = false;
  await withFetch(async () => {
    fetchCalled = true;
    throw new Error("unexpected fetch");
  }, async () => {
    for (const name of [
      "claimed.example@actual.example",
      "example.com/path",
      "example.com:443",
      "%65xample.com",
      "127.0.0.1",
    ]) {
      const { response } = await lookup(name);
      assert.equal(response.status, 400, name);
    }
  });
  assert.equal(fetchCalled, false);

  await withFetch(createFetch(), async () => {
    const { response, body } = await lookup("h\u00e1\u010dkydom\u00e9ny.cz");
    assert.equal(response.status, 200);
    assert.equal(body.domain, "xn--hkydomny-8ya9f3t.cz");
  });
});

test("resolver failures are distinct from missing records", async () => {
  await withFetch(async () => {
    throw new Error("resolver unavailable");
  }, async () => {
    const { response, body } = await lookup();
    assert.equal(response.status, 502);
    assert.equal(body.error, "DNS resolver lookup failed.");
    assert.equal(body.details.ns, "resolver unavailable");
  });

  const fetchImpl = createFetch({
    statuses: { "example.com|AAAA": 2 },
  });
  await withFetch(fetchImpl, async () => {
    const { response, body } = await lookup();
    assert.equal(response.status, 200);
    assert.equal(body.status.aaaa, 2);
    assert.equal(body.errors.aaaa, "DNS SERVFAIL (2)");
  });
});

test("DoH CNAME chain records are not mislabeled as A or MX", async () => {
  const fetchImpl = createFetch({
    answers: {
      "example.com|A": [
        { type: 5, TTL: 300, data: "target.example.com." },
        { type: 1, TTL: 300, data: "192.0.2.10" },
      ],
      "example.com|MX": [
        { type: 5, TTL: 300, data: "target.example.com." },
        { type: 15, TTL: 300, data: "10 mail.example.com." },
      ],
    },
  });
  await withFetch(fetchImpl, async () => {
    const { body } = await lookup();
    assert.deepEqual(body.a, [{ data: "192.0.2.10", ttl: 300 }]);
    assert.deepEqual(body.mx, [{ preference: 10, exchange: "mail.example.com", ttl: 300 }]);
  });
});

test("MTA-STS policy fetch requires valid discovery and bypasses HTTP cache", async () => {
  const noDiscovery = createFetch();
  await withFetch(noDiscovery, async () => {
    const { body } = await lookup();
    assert.equal(body.mtaStsValidation.found, false);
    assert.equal(body.mtaStsValidation.valid, false);
    assert.equal(body.mtaStsPolicy.skipped, true);
  });
  assert.equal(
    noDiscovery.calls.some((call) => call.url.startsWith("https://mta-sts.example.com/")),
    false
  );

  const discoveryAnswer = [{
    type: 16,
    TTL: 300,
    data: "\"v=STSv1; id=20260804;\"",
  }];
  const invalidPolicy = createFetch({
    answers: { "_mta-sts.example.com|TXT": discoveryAnswer },
    policy: { body: "version: definitely-not-stsv1\nmode: invented" },
  });
  await withFetch(invalidPolicy, async () => {
    const { body } = await lookup();
    assert.equal(body.mtaStsValidation.valid, true);
    assert.equal(body.mtaStsPolicy.found, true);
    assert.equal(body.mtaStsPolicy.valid, false);
    assert.equal(body.mtaStsPolicy.reason, "MTA-STS policy version must be STSv1");
  });
  const policyCall = invalidPolicy.calls.find((call) =>
    call.url.startsWith("https://mta-sts.example.com/")
  );
  assert.equal(policyCall.init.cache, "no-store");

  const validPolicy = createFetch({
    answers: { "_mta-sts.example.com|TXT": discoveryAnswer },
    policy: {
      body: [
        "version: STSv1",
        "mode: enforce",
        "mx: mail.example.com",
        "max_age: 604800",
        "",
      ].join("\n"),
    },
  });
  await withFetch(validPolicy, async () => {
    const { body } = await lookup();
    assert.equal(body.mtaStsPolicy.valid, true);
    assert.equal(body.mtaStsPolicy.policy.mode, "enforce");
  });

  for (const policy of [
    { body: "version: STSv1\nmode: none\nmax_age: 0\n", contentType: "text/plainish" },
    { body: "version: STSv1\nmode: none\nmax_age: 0\n", status: 201 },
  ]) {
    const invalidResponse = createFetch({
      answers: { "_mta-sts.example.com|TXT": discoveryAnswer },
      policy,
    });
    await withFetch(invalidResponse, async () => {
      const { body } = await lookup();
      assert.equal(body.mtaStsPolicy.valid, false);
    });
  }
});

test("malformed TLSA fields are reported as invalid data", async () => {
  const fetchImpl = createFetch({
    answers: {
      "example.com|MX": [{ type: 15, TTL: 300, data: "10 mail.example.com." }],
      "_25._tcp.mail.example.com|TLSA": [{
        type: 52,
        TTL: 300,
        data: "9 1 1 deadbeef",
      }],
    },
  });
  await withFetch(fetchImpl, async () => {
    const { body } = await lookup();
    assert.equal(body.dane[0].tlsa[0].error, "malformed TLSA");
  });
});

test("DANE sorts MX candidates before applying a transparent limit", async () => {
  const mxAnswers = Array.from({ length: 21 }, (_, index) => ({
    type: 15,
    TTL: 300,
    data: `${21 - index} mx${21 - index}.example.com.`,
  }));
  const fetchImpl = createFetch({
    answers: { "example.com|MX": mxAnswers },
  });
  await withFetch(fetchImpl, async () => {
    const { body } = await lookup();
    assert.equal(body.mx[0].preference, 1);
    assert.equal(body.dane[0].mx, "mx1.example.com");
    assert.equal(body.dane.length, 15);
    assert.deepEqual(body.daneMeta, {
      candidates: 21,
      checked: 15,
      truncated: true,
      limit: 15,
      implicitMx: false,
    });
  });
});

test("DANE uses an implicit MX only when address records exist", async () => {
  const implicitFetch = createFetch({
    answers: {
      "example.com|A": [{ type: 1, TTL: 300, data: "192.0.2.10" }],
    },
  });
  await withFetch(implicitFetch, async () => {
    const { body } = await lookup();
    assert.equal(body.dane.length, 1);
    assert.equal(body.dane[0].mx, "example.com");
    assert.equal(body.dane[0].implicit, true);
    assert.equal(body.daneMeta.implicitMx, true);
    assert.ok(implicitFetch.calls.some((call) =>
      call.url.includes("name=_25._tcp.example.com") && call.url.includes("type=TLSA")
    ));
  });

  const nullMxFetch = createFetch({
    answers: {
      "example.com|A": [{ type: 1, TTL: 300, data: "192.0.2.10" }],
      "example.com|MX": [{ type: 15, TTL: 300, data: "0 ." }],
    },
  });
  await withFetch(nullMxFetch, async () => {
    const { body } = await lookup();
    assert.equal(body.nullMx, true);
    assert.equal(body.dane.length, 0);
    assert.equal(body.daneMeta.implicitMx, false);
  });
});

test("DMARC inherits policy through the RFC 9989 DNS Tree Walk", async () => {
  const fetchImpl = createFetch({
    answers: {
      "_dmarc.example.com|TXT": [{
        type: 16,
        TTL: 300,
        data: "\"v=DMARC1; p=reject; sp=quarantine; psd=n;\"",
      }],
    },
  });
  await withFetch(fetchImpl, async () => {
    const { body } = await lookup("mail.example.com");
    assert.deepEqual(body.dmarc, ["v=DMARC1; p=reject; sp=quarantine; psd=n;"]);
    assert.equal(body.dmarcDiscovery.policyDomain, "example.com");
    assert.equal(body.dmarcDiscovery.organizationalDomain, "example.com");
    assert.equal(body.dmarcDiscovery.source, "organizational");
    assert.equal(body.dmarcDiscovery.inherited, true);
    assert.equal(body.dmarcDiscovery.requestedPolicy, "quarantine");
    assert.equal(body.dmarcDiscovery.effectivePolicy, "quarantine");
    assert.equal(body.dmarcDiscovery.queries.length, 2);
    assert.equal(fetchImpl.calls.some((call) => call.url.includes("name=_dmarc.com")), false);
  });
});

test("DMARC handles PSD and test-mode policies", async () => {
  const psdFetch = createFetch({
    answers: {
      "_dmarc.bank.example|TXT": [{
        type: 16,
        TTL: 300,
        data: "\"v=DMARC1; p=reject; psd=y;\"",
      }],
    },
  });
  await withFetch(psdFetch, async () => {
    const { body } = await lookup("tenant.bank.example");
    assert.equal(body.dmarcDiscovery.source, "psd");
    assert.equal(body.dmarcDiscovery.policyDomain, "bank.example");
    assert.equal(body.dmarcDiscovery.organizationalDomain, "tenant.bank.example");
    assert.equal(body.dmarcDiscovery.effectivePolicy, "reject");
  });

  const testingFetch = createFetch({
    answers: {
      "_dmarc.example.com|TXT": [{
        type: 16,
        TTL: 300,
        data: "\"v=DMARC1; P=REJECT; T=Y;\"",
      }],
    },
  });
  await withFetch(testingFetch, async () => {
    const { body } = await lookup();
    assert.equal(body.dmarcDiscovery.source, "author");
    assert.equal(body.dmarcDiscovery.requestedPolicy, "reject");
    assert.equal(body.dmarcDiscovery.effectivePolicy, "quarantine");
    assert.equal(body.dmarcDiscovery.testing, true);
  });
});

test("DMARC Tree Walk never exceeds eight DNS queries", async () => {
  const fetchImpl = createFetch();
  const domain = "a.b.c.d.e.f.g.h.i.j.example.com";
  await withFetch(fetchImpl, async () => {
    const { body } = await lookup(domain);
    assert.equal(body.dmarcDiscovery.queries.length, 8);
    assert.equal(body.dmarcDiscovery.found, false);
    assert.deepEqual(
      body.dmarcDiscovery.queries.map((query) => query.domain),
      [
        domain,
        "f.g.h.i.j.example.com",
        "g.h.i.j.example.com",
        "h.i.j.example.com",
        "i.j.example.com",
        "j.example.com",
        "example.com",
        "com",
      ]
    );
  });
  const dmarcCalls = fetchImpl.calls.filter((call) =>
    new URL(call.url).searchParams.get("name")?.startsWith("_dmarc.")
  );
  assert.equal(dmarcCalls.length, 8);
});

test("DMARC np policy takes precedence for an NXDOMAIN author domain", async () => {
  const fetchImpl = createFetch({
    statuses: { "missing.example.com|NS": 3 },
    answers: {
      "_dmarc.example.com|TXT": [{
        type: 16,
        TTL: 300,
        data: "\"v=DMARC1; p=reject; sp=quarantine; np=none; psd=n;\"",
      }],
    },
  });
  await withFetch(fetchImpl, async () => {
    const { body } = await lookup("missing.example.com");
    assert.equal(body.dmarcDiscovery.inherited, true);
    assert.equal(body.dmarcDiscovery.requestedPolicy, "none");
    assert.equal(body.dmarcDiscovery.effectivePolicy, "none");
  });
});

test("maximum user-controlled fan-out stays at 42 subrequests", async () => {
  const domain = "a.b.c.d.e.f.g.h.i.j.example.com";
  const mxAnswers = Array.from({ length: 15 }, (_, index) => ({
    type: 15,
    TTL: 300,
    data: `${index + 1} mx${index + 1}.example.com.`,
  }));
  const fetchImpl = createFetch({
    answers: {
      [`${domain}|MX`]: mxAnswers,
      [`_mta-sts.${domain}|TXT`]: [{
        type: 16,
        TTL: 300,
        data: "\"v=STSv1; id=20260804;\"",
      }],
    },
    policy: { body: "version: STSv1\nmode: none\nmax_age: 0\n" },
  });
  await withFetch(fetchImpl, async () => {
    const { response } = await lookup(domain, "one,two,three,four,five");
    assert.equal(response.status, 200);
  });
  assert.equal(fetchImpl.calls.length, 42);
});

test("UI distinguishes found, valid, missing, and lookup failure", async () => {
  const response = await worker.fetch(new Request("https://local.test/"));
  const html = await response.text();
  const script = extractInlineBlock(html, "script");

  const elements = {
    f: { addEventListener() {} },
    name: { value: "" },
    selectors: { value: "" },
    out: { innerHTML: "" },
  };
  const context = {
    document: { getElementById: (id) => elements[id] },
    encodeURIComponent,
    fetch: async () => new Response(),
  };
  vm.runInNewContext(`${script}\nglobalThis.__ui = { render, out };`, context);

  const data = {
    domain: "example.com",
    ns: [],
    a: [],
    aaaa: [],
    mx: [],
    nullMx: false,
    spf: [],
    dkim: [{
      selector: "selector1",
      cname: [],
      txt: [],
      status: { cname: 0, txt: 0 },
      errors: { cname: null, txt: null },
    }],
    dkimCustom: false,
    dmarc: ["v=DMARC1"],
    mtaSts: [],
    mtaStsValidation: { valid: false, reason: "record not found" },
    mtaStsPolicy: {
      found: false,
      valid: false,
      skipped: true,
      reason: "policy not fetched",
    },
    tlsRpt: [],
    bimi: [],
    dane: [],
    dnssec: {},
    status: {
      ns: 0,
      a: 0,
      aaaa: 0,
      mx: 0,
      txt: 0,
      dmarc: 0,
      mtaStsTxt: 0,
      tlsRpt: 0,
      bimi: 0,
    },
    errors: {},
  };

  context.__ui.render(data);
  const dmarcHeading = context.__ui.out.innerHTML.match(/<h3>DMARC[\s\S]*?<\/h3>/)?.[0];
  const dkimHeading = context.__ui.out.innerHTML.match(/<h3>DKIM[\s\S]*?<\/h3>/)?.[0];
  assert.match(dmarcHeading, />Found<\/span>/);
  assert.doesNotMatch(dmarcHeading, />OK<\/span>/);
  assert.match(dkimHeading, />Not found for selectors<\/span>/);

  data.dnssec.a = true;
  context.__ui.render(data);
  const aHeading = context.__ui.out.innerHTML.match(/<h3>A[\s\S]*?<\/h3>/)?.[0];
  const aaaaHeading = context.__ui.out.innerHTML.match(/<h3>AAAA[\s\S]*?<\/h3>/)?.[0];
  assert.match(aHeading, />DNSSEC authenticated<\/span>/);
  assert.match(aaaaHeading, />DNSSEC not authenticated<\/span>/);

  data.status.dmarc = 2;
  data.errors.dmarc = "DNS SERVFAIL (2)";
  context.__ui.render(data);
  const failedHeading = context.__ui.out.innerHTML.match(/<h3>DMARC[\s\S]*?<\/h3>/)?.[0];
  assert.match(failedHeading, />Lookup failed<\/span>/);
  assert.doesNotMatch(failedHeading, />Missing<\/span>/);
});

test("UI ignores a stale lookup that finishes after a newer request", async () => {
  const response = await worker.fetch(new Request("https://local.test/"));
  const html = await response.text();
  const script = extractInlineBlock(html, "script");

  let submitHandler;
  const pending = [];
  const elements = {
    f: {
      addEventListener(event, handler) {
        if (event === "submit") submitHandler = handler;
      },
    },
    name: { value: "first.example" },
    selectors: { value: "" },
    out: { innerHTML: "" },
  };
  const context = {
    AbortController,
    document: { getElementById: (id) => elements[id] },
    encodeURIComponent,
    fetch: () => new Promise((resolve) => pending.push(resolve)),
  };
  vm.runInNewContext(script, context);

  const event = { preventDefault() {} };
  const firstLookup = submitHandler(event);
  elements.name.value = "second.example";
  const secondLookup = submitHandler(event);

  pending[1](new Response(JSON.stringify({ error: "new result" }), { status: 400 }));
  await secondLookup;
  assert.match(elements.out.innerHTML, /new result/);

  pending[0](new Response(JSON.stringify({ error: "stale result" }), { status: 400 }));
  await firstLookup;
  assert.match(elements.out.innerHTML, /new result/);
  assert.doesNotMatch(elements.out.innerHTML, /stale result/);
});

test("CSP authorizes only the exact inline UI blocks", async () => {
  const response = await worker.fetch(new Request("https://local.test/"));
  const html = await response.text();
  const csp = response.headers.get("content-security-policy");
  assert.ok(csp);
  assert.doesNotMatch(csp, /unsafe-inline/);
  assert.match(csp, /object-src 'none'/);

  for (const tag of ["style", "script"]) {
    const content = extractInlineBlock(html, tag);
    const hash = createHash("sha256").update(content).digest("base64");
    assert.ok(csp.includes(`'sha256-${hash}'`), `${tag} hash missing from CSP`);
  }
});