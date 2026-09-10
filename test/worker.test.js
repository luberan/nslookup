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

function createFetch({ answers = {}, statuses = {}, authenticated = {}, policy = null } = {}) {
  const calls = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(String(input));
    calls.push({ url: url.href, init });
    if (url.hostname === "cloudflare-dns.com") {
      const key = `${url.searchParams.get("name")}|${url.searchParams.get("type")}`;
      return new Response(JSON.stringify({
        Status: statuses[key] ?? 0,
        AD: authenticated[key] ?? false,
        Answer: answers[key] || [],
      }), {
        status: 200,
        headers: { "content-type": "application/dns-json" },
      });
    }
    if (url.hostname.startsWith("mta-sts.") && policy) {
      return new Response(policy.body, {
        status: policy.status ?? 200,
        headers: { "content-type": policy.contentType || "text/plain", ...policy.headers },
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

async function createUi() {
  const response = await worker.fetch(new Request("https://local.test/"));
  const script = extractInlineBlock(await response.text(), "script");
  const elements = {
    f: { addEventListener() {} },
    name: { value: "" },
    selectors: { value: "" },
    out: { innerHTML: "" },
  };
  const context = { document: { getElementById: (id) => elements[id] } };
  vm.runInNewContext(`${script}\nglobalThis.__ui = { render, out };`, context);
  return context.__ui;
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
      "[::1]",
      "singlelabel",
      "-bad.example",
      "bad-.example",
      "example..com",
      `${"a".repeat(64)}.example.com`,
      `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}`,
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

test("API validates methods, selectors, and error response headers", async () => {
  await withFetch(() => { throw new Error("unexpected fetch"); }, async () => {
    for (const { path, method, status } of [
      { path: "/api/dns", method: "GET", status: 400 },
      { path: "/api/dns?name=example.com&selectors=bad_selector", method: "GET", status: 400 },
      { path: "/api/dns?name=example.com", method: "POST", status: 405 },
      { path: "/api/dns", method: "OPTIONS", status: 204 },
    ]) {
      const response = await worker.fetch(new Request(`https://local.test${path}`, { method }));
      assert.equal(response.status, status);
      assert.equal(response.headers.get("access-control-allow-origin"), "*");
      if (status === 405) assert.equal(response.headers.get("allow"), "GET, OPTIONS");
      if (status !== 204) {
        assert.equal(response.headers.get("cache-control"), "no-store");
        assert.equal(response.headers.get("x-content-type-options"), "nosniff");
        assert.equal(typeof (await response.json()).error, "string");
      }
    }
  });
  await withFetch(createFetch(), async () => {
    const { body } = await lookup("EXAMPLE.COM.", " One,one,two,three,four,five,six ");
    assert.equal(body.domain, "example.com");
    assert.equal(body.dkimCustom, true);
    assert.deepEqual(body.dkim.map((entry) => entry.selector), ["one", "two", "three", "four", "five"]);
  });
});

test("DNSSEC and positive email records propagate from resolver to every API section", async () => {
  const answers = {
    "example.com|NS": [{ type: 2, TTL: 60, data: "ns.example.com." }],
    "example.com|A": [{ type: 1, TTL: 60, data: "192.0.2.10" }],
    "example.com|AAAA": [{ type: 28, TTL: 60, data: "2001:db8::10" }],
    "example.com|MX": [{ type: 15, TTL: 60, data: "10 mail.example.com." }],
    "example.com|TXT": [{ type: 16, TTL: 60, data: "\"v=spf1 \" \"-all\"" }],
    "delegated._domainkey.example.com|CNAME": [{ type: 5, TTL: 60, data: "key.example.net." }],
    "delegated._domainkey.example.com|TXT": [
      { name: "delegated._domainkey.example.com", type: 5, TTL: 60, data: "key.example.net." },
      { type: 16, TTL: 60, data: "\"v=DKIM1; p=delegatedKey\"" },
    ],
    "direct._domainkey.example.com|TXT": [{ type: 16, TTL: 60, data: "\"v=DKIM1; p=directKey\"" }],
    "_dmarc.example.com|TXT": [{ type: 16, TTL: 60, data: "\"v=DMARC1; p=reject\"" }],
    "_mta-sts.example.com|TXT": [{ type: 16, TTL: 60, data: "\"v=STSv1; id=one\"" }],
    "_smtp._tls.example.com|TXT": [{ type: 16, TTL: 60, data: "\"v=TLSRPTv1; rua=mailto:tls@example.com\"" }],
    "default._bimi.example.com|TXT": [{ type: 16, TTL: 60, data: "\"v=BIMI1; l=https://example.com/logo.svg\"" }],
    "_25._tcp.mail.example.com|TLSA": [{ type: 52, TTL: 60, data: `3 1 1 ${"ab".repeat(32)}` }],
  };
  for (const secure of [true, false]) {
    const authenticated = Object.fromEntries(Object.keys(answers).map((key) => [key, secure]));
    await withFetch(createFetch({
      answers, authenticated,
      policy: { body: "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n" },
    }), async () => {
      const { body } = await lookup("example.com", "delegated,direct");
      assert.deepEqual(body.dnssec, Object.fromEntries(
        ["ns", "a", "aaaa", "mx", "txt", "dmarc", "mtaStsTxt", "tlsRpt", "bimi"].map((key) => [key, secure])
      ));
      assert.deepEqual(body.spf, ["v=spf1 -all"]);
      assert.equal(body.dkim[0].cname[0].data, "key.example.net");
      assert.deepEqual(body.dkim[0].txt, [{ data: "v=DKIM1; p=delegatedKey", ttl: 60 }]);
      assert.deepEqual(body.dkim[0].dnssec, { cname: secure, txt: secure });
      assert.equal(body.dkim[1].txt[0].data, "v=DKIM1; p=directKey");
      assert.equal(body.dkim[1].dnssec.txt, secure);
      assert.deepEqual(body.tlsRpt, ["v=TLSRPTv1; rua=mailto:tls@example.com"]);
      assert.deepEqual(body.bimi, ["v=BIMI1; l=https://example.com/logo.svg"]);
      assert.equal(body.dmarcDiscovery.dnssec, secure);
      assert.equal(body.mtaStsPolicy.valid, true);
      assert.equal(body.dane[0].dnssec, secure);
      assert.deepEqual(body.dane[0].tlsa, [{ usage: 3, selector: 1, matchingType: 1, certData: "ab".repeat(32), ttl: 60 }]);
    });
  }
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

test("Malformed DoH responses retain JSON error handling", async () => {
  for (const body of ["not JSON", "null", '{"Status":"0"}', '{"Status":0,"Answer":{}}']) {
    await withFetch(async () => new Response(body), async () => {
      const { response, body: result } = await lookup();
      assert.equal(response.status, 502);
      assert.ok(result.details.ns);
      assert.equal(response.headers.get("access-control-allow-origin"), "*");
    });
  }
});

test("DoH timeout bounds both response headers and streaming bodies", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  for (const phase of ["headers", "body"]) {
    const signals = [];
    await withFetch(async (input, { signal }) => {
      signals.push(signal);
      if (phase === "headers") {
        return new Promise((resolve, reject) => {
          signal.addEventListener("abort", () => reject(signal.reason), { once: true });
        });
      }
      return new Response(new ReadableStream({
        start(controller) {
          signal.addEventListener("abort", () => controller.error(signal.reason), { once: true });
        },
      }));
    }, async () => {
      const pending = lookup();
      context.mock.timers.tick(4999);
      assert.equal(signals.length, 5);
      assert.ok(signals.every((signal) => !signal.aborted));
      context.mock.timers.tick(1);
      const { response, body } = await pending;
      assert.equal(response.status, 502);
      assert.equal(body.details.ns, "DoH NS timeout");
      assert.ok(signals.every((signal) => signal.aborted));
    });
  }
});

test("DoH requests stop when the caller cancels the lookup", async () => {
  const controller = new AbortController();
  const signals = [];
  await withFetch((input, { signal }) => new Promise((resolve, reject) => {
    signals.push(signal);
    signal.addEventListener("abort", () => reject(signal.reason), { once: true });
  }), async () => {
    const pending = worker.fetch(new Request("https://local.test/api/dns?name=example.com", {
      signal: controller.signal,
    }));
    controller.abort();
    const response = await pending;
    assert.equal(response.status, 502);
    assert.equal((await response.json()).details.ns, "DoH NS cancelled");
    assert.equal(signals.length, 5);
    assert.ok(signals.every((signal) => signal.aborted));
  });
});

test("DoH sequential discovery respects the total 15-second lookup deadline", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout", "Date"] });
  const started = Array.from({ length: 4 }, () => Promise.withResolvers());
  let queries = 0;
  await withFetch((input, { signal }) => {
    const name = new URL(String(input)).searchParams.get("name");
    if (!name.startsWith("_dmarc.")) return Promise.resolve(Response.json({ Status: 0 }));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => resolve(Response.json({ Status: 0 })), 4000);
      signal.addEventListener("abort", () => {
        clearTimeout(timer);
        reject(signal.reason);
      }, { once: true });
      started[queries++].resolve();
    });
  }, async () => {
    const pending = lookup("a.b.c.d.e.f.example.com");
    for (let index = 0; index < 3; index++) {
      await started[index].promise;
      context.mock.timers.tick(4000);
    }
    await started[3].promise;
    context.mock.timers.tick(3000);
    const { response, body } = await pending;
    assert.equal(response.status, 200);
    assert.equal(body.errors.dmarc, "DoH TXT timeout");
    assert.equal(body.dmarcDiscovery.queries.length, 4);
    assert.equal(queries, 4);
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

test("SPF discovery requires an exact version at the beginning of the TXT record", async () => {
  await withFetch(createFetch({
    answers: {
      "example.com|TXT": [
        "v=spf1 -all",
        "note v=spf1 is not an SPF record",
        " v=spf1 -all",
        "v=spf10 -all",
        "v=spf1;bad",
        "v=spf1\t-all",
      ].map((value) => ({ type: 16, TTL: 60, data: JSON.stringify(value) })),
    },
  }), async () => {
    const { body } = await lookup();
    assert.deepEqual(body.spf, ["v=spf1 -all"]);
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
    answers: {
      "_mta-sts.example.com|TXT": discoveryAnswer,
      "example.com|MX": [{ type: 15, TTL: 60, data: "10 mail.example.com." }],
    },
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

test("MTA-STS accepts trailing whitespace and first-wins duplicate fields", async () => {
  const fetchImpl = createFetch({
    answers: {
      "_mta-sts.example.com|TXT": [{
        type: 16, TTL: 60, data: "\"v=STSv1; id=first; id=second\"",
      }],
      "example.com|MX": [{ type: 15, TTL: 60, data: "10 mail.example.com." }],
    },
    policy: { body: "version: STSv1 \r\nmode: enforce\t\r\nmode: none\r\nmx: mail.example.com \r\nmax_age: 604800 \r\n" },
  });
  await withFetch(fetchImpl, async () => {
    const { body } = await lookup();
    assert.equal(body.mtaStsValidation.valid, true);
    assert.equal(body.mtaStsValidation.id, "first");
    assert.equal(body.mtaStsPolicy.valid, true);
    assert.equal(body.mtaStsPolicy.policy.mode, "enforce");
    assert.equal(body.mtaStsPolicy.policy.max_age, "604800");
  });

  await withFetch(createFetch({
    answers: {
      "_mta-sts.example.com|TXT": [{ type: 16, TTL: 60, data: "\"v=STSv1; id=bad!; id=second\"" }],
    },
  }), async () => {
    const { body } = await lookup();
    assert.equal(body.mtaStsValidation.valid, false);
    assert.equal(body.mtaStsPolicy.skipped, true);
  });
});

test("MTA-STS validates every receiving MX with exact single-label wildcard matching", async () => {
  for (const { pattern, hosts, valid } of [
    { pattern: "MAIL.example.com", hosts: ["mail.example.com"], valid: true },
    { pattern: "*.example.com", hosts: ["mail.example.com", "backup.example.com"], valid: true },
    { pattern: "*.example.com", hosts: ["example.com"], valid: false },
    { pattern: "*.example.com", hosts: ["mail.eu.example.com"], valid: false },
    { pattern: "unrelated.example.net", hosts: ["mail.example.com"], valid: false },
    {
      pattern: "*.example.com",
      hosts: [...Array.from({ length: 15 }, (_, index) => `mx${index}.example.com`), "backup.example.net"],
      valid: false,
    },
  ]) {
    const fetchImpl = createFetch({
      answers: {
        "_mta-sts.example.com|TXT": [{ type: 16, TTL: 60, data: "\"v=STSv1; id=one\"" }],
        "example.com|MX": hosts.map((host, index) => ({ type: 15, TTL: 60, data: `${index + 1} ${host}.` })),
      },
      policy: { body: `version: STSv1\nmode: enforce\nmx: ${pattern}\nmax_age: 604800\n` },
    });
    await withFetch(fetchImpl, async () => {
      const { body } = await lookup();
      assert.equal(body.mtaStsPolicy.syntaxValid, true);
      assert.equal(body.mtaStsPolicy.tlsChecked, false);
      assert.equal(body.mtaStsPolicy.valid, valid);
      assert.equal(body.mtaStsPolicy.mxValidation.valid, valid);
      assert.equal(body.mtaStsPolicy.mxValidation.hosts.length, hosts.length);
    });
  }
});

test("MTA-STS does not claim MX validation when discovery fails", async () => {
  await withFetch(createFetch({
    answers: { "_mta-sts.example.com|TXT": [{ type: 16, TTL: 60, data: "\"v=STSv1; id=one\"" }] },
    statuses: { "example.com|MX": 2 },
    policy: { body: "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n" },
  }), async () => {
    const { body } = await lookup();
    assert.equal(body.mtaStsPolicy.syntaxValid, true);
    assert.equal(body.mtaStsPolicy.valid, false);
    assert.equal(body.mtaStsPolicy.mxValidation.checked, false);
    assert.match(body.mtaStsPolicy.reason, /MX discovery failed/);
  });
});

test("MTA-STS redirects are reported but never followed", async () => {
  const fetchImpl = createFetch({
    answers: { "_mta-sts.example.com|TXT": [{ type: 16, TTL: 60, data: "\"v=STSv1; id=one\"" }] },
    policy: { body: "", status: 302, headers: { location: "https://private.invalid/" } },
  });
  await withFetch(fetchImpl, async () => {
    const { body } = await lookup();
    assert.equal(body.mtaStsPolicy.valid, false);
    assert.match(body.mtaStsPolicy.reason, /redirect/);
    assert.equal(body.mtaStsPolicy.redirect, "https://private.invalid/");
    assert.equal(fetchImpl.calls.at(-1).init.redirect, "manual");
    assert.equal(fetchImpl.calls.some((call) => call.url.startsWith("https://private.invalid/")), false);
  });
});

test("MTA-STS enforces the 64 KiB cap during streaming", async () => {
  const answers = { "_mta-sts.example.com|TXT": [{ type: 16, TTL: 60, data: "\"v=STSv1; id=one\"" }] };
  let chunks = 0;
  let cancelled = false;
  const stream = new ReadableStream({
    pull(controller) {
      chunks++;
      controller.enqueue(new Uint8Array(8192).fill(120));
    },
    cancel() { cancelled = true; },
  });
  await withFetch(createFetch({ answers, policy: { body: stream } }), async () => {
    const { body } = await lookup();
    assert.equal(body.mtaStsPolicy.valid, false);
    assert.equal(body.mtaStsPolicy.reason, "policy too large (> 64KB)");
    assert.equal(cancelled, true);
    assert.ok(chunks <= 10);
  });
  const prefix = "version: STSv1\nmode: none\nmax_age: 0\nextension: ";
  for (const size of [65536, 65537]) {
    await withFetch(createFetch({ answers, policy: { body: prefix + "x".repeat(size - prefix.length) } }), async () => {
      const { body } = await lookup();
      assert.equal(body.mtaStsPolicy.valid, size === 65536);
    });
  }
});

test("MTA-STS timeout covers both headers and body streaming", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  for (const phase of ["headers", "body"]) {
    const started = Promise.withResolvers();
    const dnsFetch = createFetch({
      answers: { "_mta-sts.example.com|TXT": [{ type: 16, TTL: 60, data: "\"v=STSv1; id=one\"" }] },
    });
    await withFetch(async (input, init) => {
      if (new URL(String(input)).hostname === "cloudflare-dns.com") return dnsFetch(input, init);
      started.resolve();
      if (phase === "headers") return new Promise((resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
      });
      return new Response(new ReadableStream({
        start(controller) {
          init.signal.addEventListener("abort", () => controller.error(init.signal.reason), { once: true });
        },
      }), { headers: { "content-type": "text/plain" } });
    }, async () => {
      const pending = lookup();
      await started.promise;
      context.mock.timers.tick(5000);
      const { body } = await pending;
      assert.equal(body.mtaStsPolicy.valid, false);
      assert.equal(body.mtaStsPolicy.reason, "timeout");
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

test("Mixed null MX and ordinary MX are reported as a configuration conflict", async () => {
  await withFetch(createFetch({
    answers: {
      "example.com|MX": [
        { type: 15, TTL: 60, data: "0 ." },
        { type: 15, TTL: 60, data: "10 mail.example.com." },
      ],
      "_mta-sts.example.com|TXT": [{ type: 16, TTL: 60, data: "\"v=STSv1; id=one\"" }],
    },
    policy: { body: "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n" },
  }), async () => {
    const { body } = await lookup();
    assert.equal(body.nullMx, false);
    assert.equal(body.nullMxConflict, true);
    assert.equal(body.dane[0].mx, "mail.example.com");
    assert.equal(body.mtaStsPolicy.valid, false);
    assert.match(body.mtaStsPolicy.reason, /null MX is combined/);
  });
});

test("DANE tries the secure canonical implicit MX before the original name", async () => {
  const domain = "alias.example.com";
  const canonical = "mail.example.net";
  const canonicalKey = `_25._tcp.${canonical}|TLSA`;
  const originalKey = `_25._tcp.${domain}|TLSA`;
  const tlsa = [{ type: 52, TTL: 60, data: `3 1 1 ${"ab".repeat(32)}` }];
  for (const scenario of ["secure", "missing", "insecure", "error", "unsigned-alias"]) {
    const fetchImpl = createFetch({
      answers: {
        [`${domain}|A`]: [
          { name: domain, type: 5, TTL: 60, data: `${canonical}.` },
          { name: canonical, type: 1, TTL: 60, data: "192.0.2.25" },
        ],
        [canonicalKey]: scenario === "missing" ? [] : tlsa,
        [originalKey]: tlsa,
      },
      statuses: { [canonicalKey]: scenario === "error" ? 2 : 0 },
      authenticated: {
        [`${domain}|A`]: scenario !== "unsigned-alias",
        [canonicalKey]: scenario !== "insecure",
        [originalKey]: true,
      },
    });
    await withFetch(fetchImpl, async () => {
      const { body } = await lookup(domain);
      const calls = fetchImpl.calls.map((call) => new URL(call.url))
        .filter((url) => url.searchParams.get("type") === "TLSA")
        .map((url) => url.searchParams.get("name"));
      if (scenario === "error") {
        assert.equal(body.dane[0].error, "DNS SERVFAIL (2)");
        assert.deepEqual(calls, [`_25._tcp.${canonical}`]);
      } else {
        assert.equal(body.dane[0].tlsa.length, 1);
        assert.equal(body.dane[0].dnssec, true);
        assert.equal(body.dane[0].tlsaBaseDomain, scenario === "secure" ? canonical : domain);
        assert.deepEqual(calls, scenario === "secure" ? [`_25._tcp.${canonical}`]
          : scenario === "unsigned-alias" ? [`_25._tcp.${domain}`]
            : [`_25._tcp.${canonical}`, `_25._tcp.${domain}`]);
      }
    });
  }
});

test("CNAME with NXDOMAIN denies the target, not the DMARC author domain", async () => {
  const domain = "alias.example.com";
  const target = "missing.example.net";
  const fetchImpl = createFetch({
    answers: {
      [`${domain}|NS`]: [{ name: domain, type: 5, TTL: 60, data: `${target}.` }],
      "_dmarc.example.com|TXT": [{
        type: 16, TTL: 60, data: "\"v=DMARC1; p=reject; sp=quarantine; np=none; psd=n\"",
      }],
    },
    statuses: { [`${domain}|NS`]: 3 },
  });
  await withFetch(fetchImpl, async () => {
    const { body } = await lookup(domain);
    assert.equal(body.status.ns, 3);
    assert.equal(body.domainExists, true);
    assert.equal(body.canonicalName, target);
    assert.deepEqual(body.aliases, [{ name: domain, target, ttl: 60 }]);
    assert.equal(body.dmarcDiscovery.effectivePolicy, "quarantine");
    assert.deepEqual(body.ns, []);
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

test("DMARC organizational policy takes precedence over a PSD policy", async () => {
  const fetchImpl = createFetch({
    answers: {
      "_dmarc.tenant.bank.example|TXT": [{
        type: 16,
        TTL: 300,
        data: "\"v=DMARC1; p=none; sp=quarantine\"",
      }],
      "_dmarc.bank.example|TXT": [{
        type: 16,
        TTL: 300,
        data: "\"v=DMARC1; p=reject; psd=y\"",
      }],
    },
  });
  await withFetch(fetchImpl, async () => {
    const { body } = await lookup("mail.tenant.bank.example");
    assert.equal(body.dmarcDiscovery.policyDomain, "tenant.bank.example");
    assert.equal(body.dmarcDiscovery.organizationalDomain, "tenant.bank.example");
    assert.equal(body.dmarcDiscovery.source, "organizational");
    assert.equal(body.dmarcDiscovery.effectivePolicy, "quarantine");
    assert.equal(body.dmarcDiscovery.queries.at(-1).domain, "bank.example");
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

test("DMARC invalid policy tags use reporting-only fallback or disable processing", async () => {
  for (const policy of [
    "p=invalid; sp=reject; np=reject",
    "p=reject; sp=invalid; np=reject",
    "p=reject; sp=reject; np=invalid",
    "sp=reject",
  ]) {
    for (const reporting of ["", "; rua=not-a-uri", "; rua=mailto:reports@example.com"]) {
      const fetchImpl = createFetch({
        answers: {
          "_dmarc.example.com|TXT": [{
            type: 16,
            TTL: 300,
            data: JSON.stringify(`v=DMARC1; ${policy}${reporting}; psd=n`),
          }],
          "_dmarc.com|TXT": [{ type: 16, TTL: 300, data: "\"v=DMARC1; p=reject; psd=y\"" }],
        },
      });
      await withFetch(fetchImpl, async () => {
        for (const domain of ["example.com", "mail.example.com"]) {
          const { body } = await lookup(domain);
          const reportingOnly = reporting.includes("mailto:");
          assert.equal(body.dmarcDiscovery.found, true);
          assert.equal(body.dmarcDiscovery.valid, reportingOnly);
          assert.equal(body.dmarcDiscovery.policyDomain, "example.com");
          assert.equal(body.dmarcDiscovery.effectivePolicy, reportingOnly ? "none" : null);
          assert.ok(body.dmarcDiscovery.warnings.length);
        }
      });
    }
  }
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
  const ui = await createUi();

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

  ui.render(data);
  const dmarcHeading = ui.out.innerHTML.match(/<h3>DMARC[\s\S]*?<\/h3>/)?.[0];
  const dkimHeading = ui.out.innerHTML.match(/<h3>DKIM[\s\S]*?<\/h3>/)?.[0];
  assert.match(dmarcHeading, />Found<\/span>/);
  assert.doesNotMatch(dmarcHeading, />OK<\/span>/);
  assert.match(dkimHeading, />Not found for selectors<\/span>/);

  data.dnssec.a = true;
  ui.render(data);
  const aHeading = ui.out.innerHTML.match(/<h3>A[\s\S]*?<\/h3>/)?.[0];
  const aaaaHeading = ui.out.innerHTML.match(/<h3>AAAA[\s\S]*?<\/h3>/)?.[0];
  assert.match(aHeading, />DNSSEC authenticated<\/span>/);
  assert.match(aaaaHeading, />DNSSEC not authenticated<\/span>/);

  data.status.dmarc = 2;
  data.errors.dmarc = "DNS SERVFAIL (2)";
  ui.render(data);
  const failedHeading = ui.out.innerHTML.match(/<h3>DMARC[\s\S]*?<\/h3>/)?.[0];
  assert.match(failedHeading, />Lookup failed<\/span>/);
  assert.doesNotMatch(failedHeading, />Missing<\/span>/);
});

test("UI retains inherited DMARC for NXDOMAIN and distinguishes dangling aliases", async () => {
  const ui = await createUi();
  for (const alias of [false, true]) {
    await withFetch(createFetch({
      statuses: { "mail.example.com|NS": 3 },
      answers: {
        "mail.example.com|NS": alias
          ? [{ name: "mail.example.com", type: 5, TTL: 60, data: "missing.example.net." }] : [],
        "_dmarc.example.com|TXT": [{
          type: 16, TTL: 60, data: "\"v=DMARC1; p=reject; sp=quarantine; np=none; psd=n\"",
        }],
      },
    }), async () => {
      const { body } = await lookup("mail.example.com");
      ui.render(body);
      assert.match(ui.out.innerHTML, /Inherited from/);
      assert.match(ui.out.innerHTML, alias ? /effective policy: <code>quarantine/ : /effective policy: <code>none/);
      assert.match(ui.out.innerHTML, alias ? /Alias .* exists, but its target/ : /Domain .* does not exist/);
      if (alias) assert.doesNotMatch(ui.out.innerHTML, /Domain <code>mail.example.com<\/code> does not exist/);
    });
  }
});

test("UI displays DMARC fallback warnings and conflicting null MX", async () => {
  const ui = await createUi();
  await withFetch(createFetch({
    answers: {
      "_dmarc.example.com|TXT": [{
        type: 16, TTL: 60, data: "\"v=DMARC1; p=reject; sp=invalid; rua=mailto:reports@example.com\"",
      }],
      "example.com|MX": [{ type: 15, TTL: 60, data: "0 ." }, { type: 15, TTL: 60, data: "10 mail.example.com." }],
    },
  }), async () => {
    const { body } = await lookup();
    ui.render(body);
    assert.match(ui.out.innerHTML, /ignored invalid sp tag/);
    assert.match(ui.out.innerHTML, /using p=none for reporting only/);
    assert.match(ui.out.innerHTML, /Conflicting MX records/);
    assert.doesNotMatch(ui.out.innerHTML, /explicitly does not accept email/);
  });
});

test("UI distinguishes MTA-STS syntax, MX mismatch, and unchecked SMTP TLS", async () => {
  const ui = await createUi();
  for (const matches of [true, false]) {
    await withFetch(createFetch({
      answers: {
        "_mta-sts.example.com|TXT": [{ type: 16, TTL: 60, data: "\"v=STSv1; id=one\"" }],
        "example.com|MX": [{ type: 15, TTL: 60, data: "10 mail.example.com." }],
      },
      policy: { body: `version: STSv1\nmode: enforce\nmx: ${matches ? "mail.example.com" : "unrelated.example.net"}\nmax_age: 604800\n` },
    }), async () => {
      const { body } = await lookup();
      ui.render(body);
      const heading = ui.out.innerHTML.match(/<h3>MTA-STS Policy[\s\S]*?<\/h3>/)?.[0];
      assert.match(heading, matches ? /Syntax and MX valid/ : /MX mismatch/);
      assert.match(ui.out.innerHTML, /SMTP TLS: not checked/);
      assert.match(ui.out.innerHTML, /Receiving MX: <code>mail.example.com/);
    });
  }
});

test("UI escapes DNS text, policy warnings, and lookup errors", async () => {
  const ui = await createUi();
  const payload = '<img src=x onerror="globalThis.compromised=true">';
  await withFetch(createFetch({
    answers: {
      "example.com|TXT": [{ type: 16, TTL: 60, data: JSON.stringify(`v=spf1 -all ${payload}`) }],
      "one._domainkey.example.com|TXT": [{ type: 16, TTL: 60, data: JSON.stringify(`v=DKIM1; p=${payload}`) }],
    },
  }), async () => {
    const { body } = await lookup("example.com", "one");
    body.dmarcDiscovery.warnings.push(payload);
    body.errors.a = payload;
    ui.render(body);
    assert.doesNotMatch(ui.out.innerHTML, /<img/);
    assert.match(ui.out.innerHTML, /&lt;img/);
    assert.match(ui.out.innerHTML, /&quot;/);
  });
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