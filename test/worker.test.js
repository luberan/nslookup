import assert from "node:assert/strict";
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

async function lookup(name = "example.com") {
  const response = await worker.fetch(
    new Request(`https://local.test/api/dns?name=${encodeURIComponent(name)}`)
  );
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
    if (url.hostname === "mta-sts.example.com" && policy) {
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

test("UI distinguishes found, valid, missing, and lookup failure", async () => {
  const response = await worker.fetch(new Request("https://local.test/"));
  const html = await response.text();
  const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
  assert.ok(script);

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

  data.status.dmarc = 2;
  data.errors.dmarc = "DNS SERVFAIL (2)";
  context.__ui.render(data);
  const failedHeading = context.__ui.out.innerHTML.match(/<h3>DMARC[\s\S]*?<\/h3>/)?.[0];
  assert.match(failedHeading, />Lookup failed<\/span>/);
  assert.doesNotMatch(failedHeading, />Missing<\/span>/);
});