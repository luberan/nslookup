import { expect, test } from "@playwright/test";

const domain = `${"a".repeat(50)}.${"b".repeat(50)}.example.com`;
const payload = '<img src=x onerror="globalThis.compromised=true">';

function lookupResult() {
  return {
    domain,
    domainExists: true,
    aliases: [],
    ns: [{ data: `ns.${domain}`, ttl: 60 }],
    a: [{ data: "192.0.2.10", ttl: 60 }],
    aaaa: [],
    mx: [{ preference: 10, exchange: `mail.${domain}`, ttl: 60 }],
    spf: [`v=spf1 -all ${payload}`],
    dkim: [{
      selector: "direct",
      cname: [],
      txt: [{ data: `v=DKIM1; p=${"A".repeat(2048)}`, ttl: 60 }],
      dnssec: { cname: true, txt: true },
      status: { cname: 0, txt: 0 },
    }],
    dkimCustom: true,
    dmarc: ["v=DMARC1; p=reject; sp=invalid; rua=mailto:reports@example.com"],
    dmarcDiscovery: {
      found: true,
      valid: true,
      inherited: true,
      policyDomain: "example.com",
      source: "organizational",
      requestedPolicy: "none",
      effectivePolicy: "none",
      warnings: ["invalid policy tags: using p=none for reporting only"],
    },
    mtaSts: ["v=STSv1; id=one"],
    mtaStsValidation: { found: true, valid: true },
    mtaStsPolicy: {
      found: true,
      valid: false,
      syntaxValid: true,
      tlsChecked: false,
      policy: { version: "STSv1", mode: "enforce", max_age: "604800", mx: ["unrelated.example.net"] },
      mxValidation: { checked: true, valid: false, hosts: [{ mx: `mail.${domain}`, matched: false }] },
      reason: "policy MX patterns do not match all receiving MX hosts",
    },
    tlsRpt: ["v=TLSRPTv1; rua=mailto:tls@example.com"],
    bimi: [],
    dane: [{
      mx: `mail.${domain}`,
      status: 0,
      dnssec: true,
      tlsa: [{ usage: 3, selector: 1, matchingType: 1, certData: "ab".repeat(32), ttl: 60 }],
    }],
    status: Object.fromEntries(["ns", "a", "aaaa", "mx", "txt", "dmarc", "mtaStsTxt", "tlsRpt", "bimi"].map((key) => [key, 0])),
    dnssec: { ns: true, mx: true },
    errors: {},
  };
}

test.beforeEach(async ({ page }) => {
  await page.route("https://www.lukasberan.cz/img/logo.png", (route) => route.fulfill({ status: 204 }));
});

test("long DNS results fit the viewport and remain safe under CSP", async ({ page }, testInfo) => {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  await page.route("**/api/dns?**", async (route) => {
    const url = new URL(route.request().url());
    expect(url.searchParams.get("name")).toBe(domain);
    expect(url.searchParams.get("selectors")).toBe("direct");
    await route.fulfill({ json: lookupResult() });
  });
  await page.goto("/");
  await page.locator("#name").fill(domain);
  await page.locator("summary").click();
  await page.locator("#selectors").fill("direct");
  await page.getByRole("button", { name: "Look up", exact: true }).click();
  const results = page.locator("#out");
  await expect(results.getByRole("heading", { name: "MTA-STS Policy MX mismatch", exact: true })).toBeVisible();
  await expect(results).toContainText("SMTP TLS: not checked");
  await expect(results).toContainText("using p=none for reporting only");
  await expect(results).toContainText(payload);
  await expect(results.locator("img, script, [onerror]")).toHaveCount(0);
  expect(await page.evaluate(() => globalThis.compromised)).toBeUndefined();

  const layout = await page.evaluate(() => {
    const width = document.documentElement.clientWidth;
    const elements = Array.from(document.querySelectorAll(".wrap, .card, .panel, input, button, details"));
    return {
      width,
      scrollWidth: document.documentElement.scrollWidth,
      overflowing: elements.filter((element) => {
        const bounds = element.getBoundingClientRect();
        return bounds.left < -1 || bounds.right > width + 1
          || (element.tagName !== "INPUT" && element.scrollWidth > element.clientWidth + 1);
      }).map((element) => element.tagName + "." + element.className),
      panelBackground: getComputedStyle(document.querySelector(".panel")).backgroundColor,
    };
  });
  expect(layout.scrollWidth).toBeLessThanOrEqual(layout.width + 1);
  expect(layout.overflowing).toEqual([]);
  expect(layout.panelBackground).toBe("rgb(18, 25, 52)");
  expect(errors).toEqual([]);
  await page.screenshot({ path: testInfo.outputPath("lookup.png"), fullPage: true });
});

test("NXDOMAIN and dangling aliases retain inherited DMARC details", async ({ page }) => {
  let alias = false;
  await page.route("**/api/dns?**", async (route) => {
    const result = lookupResult();
    result.domainExists = alias;
    result.status.ns = 3;
    result.canonicalName = "missing.example.net";
    result.aliases = alias ? [{ name: domain, target: result.canonicalName, ttl: 60 }] : [];
    result.nullMxConflict = true;
    await route.fulfill({ json: result });
  });
  await page.goto("/");
  await page.locator("#name").fill(domain);
  for (const hasAlias of [false, true]) {
    alias = hasAlias;
    await page.getByRole("button", { name: "Look up", exact: true }).click();
    const results = page.locator("#out");
    await expect(results).toContainText("Inherited from");
    await expect(results).toContainText("effective policy: none");
    await expect(results).toContainText("Conflicting MX records");
    await expect(results).not.toContainText("explicitly does not accept email");
    if (hasAlias) await expect(results).toContainText("exists, but its target");
    else await expect(results.locator(".notice").first()).toContainText(`Domain ${domain} does not exist`);
  }
});

test("real Worker serves security headers and rejects invalid API requests", async ({ request }) => {
  const html = await request.get("/");
  expect(html.status()).toBe(200);
  expect(html.headers()["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(html.headers()["content-security-policy"]).not.toContain("unsafe-inline");
  expect(html.headers()["x-content-type-options"]).toBe("nosniff");
  const missing = await request.get("/api/dns");
  expect(missing.status()).toBe(400);
  expect(await missing.json()).toEqual({ error: "Missing ?name parameter" });
  const invalid = await request.get("/api/dns?name=example.com&selectors=bad_selector");
  expect(invalid.status()).toBe(400);
  expect(invalid.headers()["access-control-allow-origin"]).toBe("*");
  const post = await request.post("/api/dns?name=example.com");
  expect(post.status()).toBe(405);
  expect(post.headers().allow).toBe("GET, OPTIONS");
});