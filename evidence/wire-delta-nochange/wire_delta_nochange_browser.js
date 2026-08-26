const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const ORIGIN = "https://a.service.test:4433";
const CONTROL = "/control";

const sleep = (ms) =>
  new Promise(resolve => setTimeout(resolve, ms));

async function waitFor(name) {
  const file = path.join(CONTROL, name);

  for (let i = 0; i < 300; i++) {
    if (fs.existsSync(file))
      return;

    await sleep(100);
  }

  throw new Error("TIMEOUT_WAITING_FOR_" + name);
}

async function doRequest(page, url, label, expectFreshness) {
  const t0 = performance.now();

  const response = await page.goto(url, {
    waitUntil: "domcontentloaded",
    timeout: 20000
  });

  const ms = performance.now() - t0;

  if (!response)
    throw new Error(label + "_NO_RESPONSE");

  const status = response.status();
  const headers = await response.allHeaders();

  const hasFreshness =
    Object.keys(headers).some(
      k => k.toLowerCase() === "dns-freshness-object"
    );

  console.log(label + "_STATUS=" + status);
  console.log(label + "_MS=" + ms.toFixed(3));
  console.log(
    label + "_FRESHNESS_OBJECT=" +
    (hasFreshness ? "YES" : "NO")
  );

  if (status !== 200)
    throw new Error(label + "_HTTP_" + status);

  if (hasFreshness !== expectFreshness)
    throw new Error(label + "_FRESHNESS_MISMATCH");
}

(async () => {
  const profile = "/tmp/dnsfresh-wire-profile";

  fs.rmSync(profile, {
    recursive: true,
    force: true
  });

  fs.mkdirSync(profile, {
    recursive: true
  });

  fs.writeFileSync(
    path.join(profile, "Local State"),
    JSON.stringify({
      dns_over_https: {
        mode: "secure",
        templates:
          "https://172.18.0.55:8443/dns-query{?dns}"
      }
    })
  );

  const context =
    await chromium.launchPersistentContext(
      profile,
      {
        executablePath: "/native-chromium/chrome",
        headless: true,

        args: [
          "--no-sandbox",
          "--enable-logging=stderr",
          "--log-level=0",
          "--enable-quic",
          "--no-proxy-server",
          "--ignore-certificate-errors",
          "--disable-background-networking",
          "--origin-to-force-quic-on=a.service.test:4433",
          "--ignore-certificate-errors-spki-list=" +
            process.env.ALL_SPKI
        ]
      }
    );

  const pages = context.pages();
  const page =
    pages.length ? pages[0] : await context.newPage();

  try {
    await doRequest(
      page,
      ORIGIN + "/app/1",
      "REQUEST1",
      true
    );

    fs.writeFileSync(
      path.join(CONTROL, "request1.done"),
      "PASS\n"
    );

    await waitFor("release2");

    await doRequest(
      page,
      ORIGIN + "/app/2",
      "REQUEST2",
      true
    );

    fs.writeFileSync(
      path.join(CONTROL, "request2.done"),
      "PASS\n"
    );

    await waitFor("release3");

    await doRequest(
      page,
      ORIGIN + "/app/3",
      "REQUEST3",
      false
    );

    fs.writeFileSync(
      path.join(CONTROL, "request3.done"),
      "PASS\n"
    );

    console.log(
      "DELTA_NOCHANGE_BROWSER_SEQUENCE=PASS"
    );
  } finally {
    await context.close();
  }
})().catch(err => {
  console.error(
    "BROWSER_TEST_FAIL=" + err.stack
  );
  process.exit(1);
});
