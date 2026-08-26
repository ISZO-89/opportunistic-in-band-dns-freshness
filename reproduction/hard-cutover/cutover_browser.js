const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const sleep = ms =>
  new Promise(resolve => setTimeout(resolve, ms));

async function waitFile(file, label) {
  for (let i = 0; i < 300; i++) {
    if (fs.existsSync(file)) {
      console.log(label + "=PASS");
      return;
    }

    await sleep(100);
  }

  throw new Error(label + "_TIMEOUT");
}

async function nav(page, url, label) {
  const t0 = performance.now();

  const response = await page.goto(url, {
    waitUntil: "domcontentloaded",
    timeout: 20000
  });

  const elapsed =
    performance.now() - t0;

  const status =
    response ? response.status() : "NONE";

  console.log(label + "_STATUS=" + status);
  console.log(
    label + "_MS=" + elapsed.toFixed(3)
  );

  if (status !== 200) {
    throw new Error(
      label + "_HTTP_STATUS_" + status
    );
  }
}

(async () => {
  const profile =
    "/tmp/dnsfresh-zero-dns-profile";

  const origin =
    "https://a.service.test:4433";

  fs.rmSync(
    profile,
    {
      recursive: true,
      force: true
    }
  );

  fs.mkdirSync(
    profile,
    {
      recursive: true
    }
  );

  const localState = {
    dns_over_https: {
      mode: "secure",
      templates:
        "https://172.18.0.55:8443/dns-query{?dns}"
    }
  };

  fs.writeFileSync(
    path.join(profile, "Local State"),
    JSON.stringify(localState)
  );

  console.log(
    "LOCAL_STATE_DOH_MODE=secure"
  );

  console.log(
    "LOCAL_STATE_DOH_TEMPLATE=" +
    "https://172.18.0.55:8443/dns-query{?dns}"
  );

  const context =
    await chromium.launchPersistentContext(
      profile,
      {
        executablePath:
          "/native-chromium/chrome",

        headless: true,

        args: [
          "--no-sandbox",
          "--enable-logging=stderr",
          "--log-level=0",
          "--enable-quic",
          "--no-proxy-server",
          "--ignore-certificate-errors",
          "--disable-background-networking",
          "--disable-component-update",
          "--disable-default-apps",
          "--disable-sync",
          "--no-first-run",
          "--no-default-browser-check",
          "--origin-to-force-quic-on=" +
            "a.service.test:4433",
          "--ignore-certificate-errors-spki-list=" +
            process.env.ALL_SPKI
        ]
      }
    );

  console.log(
    "BROWSER_ENGINE=Chromium"
  );

  const pages =
    context.pages();

  const page =
    pages.length
      ? pages[0]
      : await context.newPage();

  try {
    console.log(
      "=== REQUEST 1 / SNAPSHOT ==="
    );

    await nav(
      page,
      origin + "/app/1",
      "REQUEST1"
    );

    fs.writeFileSync(
      "/control/request1.done",
      "PASS\n"
    );

    console.log(
      "BROWSER_WAIT_AFTER_REQUEST1=PASS"
    );

    await waitFile(
      "/control/continue",
      "CONTROL_REQUEST2_RELEASED"
    );

    console.log(
      "=== REQUEST 2 / DELTA ==="
    );

    await nav(
      page,
      origin + "/app/2",
      "REQUEST2"
    );

    fs.writeFileSync(
      "/control/request2.done",
      "PASS\n"
    );

    console.log(
      "BROWSER_WAIT_AFTER_REQUEST2=PASS"
    );

    await waitFile(
      "/control/continue3",
      "CONTROL_REQUEST3_RELEASED"
    );

    console.log(
      "=== REQUEST 3 / HARD CUTOVER ==="
    );

    await nav(
      page,
      origin + "/app/3",
      "REQUEST3"
    );

    console.log(
      "BROWSER_ZERO_DNS_SEQUENCE=PASS"
    );
  } finally {
    await context.close();
  }
})().catch(err => {
  console.error(
    "BROWSER_TEST_FAIL=" +
    err.stack
  );

  process.exit(1);
});
