/**
 * تست واقعی لیست سرورها با باینری رسمی Xray-core و آپدیت لیست کلودفلر.
 *
 * برخلاف نسخه‌ی اندرویدی (که به‌خاطر runtime مشترک Go در JNI فقط
 * می‌توانست یک هسته را در آنِ واحد اجرا کند)، اینجا هر تست یک پروسه‌ی
 * جدا و مستقل از سیستم‌عامل است (spawn شده با child_process)، پس
 * می‌توانیم چند ده‌تا را واقعاً موازی اجرا کنیم.
 *
 * محدودیت مهم: این تست از دیتاسنتر GitHub Actions (آمریکا/اروپا) اجرا
 * می‌شود، نه از داخل ایران. یعنی فقط سرورهای "مرده/منقضی" را می‌گیرد؛
 * فیلترینگ خاص یک اپراتور ایرانی را نمی‌سنجد.
 */

import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";

const execFileP = promisify(execFile);

// ---------------------------------------------------------------------
// تنظیمات از طریق متغیرهای محیطی
// ---------------------------------------------------------------------
const CF_ALL_URL = requireEnv("CF_ALL_URL");
const CF_UPDATE_URL = requireEnv("CF_UPDATE_URL");
const GH_RAW_URL = requireEnv("GH_RAW_URL");
const XRAY_BIN = process.env.XRAY_BIN || "./xray";

const MAX_CANDIDATES = Number(process.env.MAX_CANDIDATES || 300);
const CONCURRENCY = Number(process.env.CONCURRENCY || 12);
const CORE_WARMUP_MS = Number(process.env.CORE_WARMUP_MS || 400);

const TEST_TIMEOUT_S = Number(process.env.TEST_TIMEOUT_S || 5);
const TEST_URL = "https://www.gstatic.com/generate_204";
const BASE_PORT = 20000;

/**
 * محافظ در برابر حذف ناگهانی: چون Worker فعلی هیچ اعتبارسنجی روی بدنه‌ی
 * درخواست ندارد (هر آرایه‌ای را می‌پذیرد و جایگزین می‌کند)، این چک باید
 * اینجا در اسکریپت انجام شود. اگر لیست نهایی به‌طرز غیرمنتظره‌ای خیلی
 * کوچک‌تر از لیست فعلی شود، آپلود متوقف می‌شود.
 */
const MIN_KEEP_RATIO = Number(process.env.MIN_KEEP_RATIO || 0.5);

function requireEnv(name) {
  const v = process.env[name];

  if (!v) {
    console.error(`متغیر محیطی ${name} تنظیم نشده است.`);
    process.exit(1);
  }

  return v;
}

// ---------------------------------------------------------------------
// دریافت لیست‌ها
// ---------------------------------------------------------------------

async function fetchCloudflareServers(url) {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(15000),
  });

  const arr = await res.json();

  return arr
    .map((o, i) => ({
      uri: String(o.address || "").trim(),
      name: String(o.country || `کلودفلر-${i + 1}`),

      // "v2ray" برای سرورهای V2Ray
      // عدد برای SSTP
      port:
        o.port === "v2ray"
          ? "v2ray"
          : Number(o.port) || "v2ray",

      ping: Number(o.ping) || -1,
    }))
    .filter((s) => s.uri.length > 0);
}

async function fetchGithubConfigs(url) {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(15000),
  });

  let text = await res.text();

  // اگر کل محتوا base64 بود، decode کن
  const maybeDecoded = tryBase64Decode(text.trim());

  if (maybeDecoded && maybeDecoded.includes("://")) {
    text = maybeDecoded;
  }

  const schemes = [
    "vless://",
    "vmess://",
    "ss://",
    "trojan://",
    "hysteria2://",
    "hy2://",
  ];

  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) =>
      schemes.some((s) => l.startsWith(s))
    )
    .map((uri, i) => ({
      uri,
      name: `گیت‌هاب-${i + 1}`,
      port: "v2ray",
      ping: -1,
    }));
}

function tryBase64Decode(s) {
  try {
    return Buffer.from(s, "base64").toString("utf8");
  } catch {
    return null;
  }
}

const dedupKey = (uri) =>
  uri.trim().split("#")[0];

// ---------------------------------------------------------------------
// ساخت کانفیگ Xray
// ---------------------------------------------------------------------

function parseLinkToOutbound(link) {
  const scheme = link.split("://")[0];

  switch (scheme) {
    case "vless":
      return buildVless(link);

    case "vmess":
      return buildVmess(link);

    case "trojan":
      return buildTrojan(link);

    case "ss":
      return buildShadowsocks(link);

    case "hysteria2":
    case "hy2":
      return buildHysteria(link);

    default:
      throw new Error(
        `پروتکل پشتیبانی نمی‌شود: ${scheme}`
      );
  }
}

function buildStreamSettings({
  security,
  network,
  sni,
  fp,
  alpn,
  path,
  host,
  mode,
  serviceName,
  pbk,
  sid,
  spx,
}) {
  const s = {
    network,
    security,
  };

  if (security === "tls") {
    s.tlsSettings = {
      serverName: sni,
    };

    if (fp) {
      s.tlsSettings.fingerprint = fp;
    }

    if (alpn) {
      s.tlsSettings.alpn = alpn.split(",");
    }
  } else if (security === "reality") {
    s.realitySettings = {
      serverName: sni,
      publicKey: pbk || "",
    };

    if (fp) {
      s.realitySettings.fingerprint = fp;
    }

    if (sid) {
      s.realitySettings.shortId = sid;
    }

    if (spx) {
      s.realitySettings.spiderX = spx;
    }
  }

  if (network === "ws") {
    s.wsSettings = {
      path: path || "/",
      headers: {
        Host: host,
      },
    };
  } else if (network === "xhttp") {
    s.xhttpSettings = {
      path: path || "/",
      mode: mode || "auto",
      host,
    };
  } else if (network === "grpc") {
    s.grpcSettings = {
      serviceName: serviceName || "",
    };
  }

  return s;
}

function buildVless(link) {
  const u = new URL(link);

  const uuid = decodeURIComponent(u.username);
  const host = u.hostname;
  const port = Number(u.port) || 443;

  const q = (k, d = "") =>
    u.searchParams.get(k) || d;

  return {
    tag: "proxy",

    protocol: "vless",

    settings: {
      vnext: [
        {
          address: host,
          port,

          users: [
            {
              id: uuid,
              encryption: q(
                "encryption",
                "none"
              ),
            },
          ],
        },
      ],
    },

    streamSettings: buildStreamSettings({
      security: q("security", "none"),
      network: q("type", "tcp"),
      sni: q("sni", host),
      fp: q("fp"),
      alpn: q("alpn"),
      path: q("path", "/"),
      host: q("host", host),
      mode: q("mode", "auto"),
      serviceName: q("serviceName"),
      pbk: q("pbk"),
      sid: q("sid"),
      spx: q("spx"),
    }),
  };
}

function buildVmess(link) {
  const decoded = Buffer
    .from(
      link.replace("vmess://", ""),
      "base64"
    )
    .toString("utf8");

  const j = JSON.parse(decoded);

  const host = j.add;
  const port = Number(j.port) || 443;

  return {
    tag: "proxy",

    protocol: "vmess",

    settings: {
      vnext: [
        {
          address: host,
          port,

          users: [
            {
              id: j.id,
              alterId: Number(j.aid || 0),
              security: j.scy || "auto",
            },
          ],
        },
      ],
    },

    streamSettings: buildStreamSettings({
      security:
        j.tls === "tls"
          ? "tls"
          : "none",

      network: j.net || "tcp",

      sni:
        j.sni ||
        j.host ||
        host,

      fp: j.fp || "",
      alpn: j.alpn || "",

      path:
        j.path || "/",

      host:
        j.host || host,

      mode: "auto",

      serviceName:
        j.path || "",
    }),
  };
}

function buildTrojan(link) {
  const u = new URL(link);

  const password =
    decodeURIComponent(u.username);

  const host = u.hostname;

  const port =
    Number(u.port) || 443;

  const q = (k, d = "") =>
    u.searchParams.get(k) || d;

  return {
    tag: "proxy",

    protocol: "trojan",

    settings: {
      servers: [
        {
          address: host,
          port,
          password,
        },
      ],
    },

    streamSettings: buildStreamSettings({
      security: q("security", "tls"),
      network: q("type", "tcp"),
      sni: q("sni", host),
      fp: q("fp"),
      alpn: q("alpn"),
      path: q("path", "/"),
      host: q("host", host),
      mode: q("mode", "auto"),
      serviceName: q("serviceName"),
    }),
  };
}

function buildShadowsocks(link) {
  const withoutScheme =
    link
      .replace("ss://", "")
      .split("#")[0];

  let method;
  let password;
  let host;
  let port;

  if (withoutScheme.includes("@")) {
    const [
      userInfo,
      hostPart,
    ] = withoutScheme.split("@");

    let decodedUserInfo;

    try {
      decodedUserInfo =
        Buffer
          .from(userInfo, "base64url")
          .toString("utf8");
    } catch {
      decodedUserInfo =
        Buffer
          .from(userInfo, "base64")
          .toString("utf8");
    }

    [method, password] =
      decodedUserInfo.split(":");

    const hostPortStr =
      hostPart
        .split("/")[0]
        .split("?")[0];

    const idx =
      hostPortStr.lastIndexOf(":");

    host =
      hostPortStr.slice(0, idx);

    port =
      Number(
        hostPortStr.slice(idx + 1)
      );
  } else {
    const decodedFull =
      Buffer
        .from(withoutScheme, "base64")
        .toString("utf8");

    const [
      methodPass,
      hostPort,
    ] = decodedFull.split("@");

    [method, password] =
      methodPass.split(":");

    const idx =
      hostPort.lastIndexOf(":");

    host =
      hostPort.slice(0, idx);

    port =
      Number(
        hostPort.slice(idx + 1)
      );
  }

  return {
    tag: "proxy",

    protocol: "shadowsocks",

    settings: {
      servers: [
        {
          address: host,
          port,
          method,
          password,
        },
      ],
    },
  };
}

function buildHysteria(link) {
  const u = new URL(link);

  const auth =
    u.username
      ? decodeURIComponent(u.username)
      : "";

  const host = u.hostname;

  const port =
    Number(u.port) || 443;

  const q = (k, d = "") =>
    u.searchParams.get(k) || d;

  return {
    tag: "proxy",

    protocol: "hysteria",

    settings: {
      version: 2,
      address: host,
      port,
    },

    streamSettings: {
      network: "hysteria",
      security: "tls",

      tlsSettings: {
        serverName:
          q("sni", host),

        allowInsecure:
          q("insecure", "0") === "1",
      },

      hysteriaSettings: {
        version: 2,
        auth,
      },
    },
  };
}

function buildFullConfig(
  outbound,
  socksPort
) {
  return {
    log: {
      loglevel: "warning",
    },

    inbounds: [
      {
        listen: "127.0.0.1",
        port: socksPort,

        protocol: "socks",

        settings: {
          auth: "noauth",
          udp: false,
        },
      },
    ],

    outbounds: [
      outbound,

      {
        tag: "direct",
        protocol: "freedom",
      },
    ],
  };
}

// ---------------------------------------------------------------------
// تست یک سرور V2Ray
// ---------------------------------------------------------------------

async function testOne(server, port) {
  let outbound;

  try {
    outbound =
      parseLinkToOutbound(server.uri);
  } catch {
    return null;
  }

  const configPath =
    path.join(
      os.tmpdir(),
      `xray-test-${port}.json`
    );

  await fs.writeFile(
    configPath,
    JSON.stringify(
      buildFullConfig(
        outbound,
        port
      )
    )
  );

  const child = spawn(
    XRAY_BIN,
    [
      "run",
      "-c",
      configPath,
    ],
    {
      stdio: "ignore",
    }
  );

  try {
    await sleep(
      CORE_WARMUP_MS
    );

    const start = Date.now();

    const { stdout } =
      await execFileP(
        "curl",
        [
          "--socks5",
          `127.0.0.1:${port}`,

          "-m",
          String(TEST_TIMEOUT_S),

          "-s",
          "-o",
          "/dev/null",

          "-w",
          "%{http_code}",

          TEST_URL,
        ]
      );

    const elapsed =
      Date.now() - start;

    const code =
      stdout.trim();

    if (
      code === "204" ||
      (
        code.startsWith("2") &&
        code.length === 3
      )
    ) {
      return elapsed;
    }

    return null;
  } catch {
    return null;
  } finally {
    child.kill("SIGKILL");

    await fs.rm(
      configPath,
      {
        force: true,
      }
    );
  }
}

function sleep(ms) {
  return new Promise(
    (r) => setTimeout(r, ms)
  );
}

// ---------------------------------------------------------------------
// اجرای موازی V2Ray
// ---------------------------------------------------------------------

async function testAll(
  servers,
  concurrency
) {
  const healthy = [];
  const tested = new Set();

  let nextIndex = 0;
  let nextPort = BASE_PORT;

  async function worker() {
    while (true) {
      const i =
        nextIndex++;

      if (
        i >= servers.length
      ) {
        return;
      }

      const server =
        servers[i];

      const port =
        nextPort++;

      const ping =
        await testOne(
          server,
          port
        );

      tested.add(
        dedupKey(server.uri)
      );

      // پذیرفتن تمامی سرورهای متصل شده بدون شرط سقف پینگ
      if (ping != null) {
        healthy.push({
          ...server,
          ping,
        });

        console.log(
          `✅ سالم (${ping}ms): ${server.name}`
        );
      } else {
        console.log(
          `❌ ناسالم: ${server.name}`
        );
      }
    }
  }

  await Promise.all(
    Array.from(
      {
        length: concurrency,
      },
      worker
    )
  );

  healthy.sort(
    (a, b) =>
      a.ping - b.ping
  );

  return {
    healthy,
    tested,
  };
}

// ---------------------------------------------------------------------
// VPNGate / SSTP
// ---------------------------------------------------------------------

const VPNGATE_API_URL =
  "http://www.vpngate.net/api/iphone/";

const MAX_SSTP_CANDIDATES =
  Number(
    process.env.MAX_SSTP_CANDIDATES ||
    200
  );

const SSTP_CONCURRENCY =
  Number(
    process.env.SSTP_CONCURRENCY ||
    1
  );

const SSTP_TIMEOUT_MS =
  Number(
    process.env.SSTP_TIMEOUT_MS ||
    5000
  );

const SSTP_USERNAME =
  process.env.SSTP_USERNAME ||
  "vpn";

const SSTP_PASSWORD =
  process.env.SSTP_PASSWORD ||
  "vpn";

const SSTP_REAL_TUNNEL =
  process.env.SSTP_REAL_TUNNEL === "1";

const SSTP_INTERNET_TEST =
  process.env.SSTP_INTERNET_TEST !== "0";

const SSTP_TEST_URL =
  process.env.SSTP_TEST_URL ||
  "https://www.gstatic.com/generate_204";


async function fetchVpnGateServers() {
  const res =
    await fetch(
      VPNGATE_API_URL,
      {
        signal:
          AbortSignal.timeout(15000),
      }
    );

  if (!res.ok) {
    throw new Error(
      `VPNGate HTTP ${res.status}`
    );
  }

  const text =
    await res.text();

  const lines =
    text
      .replace(/\r/g, "")
      .split("\n")
      .slice(2, -2);

  const servers = [];

  for (const line of lines) {
    if (!line.trim()) {
      continue;
    }

    try {
      const cols =
        line.split(",");

      let rawHostName =
        String(
          cols[0] || ""
        ).trim();

      const ip =
        String(
          cols[1] || ""
        ).trim();

      const countryLong =
        String(
          cols[5] || "Unknown"
        ).trim();

      if (!rawHostName) {
        continue;
      }

      let hostName =
        rawHostName;

      if (
        !hostName.includes(".")
      ) {
        hostName =
          `${hostName}.opengw.net`;
      }

      if (
        !/^[a-zA-Z0-9.-]+$/.test(
          hostName
        )
      ) {
        continue;
      }

      const ovpnBase64 =
        cols
          .slice(14)
          .join(",")
          .trim();

      let ovpnConfig = "";

      if (ovpnBase64) {
        try {
          ovpnConfig =
            Buffer
              .from(
                ovpnBase64,
                "base64"
              )
              .toString("utf8");
        } catch {
          ovpnConfig = "";
        }
      }

      let port = null;

      const remoteLines =
        ovpnConfig.match(
          /^remote\s+\S+\s+\d+(?:\s+\S+)?/gm
        ) || [];

      for (
        const remoteLine
        of remoteLines
      ) {
        const parts =
          remoteLine
            .trim()
            .split(/\s+/);

        if (
          parts.length < 3
        ) {
          continue;
        }

        const candidatePort =
          Number(parts[2]);

        if (
          !Number.isInteger(
            candidatePort
          ) ||
          candidatePort < 1 ||
          candidatePort > 65535
        ) {
          continue;
        }

        if (
          parts[3] &&
          parts[3].toLowerCase() === "tcp"
        ) {
          port =
            candidatePort;

          break;
        }

        if (
          port === null
        ) {
          port =
            candidatePort;
        }
      }

      if (
        port === null
      ) {
        if (
          hostName.startsWith(
            "public-vpn-"
          )
        ) {
          port = 443;
        } else {
          continue;
        }
      }

      if (
        !Number.isInteger(port) ||
        port < 1 ||
        port > 65535
      ) {
        continue;
      }

      servers.push({
        uri:
          hostName,

        name:
          countryLong ||
          hostName,

        port,

        ip,

        hostName,

        rawHostName,

        ping: -1,
      });

    } catch (e) {
      console.log(
        `⚠️ خطا در پردازش یک خط VPNGate: ${e.message}`
      );
    }
  }

  const unique = [];
  const seen = new Set();

  for (
    const server
    of servers
  ) {
    const key =
      `${server.hostName}:${server.port}`;

    if (
      seen.has(key)
    ) {
      continue;
    }

    seen.add(key);

    unique.push(
      server
    );
  }

  return unique;
}


async function testSstpReal(
  server,
  timeoutMs = SSTP_TIMEOUT_MS
) {
  const host =
    server.hostName ||
    server.uri;

  const port =
    Number(server.port) || 443;

  const started =
    Date.now();

  let child = null;
  let pppInterface = null;
  let output = "";
  let settled = false;

  const finish =
    async (
      ok,
      reason = ""
    ) => {
      if (settled) {
        return null;
      }

      settled = true;

      if (child?.pid) {
        try {
          process.kill(
            -child.pid,
            "SIGTERM"
          );
        } catch {
          try {
            child.kill("SIGTERM");
          } catch {}
        }

        await sleep(1200);

        try {
          process.kill(
            -child.pid,
            "SIGKILL"
          );
        } catch {
          try {
            child.kill("SIGKILL");
          } catch {}
        }
      }

      if (pppInterface) {
        try {
          await execFileP(
            "sudo",
            [
              "-n",
              "ip",
              "link",
              "set",
              pppInterface,
              "down",
            ],
            {
              timeout: 3000,
            }
          );
        } catch {}
      }

      return ok
        ? Date.now() - started
        : null;
    };

  try {
    const args = [
      "-n",
      "sstpc",

      "--log-stderr",
      "--log-level",
      "3",

      "--cert-warn",
      "--tls-ext",
      "--save-server-route",

      "--user",
      SSTP_USERNAME,

      "--password",
      SSTP_PASSWORD,

      `${host}:${port}`,

      "usepeerdns",
      "require-mschap-v2",
      "noauth",
      "noipdefault",
      "defaultroute",

      "refuse-eap",
      "refuse-pap",
      "refuse-chap",
      "refuse-mschap",

      "nobsdcomp",
      "nodeflate",
    ];

    child =
      spawn(
        "sudo",
        args,
        {
          detached: true,
          stdio: [
            "ignore",
            "pipe",
            "pipe",
          ],
        }
      );

    child.stdout.on(
      "data",
      (d) => {
        output +=
          d.toString();
      }
    );

    child.stderr.on(
      "data",
      (d) => {
        output +=
          d.toString();
      }
    );

    let childExitInfo = null;

    child.once(
      "exit",
      (code, signal) => {
        childExitInfo = {
          code,
          signal,
        };
      }
    );

    child.once(
      "error",
      (err) => {
        childExitInfo = {
          error: err.message,
        };
      }
    );

    const deadline =
      Date.now() + timeoutMs;

    while (
      Date.now() < deadline
    ) {
      await sleep(500);

      let links = "";

      try {
        const result =
          await execFileP(
            "ip",
            [
              "-o",
              "link",
              "show",
              "type",
              "ppp",
            ],
            {
              timeout: 3000,
            }
          );

        links =
          result.stdout || "";
      } catch {}

      const match =
        links.match(
          /^\d+:\s+(ppp\d+):/m
        );

      if (match) {
        pppInterface =
          match[1];

        let address = "";

        try {
          const result =
            await execFileP(
              "ip",
              [
                "-4",
                "addr",
                "show",
                "dev",
                pppInterface,
              ],
              {
                timeout: 3000,
              }
            );

          address =
            result.stdout || "";
        } catch {}

        if (
          /inet\s+\d+\.\d+\.\d+\.\d+/
            .test(address)
        ) {
          break;
        }
      }

      if (childExitInfo) {
        return await finish(
          false,
          `sstpc قبل از PPP خارج شد: ${JSON.stringify(childExitInfo)}`
        );
      }
    }

    if (!pppInterface) {
      return await finish(
        false,
        "PPP interface ساخته نشد / timeout"
      );
    }

    if (SSTP_INTERNET_TEST) {
      const curlStart =
        Date.now();

      try {
        const { stdout } =
          await execFileP(
            "curl",
            [
              "--interface",
              pppInterface,

              "-4",

              "--connect-timeout",
              "8",

              "--max-time",
              "12",

              "-sS",

              "-o",
              "/dev/null",

              "-w",
              "%{http_code}",

              SSTP_TEST_URL,
            ],
            {
              timeout: 15000,
            }
          );

        const code =
          stdout.trim();

        if (
          code === "204" ||
          (
            code.startsWith("2") &&
            code.length === 3
          )
        ) {
          const elapsed =
            Date.now() - started;

          return await finish(
            true,
            `PPP=${pppInterface}, HTTP=${code}`
          );
        }

        return await finish(
          false,
          `اینترنت ناموفق؛ HTTP=${code || "empty"}`
        );
      } catch (e) {
        return await finish(
          false,
          `تست اینترنت شکست خورد: ${e.code || e.message}`
        );
      }
    }

    return await finish(
      true,
      `PPP=${pppInterface}`
    );
  } catch (e) {
    return await finish(
      false,
      `خطای SSTP: ${e.code || e.message}`
    );
  }
}

function testSstpHandshake(
  host,
  port = 443,
  timeoutMs = SSTP_TIMEOUT_MS
) {
  return new Promise(
    (resolve) => {
      let settled = false;
      let buffer = "";

      const start =
        Date.now();

      const socket =
        tls.connect({
          host,
          port,

          servername: host,

          rejectUnauthorized: false,

          timeout: timeoutMs,
        });

      const finish =
        (
          ok,
          reason
        ) => {
          if (settled) {
            return;
          }

          settled = true;

          socket.destroy();

          resolve(
            ok
              ? Date.now() - start
              : null
          );
        };

      socket.on(
        "secureConnect",
        () => {
          const guid =
            "BA195980-CD49-458b-9E23-C84EE0ADCD75";

          const correlation =
            cryptoRandomUuid();

          const req =
            `SSTP_DUPLEX_POST /sra_{${guid}} HTTP/1.1\r\n` +
            `Content-Length: 18446744073709551615\r\n` +
            `Host: ${host}\r\n` +
            `SSTPCORRELATIONID: {${correlation}}\r\n\r\n`;

          socket.write(req);
        }
      );

      socket.on(
        "data",
        (chunk) => {
          buffer +=
            chunk.toString(
              "latin1"
            );

          if (
            buffer.includes(
              "\r\n\r\n"
            ) ||
            buffer.length > 512
          ) {
            const firstLine =
              buffer.split(
                "\r\n"
              )[0];

            finish(
              /^HTTP\/1\.1 200/.test(
                buffer
              ),
              `پاسخ: "${firstLine}"`
            );
          }
        }
      );

      socket.on(
        "timeout",
        () =>
          finish(
            false,
            "timeout"
          )
      );

      socket.on(
        "error",
        (err) =>
          finish(
            false,
            `TLS: ${err.code || err.message}`
          )
      );

      socket.on(
        "close",
        () =>
          finish(
            false,
            "اتصال بسته شد"
          )
      );
    }
  );
}

function cryptoRandomUuid() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    .replace(
      /[xy]/g,
      (c) => {
        const r =
          Math.random() * 16 | 0;

        const v =
          c === "x"
            ? r
            : (r & 0x3 | 0x8);

        return v.toString(16);
      }
    );
}

// ---------------------------------------------------------------------
// تست تمام SSTPها
// ---------------------------------------------------------------------

async function testAllSstp(
  servers,
  concurrency
) {
  const healthy = [];
  const tested = new Set();

  let nextIndex = 0;

  async function worker() {
    while (true) {
      const i =
        nextIndex++;

      if (
        i >= servers.length
      ) {
        return;
      }

      const server =
        servers[i];

      const key =
        dedupKey(server.uri);

      tested.add(key);

      console.log(
        `🔎 [SSTP] تست ${i + 1}/${servers.length}: ` +
        `${server.uri}:${server.port}`
      );

      let ping;

      if (SSTP_REAL_TUNNEL) {
        ping =
          await testSstpReal(
            server,
            SSTP_TIMEOUT_MS
          );
      } else {
        ping =
          await testSstpHandshake(
            server.uri,
            server.port,
            SSTP_TIMEOUT_MS
          );
      }

      // پذیرفتن تمامی سرورهای متصل شده بدون شرط سقف پینگ
      if (ping != null) {
        healthy.push({
          ...server,
          ping,
        });

        if (!SSTP_REAL_TUNNEL) {
          console.log(
            `✅ [SSTP handshake] سالم (${ping}ms): ` +
            `${server.uri}:${server.port}`
          );
        }
      } else {
        console.log(
          `❌ [SSTP] ناسالم: ` +
          `${server.uri}:${server.port}`
        );
      }
    }
  }

  await Promise.all(
    Array.from(
      {
        length: concurrency,
      },
      worker
    )
  );

  healthy.sort(
    (a, b) =>
      a.ping - b.ping
  );

  return {
    healthy,
    tested,
  };
}

// ---------------------------------------------------------------------
// اجرای اصلی اسکریپت (Main)
// ---------------------------------------------------------------------

async function main() {
  console.log("🚀 شروع فرایند تست و بروزرسانی سرورها...");

  // ۱. دریافت لیست سرورهای فعلی موجود در Worker
  console.log("📥 در حال دریافت سرورهای فعلی از Cloudflare...");
  let currentServers = [];
  try {
    currentServers = await fetchCloudflareServers(CF_ALL_URL);
    console.log(`تعداد سرورهای فعلی کلودفلر: ${currentServers.length}`);
  } catch (e) {
    console.warn(`⚠️ خطا در دریافت لیست فعلی کلودفلر: ${e.message}`);
  }

  // ۲. دریافت کاندیداهای جدید از GitHub و VPNGate
  console.log("📥 در حال دریافت لیست‌های جدید...");
  const ghServers = await fetchGithubConfigs(GH_RAW_URL).catch((e) => {
    console.error(`⚠️ خطا در دریافت کانفیگ‌های GitHub: ${e.message}`);
    return [];
  });

  const vpnGateServers = await fetchVpnGateServers().catch((e) => {
    console.error(`⚠️ خطا در دریافت سرورهای VPNGate: ${e.message}`);
    return [];
  });

  // ۳. جداکردن سرورها بر اساس نوع (V2Ray / SSTP)
  const currentV2ray = currentServers.filter((s) => s.port === "v2ray");
  const currentSstp = currentServers.filter((s) => s.port !== "v2ray");

  // ترکیب و یکتاکردن سرورهای V2Ray
  const v2rayMap = new Map();
  for (const s of [...ghServers, ...currentV2ray]) {
    const key = dedupKey(s.uri);
    if (!v2rayMap.has(key)) {
      v2rayMap.set(key, s);
    }
  }
  const v2rayCandidates = Array.from(v2rayMap.values()).slice(0, MAX_CANDIDATES);

  // ترکیب و یکتاکردن سرورهای SSTP
  const sstpMap = new Map();
  for (const s of [...vpnGateServers, ...currentSstp]) {
    const key = `${s.hostName || s.uri}:${s.port}`;
    if (!sstpMap.has(key)) {
      sstpMap.set(key, s);
    }
  }
  const sstpCandidates = Array.from(sstpMap.values()).slice(0, MAX_SSTP_CANDIDATES);

  console.log(`📊 آماده‌سازی تست: ${v2rayCandidates.length} سرور V2Ray و ${sstpCandidates.length} سرور SSTP`);

  // ۴. تست موازی V2Ray
  console.log("\n🧪 شروع تست سرورهای V2Ray...");
  const { healthy: healthyV2ray, tested: testedV2rayKeys } = await testAll(
    v2rayCandidates,
    CONCURRENCY
  );

  // ۵. تست موازی SSTP
  console.log("\n🧪 شروع تست سرورهای SSTP...");
  const { healthy: healthySstp, tested: testedSstpKeys } = await testAllSstp(
    sstpCandidates,
    SSTP_CONCURRENCY
  );

  // ۶. ادغام سرورهای سالم
  const finalHealthy = [...healthyV2ray, ...healthySstp];

  // اگر سروری در لیست قبلی بوده اما در این نوبت تست نشده باشد، نگه‌داری می‌شود
  for (const s of currentServers) {
    const isV2ray = s.port === "v2ray";
    const key = isV2ray ? dedupKey(s.uri) : `${s.hostName || s.uri}:${s.port}`;
    const wasTested = isV2ray ? testedV2rayKeys.has(key) : testedSstpKeys.has(key);

    if (!wasTested) {
      finalHealthy.push(s);
    }
  }

  console.log(`\n🎉 مجموع سرورهای سالم نهایی: ${finalHealthy.length}`);

  // ۷. بررسی مکانیزم محافظتی (MIN_KEEP_RATIO)
  if (currentServers.length > 0) {
    const minRequired = Math.floor(currentServers.length * MIN_KEEP_RATIO);
    if (finalHealthy.length < minRequired) {
      console.error(
        `❌ تعداد سرورهای سالم (${finalHealthy.length}) کمتر از حد مجاز (${minRequired}) است. به‌روزرسانی لغو شد.`
      );
      process.exit(1);
    }
  }
}

main();
