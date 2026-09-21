/**
 * تست واقعی لیست سرورها با Xray-core و SSTP/VPNGate
 * و آپدیت لیست Cloudflare.
 */

import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import crypto from "node:crypto";

const execFileP = promisify(execFile);

// ================================================================
// Environment
// ================================================================

const CF_ALL_URL = requireEnv("CF_ALL_URL");
const CF_UPDATE_URL = requireEnv("CF_UPDATE_URL");
const GH_RAW_URL = requireEnv("GH_RAW_URL");

const XRAY_BIN = process.env.XRAY_BIN || "./xray";

const MAX_CANDIDATES =
  Number(process.env.MAX_CANDIDATES || 300);

const CONCURRENCY =
  Number(process.env.CONCURRENCY || 12);

const CORE_WARMUP_MS =
  Number(process.env.CORE_WARMUP_MS || 400);

const TEST_TIMEOUT_S =
  Number(process.env.TEST_TIMEOUT_S || 6);

const TEST_URL =
  "https://www.gstatic.com/generate_204";

const BASE_PORT = 20000;

// ================================================================
// SSTP / VPNGate
// ================================================================

const VPNGATE_API_URL =
  "http://www.vpngate.net/api/iphone/";

/*
 * استاندارد SSTP GUID
 */
const SSTP_GUID =
  "BA195980-CD49-458b-9E23-C84EE0ADCD75";

const MAX_SSTP_CANDIDATES =
  Number(process.env.MAX_SSTP_CANDIDATES || 200);

const SSTP_CONCURRENCY =
  Number(process.env.SSTP_CONCURRENCY || 10);

const SSTP_TIMEOUT_MS =
  Number(process.env.SSTP_TIMEOUT_MS || 10000);

const MIN_KEEP_RATIO =
  Number(process.env.MIN_KEEP_RATIO || 0.5);

// ================================================================
// Helpers
// ================================================================

function requireEnv(name) {
  const value = process.env[name];

  if (!value) {
    console.error(
      `متغیر محیطی ${name} تنظیم نشده است.`
    );

    process.exit(1);
  }

  return value;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ================================================================
// Cloudflare servers
// ================================================================

async function fetchCloudflareServers(url) {

  const res = await fetch(url, {
    signal: AbortSignal.timeout(15000)
  });

  if (!res.ok) {
    throw new Error(
      `Cloudflare HTTP ${res.status}`
    );
  }

  const arr = await res.json();

  return arr
    .map((o, i) => ({
      uri: String(o.address || "").trim(),

      name: String(
        o.country || `کلودفلر-${i + 1}`
      ),

      port:
        o.port === "v2ray"
          ? "v2ray"
          : Number(o.port) || "v2ray",

      ping: -1
    }))

    .filter(
      s => s.uri.length > 0
    );
}

// ================================================================
// GitHub configs
// ================================================================

async function fetchGithubConfigs(url) {

  const res = await fetch(url, {
    signal: AbortSignal.timeout(15000)
  });

  if (!res.ok) {
    throw new Error(
      `GitHub HTTP ${res.status}`
    );
  }

  let text = await res.text();

  const decoded =
    tryBase64Decode(text.trim());

  if (
    decoded &&
    decoded.includes("://")
  ) {
    text = decoded;
  }

  const schemes = [
    "vless://",
    "vmess://",
    "ss://",
    "trojan://",
    "hysteria2://",
    "hy2://"
  ];

  return text
    .split("\n")
    .map(line => line.trim())
    .filter(line =>
      schemes.some(
        scheme => line.startsWith(scheme)
      )
    )
    .map((uri, i) => ({
      uri,
      name: `گیت‌هاب-${i + 1}`,
      port: "v2ray",
      ping: -1
    }));
}

function tryBase64Decode(s) {

  try {
    return Buffer
      .from(s, "base64")
      .toString("utf8");
  } catch {
    return null;
  }
}

const dedupKey = uri =>
  uri.trim().split("#")[0];

// ================================================================
// Xray parsers
// ================================================================

function parseLinkToOutbound(link) {

  const scheme =
    link.split("://")[0].toLowerCase();

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

// ================================================================
// Stream settings
// ================================================================

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
  spx
}) {

  const s = {
    network,
    security
  };

  if (security === "tls") {

    s.tlsSettings = {
      serverName: sni
    };

    if (fp) {
      s.tlsSettings.fingerprint = fp;
    }

    if (alpn) {
      s.tlsSettings.alpn =
        alpn.split(",");
    }
  }

  else if (security === "reality") {

    s.realitySettings = {
      serverName: sni,
      publicKey: pbk || ""
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
        Host: host
      }
    };
  }

  else if (network === "xhttp") {

    s.xhttpSettings = {
      path: path || "/",
      mode: mode || "auto",
      host
    };
  }

  else if (network === "grpc") {

    s.grpcSettings = {
      serviceName: serviceName || ""
    };
  }

  return s;
}

// ================================================================
// VLESS
// ================================================================

function buildVless(link) {

  const u = new URL(link);

  const uuid =
    decodeURIComponent(u.username);

  const host = u.hostname;

  const port =
    Number(u.port) || 443;

  const q = (key, defaultValue = "") =>
    u.searchParams.get(key) ||
    defaultValue;

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

              encryption:
                q("encryption", "none")
            }
          ]
        }
      ]
    },

    streamSettings:
      buildStreamSettings({

        security:
          q("security", "none"),

        network:
          q("type", "tcp"),

        sni:
          q("sni", host),

        fp:
          q("fp"),

        alpn:
          q("alpn"),

        path:
          q("path", "/"),

        host:
          q("host", host),

        mode:
          q("mode", "auto"),

        serviceName:
          q("serviceName"),

        pbk:
          q("pbk"),

        sid:
          q("sid"),

        spx:
          q("spx")
      })
  };
}

// ================================================================
// VMESS
// ================================================================

function buildVmess(link) {

  const decoded =
    Buffer
      .from(
        link.replace("vmess://", ""),
        "base64"
      )
      .toString("utf8");

  const j =
    JSON.parse(decoded);

  const host = j.add;

  const port =
    Number(j.port) || 443;

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

              alterId:
                Number(j.aid || 0),

              security:
                j.scy || "auto"
            }

          ]
        }

      ]
    },

    streamSettings:
      buildStreamSettings({

        security:
          j.tls === "tls"
            ? "tls"
            : "none",

        network:
          j.net || "tcp",

        sni:
          j.sni ||
          j.host ||
          host,

        fp:
          j.fp || "",

        alpn:
          j.alpn || "",

        path:
          j.path || "/",

        host:
          j.host || host,

        mode:
          "auto",

        serviceName:
          j.path || ""
      })
  };
}

// ================================================================
// TROJAN
// ================================================================

function buildTrojan(link) {

  const u =
    new URL(link);

  const password =
    decodeURIComponent(u.username);

  const host =
    u.hostname;

  const port =
    Number(u.port) || 443;

  const q = (key, defaultValue = "") =>
    u.searchParams.get(key) ||
    defaultValue;

  return {

    tag: "proxy",

    protocol: "trojan",

    settings: {

      servers: [
        {
          address: host,
          port,
          password
        }
      ]
    },

    streamSettings:
      buildStreamSettings({

        security:
          q("security", "tls"),

        network:
          q("type", "tcp"),

        sni:
          q("sni", host),

        fp:
          q("fp"),

        alpn:
          q("alpn"),

        path:
          q("path", "/"),

        host:
          q("host", host),

        mode:
          q("mode", "auto"),

        serviceName:
          q("serviceName")
      })
  };
}

// ================================================================
// Shadowsocks
// ================================================================

function buildShadowsocks(link) {

  const withoutScheme =
    link
      .replace("ss://", "")
      .split("#")[0];

  let method;
  let password;
  let host;
  let port;

  if (
    withoutScheme.includes("@")
  ) {

    const [
      userInfo,
      hostPart
    ] =
      withoutScheme.split("@");

    let decodedUserInfo;

    try {

      decodedUserInfo =
        Buffer
          .from(
            userInfo,
            "base64url"
          )
          .toString("utf8");

    } catch {

      decodedUserInfo =
        Buffer
          .from(
            userInfo,
            "base64"
          )
          .toString("utf8");
    }

    [
      method,
      password
    ] =
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
  }

  else {

    const decodedFull =
      Buffer
        .from(
          withoutScheme,
          "base64"
        )
        .toString("utf8");

    const [
      methodPass,
      hostPort
    ] =
      decodedFull.split("@");

    [
      method,
      password
    ] =
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
          password
        }
      ]
    }
  };
}

// ================================================================
// Hysteria
// ================================================================

function buildHysteria(link) {

  const u =
    new URL(link);

  const auth =
    u.username
      ? decodeURIComponent(u.username)
      : "";

  const host =
    u.hostname;

  const port =
    Number(u.port) || 443;

  const q = (key, defaultValue = "") =>
    u.searchParams.get(key) ||
    defaultValue;

  return {

    tag: "proxy",

    protocol: "hysteria",

    settings: {

      version: 2,

      address: host,

      port
    },

    streamSettings: {

      network: "hysteria",

      security: "tls",

      tlsSettings: {

        serverName:
          q("sni", host),

        allowInsecure:
          q("insecure", "0") === "1"
      },

      hysteriaSettings: {

        version: 2,

        auth
      }
    }
  };
}

// ================================================================
// Xray config
// ================================================================

function buildFullConfig(
  outbound,
  socksPort
) {

  return {

    log: {
      loglevel: "warning"
    },

    inbounds: [

      {
        listen: "127.0.0.1",

        port: socksPort,

        protocol: "socks",

        settings: {
          auth: "noauth",
          udp: false
        }
      }

    ],

    outbounds: [

      outbound,

      {
        tag: "direct",
        protocol: "freedom"
      }

    ]
  };
}

// ================================================================
// Test Xray server
// ================================================================

async function testOne(
  server,
  port
) {

  let outbound;

  try {

    outbound =
      parseLinkToOutbound(
        server.uri
      );

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

  const child =
    spawn(
      XRAY_BIN,
      [
        "run",
        "-c",
        configPath
      ],
      {
        stdio: "ignore"
      }
    );

  try {

    await sleep(
      CORE_WARMUP_MS
    );

    if (
      child.exitCode !== null
    ) {
      return null;
    }

    const start =
      Date.now();

    const {
      stdout
    } =
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

          TEST_URL
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

    try {
      child.kill("SIGKILL");
    } catch {}

    await fs.rm(
      configPath,
      {
        force: true
      }
    );
  }
}

// ================================================================
// Test all Xray
// ================================================================

async function testAll(
  servers,
  concurrency
) {

  const healthy = [];

  const tested = new Set();

  let nextIndex = 0;

  let nextPort =
    BASE_PORT;

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

      if (
        ping != null
      ) {

        healthy.push({
          ...server,
          ping
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
        length: concurrency
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
    tested
  };
}

// ================================================================
// VPNGate / SSTP
// ================================================================

async function fetchVpnGateServers() {

  console.log(
    "دریافت لیست VPNGate..."
  );

  const res =
    await fetch(
      VPNGATE_API_URL,
      {
        signal:
          AbortSignal.timeout(15000)
      }
    );

  if (!res.ok) {

    throw new Error(
      `VPNGate API HTTP ${res.status}`
    );
  }

  const text =
    await res.text();

  const lines =
    text
      .replace(/\r/g, "")
      .split("\n");

  const servers = [];

  for (
    const line of lines
  ) {

    const trimmed =
      line.trim();

    if (
      !trimmed ||
      trimmed.startsWith("#") ||
      trimmed.startsWith("*")
    ) {
      continue;
    }

    try {

      const cols =
        trimmed.split(",");

      /*
       * VPNGate API:
       *
       * 0  HostName
       * 1  IP
       * 2  Score
       * 3  Ping
       * 4  Speed
       * 5  CountryLong
       * ...
       * آخرین ستون OpenVPN Config
       */

      const hostName =
        cols[0]
          ? cols[0]
              .trim()
              .toLowerCase()
          : "";

      const ip =
        cols[1]
          ? cols[1].trim()
          : "";

      const countryLong =
        cols[5]
          ? cols[5].trim()
          : "Unknown";

      const ovpnBase64 =
        cols.length > 14
          ? cols[14].trim()
          : "";

      if (
        !hostName ||
        !ip ||
        !ovpnBase64
      ) {
        continue;
      }

      // ==========================================================
      // Decode OpenVPN config
      // ==========================================================

      let ovpnConfig;

      try {

        ovpnConfig =
          Buffer
            .from(
              ovpnBase64,
              "base64"
            )
            .toString("utf8");

      } catch {

        continue;
      }

      // ==========================================================
      // استخراج TCP port
      // ==========================================================

      const tcpPort =
        extractOpenVpnTcpPort(
          ovpnConfig
        );

      /*
       * اگر OpenVPN فقط UDP باشد،
       * برای SSTP کاندید مناسبی نیست.
       */

      if (!tcpPort) {

        if (
          process.env.SSTP_DEBUG === "1"
        ) {

          console.log(
            `    [SSTP Skip] ${hostName} -> TCP port پیدا نشد`
          );
        }

        continue;
      }

      const domain =
        hostName.endsWith(
          ".opengw.net"
        )
          ? hostName
          : `${hostName}.opengw.net`;

      servers.push({

        ip,

        domain,

        uri: domain,

        name: countryLong,

        port: tcpPort,

        ping: -1
      });

    } catch (error) {

      if (
        process.env.SSTP_DEBUG === "1"
      ) {

        console.log(
          `[SSTP Parse Error] ${error.message}`
        );
      }
    }
  }

  return servers;
}

// ================================================================
// Extract TCP port from OpenVPN config
// ================================================================

function extractOpenVpnTcpPort(
  config
) {

  if (!config) {
    return null;
  }

  /*
   * proto tcp
   * proto tcp-client
   */

  const protoMatch =
    config.match(
      /^\s*proto\s+(tcp(?:-client)?)\s*$/im
    );

  if (!protoMatch) {
    return null;
  }

  /*
   * remote hostname PORT
   */

  const remoteMatches = [
    ...config.matchAll(
      /^\s*remote\s+\S+\s+(\d+)\s*.*$/gim
    )
  ];

  for (
    const match of remoteMatches
  ) {

    const port =
      Number(match[1]);

    if (
      port >= 1 &&
      port <= 65535
    ) {

      return port;
    }
  }

  return null;
}

// ================================================================
// SSTP test
// ================================================================

function testSstp(
  server,
  timeoutMs = SSTP_TIMEOUT_MS
) {

  return new Promise(
    resolve => {

      let settled = false;

      let buffer = "";

      const start =
        Date.now();

      const ipAddress =
        server.ip;

      const domainAddress =
        server.domain ||
        server.uri;

      const targetPort =
        Number(server.port);

      if (
        !ipAddress ||
        !domainAddress ||
        !targetPort
      ) {

        resolve(null);

        return;
      }

      const correlationId =
        crypto.randomUUID();

      /*
       * اتصال با hostname انجام می‌شود.
       *
       * دلیل:
       * TLS باید SNI صحیح داشته باشد.
       *
       * بنابراین:
       *
       * Host = vpnxxxx.opengw.net
       * SNI  = vpnxxxx.opengw.net
       */

      const socket =
        tls.connect({

          host:
            domainAddress,

          port:
            targetPort,

          servername:
            domainAddress,

          rejectUnauthorized:
            false,

          minVersion:
            "TLSv1.2",

          timeout:
            timeoutMs
        });

      const finish =
        (ok, reason) => {

          if (settled) {
            return;
          }

          settled = true;

          try {
            socket.destroy();
          } catch {}

          if (
            process.env.SSTP_DEBUG === "1"
          ) {

            console.log(
              `    [SSTP Debug] ` +
              `${domainAddress}:${targetPort} ` +
              `(${ipAddress}) -> ` +
              `${ok ? "OK" : "FAIL"}: ` +
              `${reason}`
            );
          }

          resolve(
            ok
              ? Date.now() - start
              : null
          );
        };

      // ==========================================================
      // TLS connected
      // ==========================================================

      socket.on(
        "secureConnect",
        () => {

          /*
           * SSTP HTTP request
           */

          const req =
            `SSTP_DUPLEX_POST ` +
            `/sra_{${SSTP_GUID}}/ ` +
            `HTTP/1.1\r\n` +

            `Host: ${domainAddress}\r\n` +

            `SSTPCORRELATIONID: ` +
            `{${correlationId}}\r\n` +

            `Content-Length: ` +
            `18446744073709551615\r\n` +

            `User-Agent: SSTP Client\r\n` +

            `\r\n`;

          socket.write(req);
        }
      );

      // ==========================================================
      // Response
      // ==========================================================

      socket.on(
        "data",
        chunk => {

          buffer +=
            chunk.toString("latin1");

          /*
           * منتظر HTTP header می‌مانیم.
           */

          if (
            buffer.includes(
              "\r\n\r\n"
            ) ||
            buffer.length > 4096
          ) {

            const firstLine =
              buffer.split(
                "\r\n"
              )[0];

            /*
             * SSTP سالم:
             *
             * HTTP/1.1 200 OK
             */

            if (
              /^HTTP\/1\.[01]\s+200\b/
                .test(firstLine)
            ) {

              finish(
                true,
                `SSTP HTTP 200: ${firstLine}`
              );

            } else {

              finish(
                false,
                `HTTP response: ${firstLine}`
              );
            }
          }
        }
      );

      // ==========================================================
      // Timeout
      // ==========================================================

      socket.on(
        "timeout",
        () => {

          finish(
            false,
            "TLS/SSTP timeout"
          );
        }
      );

      // ==========================================================
      // Error
      // ==========================================================

      socket.on(
        "error",
        err => {

          finish(
            false,
            `TLS/network error: ` +
            `${err.code || err.message}`
          );
        }
      );

      // ==========================================================
      // Close
      // ==========================================================

      socket.on(
        "close",
        () => {

          if (!settled) {

            finish(
              false,
              "connection closed before SSTP response"
            );
          }
        }
      );
    }
  );
}

// ================================================================
// Test all SSTP
// ================================================================

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

      /*
       * بسیار مهم:
       *
       * فقط server را می‌فرستیم.
       *
       * قبلاً اشتباهاً server.port
       * به عنوان timeout فرستاده می‌شد.
       */

      const ping =
        await testSstp(
          server
        );

      tested.add(
        dedupKey(server.uri)
      );

      if (
        ping != null
      ) {

        healthy.push({
          ...server,
          ping
        });

        console.log(
          `✅ [SSTP] سالم ` +
          `(${ping}ms): ` +
          `${server.name} ` +
          `(${server.uri}:${server.port})`
        );

      } else {

        console.log(
          `❌ [SSTP] ناسالم: ` +
          `${server.name} ` +
          `(${server.uri}:${server.port})`
        );
      }
    }
  }

  await Promise.all(
    Array.from(
      {
        length: concurrency
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
    tested
  };
}

// ================================================================
// Merge
// ================================================================

function mergeResults(
  remoteList,
  testedUris,
  healthyResults
) {

  const healthyByKey =
    new Map(
      healthyResults.map(
        s => [
          dedupKey(s.uri),
          s
        ]
      )
    );

  const kept =
    remoteList

      .map(existing => {

        const key =
          dedupKey(
            existing.uri
          );

        if (
          healthyByKey.has(key)
        ) {

          return healthyByKey.get(
            key
          );
        }

        if (
          testedUris.has(key)
        ) {

          return null;
        }

        return existing;
      })

      .filter(Boolean);

  const keptKeys =
    new Set(
      kept.map(
        s => dedupKey(s.uri)
      )
    );

  const newlyAdded =
    healthyResults.filter(
      s =>
        !keptKeys.has(
          dedupKey(s.uri)
        )
    );

  return [
    ...kept,
    ...newlyAdded
  ];
}

// ================================================================
// Upload Cloudflare
// ================================================================

async function uploadToCloudflare(
  url,
  servers
) {

  const unique = [];

  const seen =
    new Set();

  for (
    const s of servers
  ) {

    const key =
      dedupKey(s.uri);

    if (
      !seen.has(key)
    ) {

      seen.add(key);

      unique.push(s);
    }
  }

  const body =
    JSON.stringify(

      unique.map(
        (s, i) => ({

          id:
            String(i),

          address:
            s.uri.trim(),

          port:
            s.port ?? "v2ray",

          country:
            s.name,

          ping:
            s.ping ?? -1,

          icon:
            "https://raw.githubusercontent.com/alinarooi/icons/main/global.png"
        })
      )
    );

  const headers = {
    "Content-Type":
      "application/json; charset=UTF-8"
  };

  const res =
    await fetch(
      url,
      {
        method: "POST",

        headers,

        body,

        signal:
          AbortSignal.timeout(15000)
      }
    );

  return res.ok;
}

// ================================================================
// MAIN
// ================================================================

async function main() {

  console.log(
    "========================================"
  );

  console.log(
    "شروع تست سرورها..."
  );

  console.log(
    "========================================"
  );

  // ==============================================================
  // دریافت V2Ray
  // ==============================================================

  const [
    cfServers,
    ghServers
  ] =
    await Promise.all([

      fetchCloudflareServers(
        CF_ALL_URL
      ).catch(error => {

        console.error(
          "خطا در دریافت Cloudflare:",
          error.message
        );

        return [];
      }),

      fetchGithubConfigs(
        GH_RAW_URL
      ).catch(error => {

        console.error(
          "خطا در دریافت GitHub:",
          error.message
        );

        return [];
      })

    ]);

  console.log(
    `Cloudflare: ${cfServers.length} | ` +
    `GitHub: ${ghServers.length}`
  );

  // ==============================================================
  // Deduplicate V2Ray
  // ==============================================================

  const seen =
    new Set();

  const combined =
    [
      ...cfServers,
      ...ghServers
    ]

      .filter(server => {

        const key =
          dedupKey(server.uri);

        if (
          seen.has(key)
        ) {

          return false;
        }

        seen.add(key);

        return true;
      })

      .slice(
        0,
        MAX_CANDIDATES
      );

  console.log(
    `تعداد V2Ray برای تست: ` +
    `${combined.length}`
  );

  // ==============================================================
  // Test V2Ray
  // ==============================================================

  let v2rayResult = {
    healthy: [],
    tested: new Set()
  };

  if (
    combined.length > 0
  ) {

    console.log(
      `شروع تست V2Ray با ` +
      `${CONCURRENCY} اتصال هم‌زمان...`
    );

    v2rayResult =
      await testAll(
        combined,
        CONCURRENCY
      );

    console.log(
      `نتیجه V2Ray: ` +
      `${v2rayResult.healthy.length} سالم ` +
      `از ${v2rayResult.tested.size} تست‌شده`
    );

  } else {

    console.log(
      "هیچ کاندیدای V2Ray وجود ندارد."
    );
  }

  // ==============================================================
  // VPNGate
  // ==============================================================

  console.log(
    "========================================"
  );

  console.log(
    "دریافت سرورهای VPNGate..."
  );

  const vpnGateServers =
    await fetchVpnGateServers()
      .catch(error => {

        console.error(
          "خطا در VPNGate:",
          error.message
        );

        return [];
      });

  console.log(
    `VPNGate: ` +
    `${vpnGateServers.length} سرور TCP/SSTP پیدا شد.`
  );

  // ==============================================================
  // Deduplicate SSTP
  // ==============================================================

  const seenSstp =
    new Set();

  const sstpCandidates =
    vpnGateServers

      .filter(server => {

        const key =
          dedupKey(server.uri);

        if (
          seenSstp.has(key)
        ) {

          return false;
        }

        seenSstp.add(key);

        return true;
      })

      .slice(
        0,
        MAX_SSTP_CANDIDATES
      );

  console.log(
    `کاندیداهای SSTP برای تست: ` +
    `${sstpCandidates.length}`
  );

  // ==============================================================
  // Test SSTP
  // ==============================================================

  let sstpResult = {
    healthy: [],
    tested: new Set()
  };

  if (
    sstpCandidates.length > 0
  ) {

    console.log(
      `شروع تست SSTP با ` +
      `${SSTP_CONCURRENCY} اتصال هم‌زمان...`
    );

    sstpResult =
      await testAllSstp(
        sstpCandidates,
        SSTP_CONCURRENCY
      );

    console.log(
      `نتیجه SSTP: ` +
      `${sstpResult.healthy.length} سالم ` +
      `از ${sstpResult.tested.size} تست‌شده`
    );

  } else {

    console.log(
      "هیچ کاندیدای SSTP پیدا نشد."
    );
  }

  // ==============================================================
  // Merge
  // ==============================================================

  const healthy = [
    ...v2rayResult.healthy,
    ...sstpResult.healthy
  ];

  const tested =
    new Set([
      ...v2rayResult.tested,
      ...sstpResult.tested
    ]);

  console.log(
    `مجموع سرورهای سالم: ${healthy.length}`
  );

  // ==============================================================
  // اگر هیچ سروری سالم نبود
  // ==============================================================

  if (
    healthy.length === 0
  ) {

    console.log(
      "هیچ سرور سالمی پیدا نشد."
    );

    console.log(
      "لیست Cloudflare دست‌نخورده باقی می‌ماند."
    );

    return;
  }

  // ==============================================================
  // Fresh Cloudflare list
  // ==============================================================

  console.log(
    "دریافت مجدد لیست Cloudflare..."
  );

  const freshRemote =
    await fetchCloudflareServers(
      CF_ALL_URL
    ).catch(
      () => cfServers
    );

  // ==============================================================
  // Merge
  // ==============================================================

  const merged =
    mergeResults(
      freshRemote,
      tested,
      healthy
    );

  console.log(
    `لیست قبلی: ${freshRemote.length}`
  );

  console.log(
    `لیست جدید: ${merged.length}`
  );

  // ==============================================================
  // Safety check
  // ==============================================================

  if (
    freshRemote.length > 0
  ) {

    const ratio =
      merged.length /
      freshRemote.length;

    if (
      ratio < MIN_KEEP_RATIO
    ) {

      console.error(
        `⚠️ آپلود متوقف شد: ` +
        `لیست نهایی (${merged.length}) ` +
        `کمتر از ` +
        `${Math.round(
          MIN_KEEP_RATIO * 100
        )}% ` +
        `لیست فعلی ` +
        `(${freshRemote.length}) است.`
      );

      process.exit(1);
    }
  }

  // ==============================================================
  // Upload
  // ==============================================================

  console.log(
    `آپلود ${merged.length} سرور به Cloudflare...`
  );

  const ok =
    await uploadToCloudflare(
      CF_UPDATE_URL,
      merged
    );

  if (ok) {

    console.log(
      "✅ آپلود موفق بود."
    );

  } else {

    console.error(
      "❌ آپلود ناموفق بود."
    );

    process.exit(1);
  }
}

// ================================================================
// Start
// ================================================================

main()
  .catch(error => {

    console.error(
      "خطای کلی:",
      error
    );

    process.exit(1);
  });
