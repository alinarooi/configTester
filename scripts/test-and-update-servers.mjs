import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import tls from "node:tls";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

// =====================================================================
// Environment Variables & Configuration
// =====================================================================

function requireEnv(name) {
  const value = process.env[name];

  if (!value) {
    console.error(`متغیر محیطی ${name} تنظیم نشده است.`);
    process.exit(1);
  }

  return value;
}

const CF_ALL_URL = requireEnv("CF_ALL_URL");
const CF_UPDATE_URL = requireEnv("CF_UPDATE_URL");
const GH_RAW_URL = requireEnv("GH_RAW_URL");

const XRAY_BIN = process.env.XRAY_BIN || "./xray";
const MAX_CANDIDATES = Number(process.env.MAX_CANDIDATES || 300);
const CONCURRENCY = Number(process.env.CONCURRENCY || 12);
const CORE_WARMUP_MS = Number(process.env.CORE_WARMUP_MS || 400);
const TEST_TIMEOUT_S = Number(process.env.TEST_TIMEOUT_S || 5);
const TEST_URL = process.env.TEST_URL || "https://www.gstatic.com/generate_204";
const BASE_PORT = 20000;
const MIN_KEEP_RATIO = Number(process.env.MIN_KEEP_RATIO || 0.5);

// =====================================================================
// SSTP
// =====================================================================

const VPNGATE_API_URL = "http://www.vpngate.net/api/iphone/";
const MAX_SSTP_CANDIDATES = Number(process.env.MAX_SSTP_CANDIDATES || 200);
const SSTP_CONCURRENCY = Number(process.env.SSTP_CONCURRENCY || 1);
const SSTP_TIMEOUT_MS = Number(process.env.SSTP_TIMEOUT_MS || 30000);
const SSTP_USERNAME = process.env.SSTP_USERNAME || "vpn";
const SSTP_PASSWORD = process.env.SSTP_PASSWORD || "vpn";
const SSTP_REAL_TUNNEL = process.env.SSTP_REAL_TUNNEL === "1";
const SSTP_INTERNET_TEST = process.env.SSTP_INTERNET_TEST !== "0";
const SSTP_TEST_URL = process.env.SSTP_TEST_URL || "https://www.gstatic.com/generate_204";

// =====================================================================
// Helpers
// =====================================================================

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function dedupKey(uri) {
  return String(uri || "").trim().split("#")[0];
}

// =====================================================================
// Cloudflare - GET
// =====================================================================

async function fetchCloudflareServers(url) {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(15000),
  });

  if (!res.ok) {
    throw new Error(`Cloudflare HTTP ${res.status}`);
  }

  const arr = await res.json();

  if (!Array.isArray(arr)) {
    throw new Error("پاسخ Cloudflare آرایه نیست.");
  }

  return arr
    .map((o, i) => ({
      uri: String(o.address || "").trim(),
      name: String(o.country || `کلودفلر-${i + 1}`),
      port: o.port === "v2ray" ? "v2ray" : Number(o.port) || "v2ray",
      ping: Number.isFinite(Number(o.ping)) ? Number(o.ping) : -1,
      ip: String(o.ip || "").trim(),
      hostName: String(o.hostName || o.address || "").trim(),
    }))
    .filter(s => s.uri.length > 0);
}

// =====================================================================
// Cloudflare - UPDATE
// =====================================================================

async function uploadToCloudflare(url, servers) {
  if (!Array.isArray(servers)) {
    throw new Error("لیست نهایی آرایه نیست.");
  }

  const body = servers.map(s => ({
    address: String(s.address || s.uri || "").trim(),
    country: String(s.country || s.name || "Unknown").trim(),
    port: s.port === "v2ray" ? "v2ray" : Number(s.port),
    ping: Number.isFinite(Number(s.ping)) ? Number(s.ping) : -1,
    ...(s.ip ? { ip: String(s.ip) } : {}),
  }));

  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30000),
  });

  const responseText = await res.text();

  if (!res.ok) {
    throw new Error(
      `Cloudflare update HTTP ${res.status}: ${responseText.slice(0, 500)}`
    );
  }

  console.log(`☁️ Cloudflare با موفقیت آپدیت شد: ${body.length} سرور`);

  if (responseText) {
    console.log(`Cloudflare response: ${responseText.slice(0, 500)}`);
  }
}

// =====================================================================
// GitHub configs
// =====================================================================

async function fetchGithubConfigs(url) {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(15000),
  });

  if (!res.ok) {
    throw new Error(`GitHub HTTP ${res.status}`);
  }

  let text = await res.text();
  const decoded = tryBase64Decode(text.trim());

  if (decoded && decoded.includes("://")) {
    text = decoded;
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
    .map(line => line.trim())
    .filter(line => schemes.some(scheme => line.startsWith(scheme)))
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

// =====================================================================
// Xray config
// =====================================================================

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
      throw new Error(`پروتکل ناشناخته: ${scheme}`);
  }
}

function buildStreamSettings({
  security,
  network,
  sni,
  fp,
  alpn,
  path: wsPath,
  host,
  mode,
  serviceName,
  pbk,
  sid,
  spx,
}) {
  const settings = {
    network,
    security,
  };

  if (security === "tls") {
    settings.tlsSettings = {
      serverName: sni,
    };

    if (fp) {
      settings.tlsSettings.fingerprint = fp;
    }

    if (alpn) {
      settings.tlsSettings.alpn = alpn.split(",");
    }
  }

  if (security === "reality") {
    settings.realitySettings = {
      serverName: sni,
      publicKey: pbk || "",
    };

    if (fp) {
      settings.realitySettings.fingerprint = fp;
    }

    if (sid) {
      settings.realitySettings.shortId = sid;
    }

    if (spx) {
      settings.realitySettings.spiderX = spx;
    }
  }

  if (network === "ws") {
    settings.wsSettings = {
      path: wsPath || "/",
      headers: {
        Host: host,
      },
    };
  }

  if (network === "xhttp") {
    settings.xhttpSettings = {
      path: wsPath || "/",
      mode: mode || "auto",
      host,
    };
  }

  if (network === "grpc") {
    settings.grpcSettings = {
      serviceName: serviceName || "",
    };
  }

  return settings;
}

// =====================================================================
// VLESS
// =====================================================================

function buildVless(link) {
  const u = new URL(link);
  const uuid = decodeURIComponent(u.username);
  const host = u.hostname;
  const port = Number(u.port) || 443;
  const q = (key, def = "") => u.searchParams.get(key) || def;

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
              encryption: q("encryption", "none"),
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

// =====================================================================
// VMESS
// =====================================================================

function buildVmess(link) {
  const decoded = Buffer.from(link.replace("vmess://", ""), "base64").toString("utf8");
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
      security: j.tls === "tls" ? "tls" : "none",
      network: j.net || "tcp",
      sni: j.sni || j.host || host,
      fp: j.fp || "",
      alpn: j.alpn || "",
      path: j.path || "/",
      host: j.host || host,
      mode: "auto",
      serviceName: j.path || "",
    }),
  };
}

// =====================================================================
// TROJAN
// =====================================================================

function buildTrojan(link) {
  const u = new URL(link);
  const password = decodeURIComponent(u.username);
  const host = u.hostname;
  const port = Number(u.port) || 443;
  const q = (key, def = "") => u.searchParams.get(key) || def;

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

// =====================================================================
// SHADOWSOCKS
// =====================================================================

function buildShadowsocks(link) {
  const raw = link.replace("ss://", "").split("#")[0];
  let method, password, host, port;

  if (raw.includes("@")) {
    const [userInfo, hostPart] = raw.split("@");
    let decoded;

    try {
      decoded = Buffer.from(userInfo, "base64url").toString("utf8");
    } catch {
      decoded = Buffer.from(userInfo, "base64").toString("utf8");
    }

    [method, password] = decoded.split(":");
    const hostPort = hostPart.split("/")[0].split("?")[0];
    const idx = hostPort.lastIndexOf(":");
    host = hostPort.slice(0, idx);
    port = Number(hostPort.slice(idx + 1));
  } else {
    const decoded = Buffer.from(raw, "base64").toString("utf8");
    const [methodPass, hostPort] = decoded.split("@");
    [method, password] = methodPass.split(":");
    const idx = hostPort.lastIndexOf(":");
    host = hostPort.slice(0, idx);
    port = Number(hostPort.slice(idx + 1));
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

// =====================================================================
// HYSTERIA
// =====================================================================

function buildHysteria(link) {
  const u = new URL(link);
  const auth = u.username ? decodeURIComponent(u.username) : "";
  const host = u.hostname;
  const port = Number(u.port) || 443;
  const q = (key, def = "") => u.searchParams.get(key) || def;

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
        serverName: q("sni", host),
        allowInsecure: q("insecure", "0") === "1",
      },
      hysteriaSettings: {
        version: 2,
        auth,
      },
    },
  };
}

// =====================================================================
// Full Xray config
// =====================================================================

function buildFullConfig(outbound, socksPort) {
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

// =====================================================================
// Test one Xray server
// =====================================================================

async function testOne(server, port) {
  let outbound;

  try {
    outbound = parseLinkToOutbound(server.uri);
  } catch {
    return null;
  }

  const configPath = path.join(os.tmpdir(), `xray-test-${port}.json`);

  await fs.writeFile(configPath, JSON.stringify(buildFullConfig(outbound, port)));

  const child = spawn(XRAY_BIN, ["run", "-c", configPath], {
    stdio: "ignore",
  });

  try {
    await sleep(CORE_WARMUP_MS);

    const start = Date.now();
    const { stdout } = await execFileP("curl", [
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
    ]);

    const elapsed = Date.now() - start;
    const code = stdout.trim();

    if (code === "204" || (code.startsWith("2") && code.length === 3)) {
      return elapsed;
    }

    return null;
  } catch {
    return null;
  } finally {
    try {
      child.kill("SIGKILL");
    } catch {}

    await fs.rm(configPath, { force: true });
  }
}

// =====================================================================
// Test all Xray
// =====================================================================

async function testAll(servers, concurrency) {
  const healthy = [];
  const tested = new Set();

  let nextIndex = 0;
  let nextPort = BASE_PORT;

  async function worker() {
    while (true) {
      const i = nextIndex++;
      if (i >= servers.length) return;

      const server = servers[i];
      const port = nextPort++;

      const ping = await testOne(server, port);
      tested.add(dedupKey(server.uri));

      if (ping != null) {
        healthy.push({
          ...server,
          ping,
        });

        console.log(`✅ سالم (${ping}ms): ${server.name}`);
      } else {
        console.log(`❌ ناسالم: ${server.name}`);
      }
    }
  }

  await Promise.all(
    Array.from(
      {
        length: Math.min(
          Math.max(concurrency, 1),
          Math.max(servers.length, 1)
        ),
      },
      worker
    )
  );

  healthy.sort((a, b) => a.ping - b.ping);

  return {
    healthy,
    tested,
  };
}

// =====================================================================
// VPNGate hostname
// =====================================================================

function normalizeVpnGateHost(host) {
  const h = String(host || "").trim().replace(/\.$/, "");

  if (!h) return "";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return h;
  if (h.includes(".")) return h;

  return `${h}.opengw.net`;
}

// =====================================================================
// VPNGate parser
// =====================================================================

async function fetchVpnGateServers() {
  console.log("در حال دریافت لیست VPNGate...");

  const res = await fetch(VPNGATE_API_URL, {
    signal: AbortSignal.timeout(15000),
  });

  if (!res.ok) {
    throw new Error(`VPNGate HTTP ${res.status}`);
  }

  const text = await res.text();
  const lines = text.replace(/\r/g, "").split("\n").slice(2, -2);
  const servers = [];

  for (const line of lines) {
    if (!line.trim()) continue;

    try {
      const cols = line.split(",");
      const rawHostName = String(cols[0] || "").trim();
      const ip = String(cols[1] || "").trim();
      const countryLong = String(cols[5] || "Unknown").trim();

      if (!rawHostName) continue;

      const hostName = normalizeVpnGateHost(rawHostName);
      if (!hostName || !/^[a-zA-Z0-9.-]+$/.test(hostName)) continue;

      const ovpnBase64 = cols.slice(14).join(",").trim();
      let ovpnConfig = "";

      if (ovpnBase64) {
        try {
          ovpnConfig = Buffer.from(ovpnBase64, "base64").toString("utf8");
        } catch {
          ovpnConfig = "";
        }
      }

      let port = null;
      const remoteLines = ovpnConfig.match(/^remote\s+\S+\s+\d+(?:\s+\S+)?/gm) || [];

      for (const remoteLine of remoteLines) {
        const parts = remoteLine.trim().split(/\s+/);
        if (parts.length < 3) continue;

        const candidatePort = Number(parts[2]);
        if (!Number.isInteger(candidatePort) || candidatePort < 1 || candidatePort > 65535) {
          continue;
        }

        if (parts[3] && parts[3].toLowerCase() === "tcp") {
          port = candidatePort;
          break;
        }

        if (port === null) {
          port = candidatePort;
        }
      }

      if (port === null) {
        if (hostName.startsWith("public-vpn-")) {
          port = 443;
        } else {
          continue;
        }
      }

      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        continue;
      }

      servers.push({
        uri: hostName,
        name: countryLong || hostName,
        port,
        ip,
        hostName,
        rawHostName,
        ping: -1,
      });
    } catch (e) {
      console.log(`⚠️ خطا در پردازش VPNGate: ${e.message}`);
    }
  }

  const unique = [];
  const seen = new Set();

  for (const server of servers) {
    const key = `${server.hostName}:${server.port}`;
    if (seen.has(key)) continue;

    seen.add(key);
    unique.push(server);
  }

  console.log(`VPNGate parser: ${unique.length} سرور SSTP معتبر استخراج شد.`);

  for (const server of unique.slice(0, 5)) {
    console.log(`    [VPNGate] ${server.hostName}:${server.port} (${server.ip})`);
  }

  return unique;
}

// =====================================================================
// REAL SSTP
// =====================================================================

async function testSstpReal(server, timeoutMs = SSTP_TIMEOUT_MS) {
  const host = String(server.hostName || server.uri || "").trim();
  const port = Number(server.port) || 443;

  if (!host) return null;

  const started = Date.now();
  let child = null;
  let pppInterface = null;
  let output = "";
  let settled = false;

  const finish = async (ok, reason = "") => {
    if (settled) return null;
    settled = true;

    if (child?.pid) {
      try {
        process.kill(-child.pid, "SIGTERM");
      } catch {
        try {
          child.kill("SIGTERM");
        } catch {}
      }

      await sleep(1200);

      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {
        try {
          child.kill("SIGKILL");
        } catch {}
      }
    }

    if (pppInterface) {
      try {
        await execFileP("sudo", ["-n", "ip", "link", "set", pppInterface, "down"], {
          timeout: 3000,
        });
      } catch {}
    }

    if (ok) {
      console.log(
        `✅ [SSTP REAL] سالم (${Date.now() - started}ms): ${host}:${port} ${reason}`
      );
      return Date.now() - started;
    }

    console.log(
      `    [SSTP debug] ${host}:${port} -> ${reason}` +
        (output ? ` | ${output.trim().slice(-3000)}` : "")
    );

    return null;
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

    child = spawn("sudo", args, {
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });

    child.stdout.on("data", data => {
      output += data.toString();
    });

    child.stderr.on("data", data => {
      output += data.toString();
    });

    let childExitInfo = null;

    child.once("exit", (code, signal) => {
      childExitInfo = { code, signal };
    });

    child.once("error", error => {
      childExitInfo = { error: error.message };
    });

    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      await sleep(500);

      let links = "";

      try {
        const result = await execFileP("ip", ["-o", "link", "show", "type", "ppp"], {
          timeout: 3000,
        });
        links = result.stdout || "";
      } catch {}

      const matches = [...links.matchAll(/^\d+:\s+(ppp\d+):/gm)];

      if (matches.length > 0) {
        pppInterface = matches[matches.length - 1][1];
        let address = "";

        try {
          const result = await execFileP(
            "ip",
            ["-4", "addr", "show", "dev", pppInterface],
            { timeout: 3000 }
          );
          address = result.stdout || "";
        } catch {}

        if (/inet\s+\d+\.\d+\.\d+\.\d+/.test(address)) {
          break;
        }
      }

      if (childExitInfo) {
        return finish(
          false,
          `sstpc قبل از PPP خارج شد: ${JSON.stringify(childExitInfo)}`
        );
      }
    }

    if (!pppInterface) {
      return finish(false, "PPP interface ساخته نشد / timeout");
    }

    if (SSTP_INTERNET_TEST) {
      try {
        const { stdout } = await execFileP(
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
          { timeout: 15000 }
        );

        const code = stdout.trim();

        if (code === "204" || (code.startsWith("2") && code.length === 3)) {
          return finish(
            true,
            `PPP=${pppInterface}, HTTP=${code}, Internet=${Date.now() - started}ms`
          );
        }

        return finish(false, `اینترنت ناموفق؛ HTTP=${code || "empty"}`);
      } catch (e) {
        return finish(false, `تست اینترنت شکست خورد: ${e.code || e.message}`);
      }
    }

    return finish(true, `PPP=${pppInterface}`);
  } catch (e) {
    return finish(false, `خطای SSTP: ${e.code || e.message}`);
  }
}

// =====================================================================
// SSTP handshake
// =====================================================================

function cryptoRandomUuid() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

function testSstpHandshake(host, port = 443, timeoutMs = SSTP_TIMEOUT_MS) {
  return new Promise(resolve => {
    let settled = false;
    let buffer = "";
    const start = Date.now();

    const socket = tls.connect({
      host,
      port,
      servername: host,
      rejectUnauthorized: false,
      timeout: timeoutMs,
    });

    const finish = ok => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(ok ? Date.now() - start : null);
    };

    socket.on("secureConnect", () => {
      const guid = "BA195980-CD49-458b-9E23-C84EE0ADCD75";
      const correlation = cryptoRandomUuid();
      const req =
        `SSTP_DUPLEX_POST /sra_{${guid}} HTTP/1.1\r\n` +
        `Content-Length: 18446744073709551615\r\n` +
        `Host: ${host}\r\n` +
        `SSTPCORRELATIONID: {${correlation}}\r\n\r\n`;

      socket.write(req);
    });

    socket.on("data", chunk => {
      buffer += chunk.toString("utf8");
      if (buffer.includes("HTTP/1.1 200") || buffer.includes("HTTP/1.0 200")) {
        finish(true);
      }
    });

    socket.on("error", () => finish(false));
    socket.on("timeout", () => finish(false));
    socket.on("end", () => finish(false));
  });
}

// =====================================================================
// SSTP Batch Tester
// =====================================================================

async function testOneSstp(server) {
  if (SSTP_REAL_TUNNEL) {
    return await testSstpReal(server);
  } else {
    return await testSstpHandshake(server.hostName || server.uri, server.port);
  }
}

async function testAllSstp(servers, concurrency) {
  const healthy = [];
  let nextIndex = 0;

  async function worker() {
    while (true) {
      const i = nextIndex++;
      if (i >= servers.length) return;

      const server = servers[i];
      const ping = await testOneSstp(server);

      if (ping !== null) {
        healthy.push({ ...server, ping });
        console.log(`✅ [SSTP] سالم (${ping}ms): ${server.hostName}:${server.port}`);
      } else {
        console.log(`❌ [SSTP] ناسالم: ${server.hostName}:${server.port}`);
      }
    }
  }

  await Promise.all(
    Array.from(
      { length: Math.min(Math.max(concurrency, 1), Math.max(servers.length, 1)) },
      worker
    )
  );

  healthy.sort((a, b) => a.ping - b.ping);
  return healthy;
}

// =====================================================================
// Main Execution Workflow
// =====================================================================

async function main() {
  console.log("🚀 شروع فرایند تست و بروزرسانی سرورها...");

  let xrayCandidates = [];
  try {
    console.log("در حال دریافت سرورهای Xray از Cloudflare و GitHub...");
    const [cfResult, ghResult] = await Promise.allSettled([
      fetchCloudflareServers(CF_ALL_URL),
      fetchGithubConfigs(GH_RAW_URL),
    ]);

    if (cfResult.status === "fulfilled") xrayCandidates.push(...cfResult.value);
    if (ghResult.status === "fulfilled") xrayCandidates.push(...ghResult.value);

    const seen = new Set();
    xrayCandidates = xrayCandidates
      .filter(s => {
        const k = dedupKey(s.uri);
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      })
      .slice(0, MAX_CANDIDATES);
  } catch (e) {
    console.error("خطا در دریافت سرورهای Xray:", e.message);
  }

  console.log(`تعداد ${xrayCandidates.length} کاندید Xray برای تست آماده شد.`);
  const xrayResults = await testAll(xrayCandidates, CONCURRENCY);

  let sstpCandidates = [];
  try {
    const vpnGateServers = await fetchVpnGateServers();
    sstpCandidates = vpnGateServers.slice(0, MAX_SSTP_CANDIDATES);
  } catch (e) {
    console.error("خطا در دریافت سرورهای VPNGate:", e.message);
  }

  console.log(`تعداد ${sstpCandidates.length} کاندید SSTP برای تست آماده شد.`);
  const healthySstp = await testAllSstp(sstpCandidates, SSTP_CONCURRENCY);

  const finalServers = [
    ...xrayResults.healthy,
    ...healthySstp.map(s => ({
      address: s.hostName,
      name: s.name,
      port: s.port,
      ping: s.ping,
      ip: s.ip,
      hostName: s.hostName,
    })),
  ];

  console.log(`تعداد کل سرورهای سالم: ${finalServers.length}`);

  if (finalServers.length > 0) {
    await uploadToCloudflare(CF_UPDATE_URL, finalServers);
  } else {
    console.log("⚠️ هیچ سرور سالمی یافت نشد. آپدیت Cloudflare انجام نشد.");
  }
}

main().catch(err => {
  console.error("❌ خطای اجرا:", err);
  process.exit(1);
});
