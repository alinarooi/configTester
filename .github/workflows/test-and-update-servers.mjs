#!/usr/bin/env node
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
const TEST_TIMEOUT_S = Number(process.env.TEST_TIMEOUT_S || 6);
const TEST_URL = "https://www.gstatic.com/generate_204";
const BASE_PORT = 20000;

/**
 * محافظ در برابر حذف ناگهانی: چون Worker فعلی هیچ اعتبارسنجی روی بدنه‌ی
 * درخواست ندارد (هر آرایه‌ای را می‌پذیرد و جایگزین می‌کند)، این چک باید
 * اینجا در اسکریپت انجام شود. اگر لیست نهایی به‌طرز غیرمنتظره‌ای خیلی
 * کوچک‌تر از لیست فعلی شود (مثلاً به‌خاطر یک باگ یا قطعی موقت شبکه‌ی
 * runner)، آپلود متوقف می‌شود تا به‌جای یک بازنویسی مخرب، دستی بررسی شود.
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
  const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
  const arr = await res.json();
  return arr
    .map((o, i) => ({
      uri: String(o.address || "").trim(),
      name: String(o.country || `کلودفلر-${i + 1}`),
      ping: -1,
    }))
    .filter((s) => s.uri.length > 0);
}

async function fetchGithubConfigs(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
  let text = await res.text();

  // اگر کل محتوا base64 بود، decode کن
  const maybeDecoded = tryBase64Decode(text.trim());
  if (maybeDecoded && maybeDecoded.includes("://")) {
    text = maybeDecoded;
  }

  const schemes = ["vless://", "vmess://", "ss://", "trojan://", "hysteria2://", "hy2://"];
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => schemes.some((s) => l.startsWith(s)))
    .map((uri, i) => ({ uri, name: `گیت‌هاب-${i + 1}`, ping: -1 }));
}

function tryBase64Decode(s) {
  try {
    return Buffer.from(s, "base64").toString("utf8");
  } catch {
    return null;
  }
}

const dedupKey = (uri) => uri.trim().split("#")[0];

// ---------------------------------------------------------------------
// ساخت کانفیگ Xray از روی لینک (vless/vmess/trojan/ss/hysteria)
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
      throw new Error(`پروتکل پشتیبانی نمی‌شود: ${scheme}`);
  }
}

function buildStreamSettings({ security, network, sni, fp, alpn, path, host, mode, serviceName, pbk, sid, spx }) {
  const s = { network, security };
  if (security === "tls") {
    s.tlsSettings = { serverName: sni };
    if (fp) s.tlsSettings.fingerprint = fp;
    if (alpn) s.tlsSettings.alpn = alpn.split(",");
  } else if (security === "reality") {
    s.realitySettings = { serverName: sni, publicKey: pbk || "" };
    if (fp) s.realitySettings.fingerprint = fp;
    if (sid) s.realitySettings.shortId = sid;
    if (spx) s.realitySettings.spiderX = spx;
  }
  if (network === "ws") {
    s.wsSettings = { path: path || "/", headers: { Host: host } };
  } else if (network === "xhttp") {
    s.xhttpSettings = { path: path || "/", mode: mode || "auto", host };
  } else if (network === "grpc") {
    s.grpcSettings = { serviceName: serviceName || "" };
  }
  return s;
}

function buildVless(link) {
  const u = new URL(link);
  const uuid = decodeURIComponent(u.username);
  const host = u.hostname;
  const port = Number(u.port) || 443;
  const q = (k, d = "") => u.searchParams.get(k) || d;

  return {
    tag: "proxy",
    protocol: "vless",
    settings: {
      vnext: [{ address: host, port, users: [{ id: uuid, encryption: q("encryption", "none") }] }],
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
          users: [{ id: j.id, alterId: Number(j.aid || 0), security: j.scy || "auto" }],
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

function buildTrojan(link) {
  const u = new URL(link);
  const password = decodeURIComponent(u.username);
  const host = u.hostname;
  const port = Number(u.port) || 443;
  const q = (k, d = "") => u.searchParams.get(k) || d;

  return {
    tag: "proxy",
    protocol: "trojan",
    settings: { servers: [{ address: host, port, password }] },
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
  const withoutScheme = link.replace("ss://", "").split("#")[0];
  let method, password, host, port;

  if (withoutScheme.includes("@")) {
    const [userInfo, hostPart] = withoutScheme.split("@");
    let decodedUserInfo;
    try {
      decodedUserInfo = Buffer.from(userInfo, "base64url").toString("utf8");
    } catch {
      decodedUserInfo = Buffer.from(userInfo, "base64").toString("utf8");
    }
    [method, password] = decodedUserInfo.split(":");
    const hostPortStr = hostPart.split("/")[0].split("?")[0];
    const idx = hostPortStr.lastIndexOf(":");
    host = hostPortStr.slice(0, idx);
    port = Number(hostPortStr.slice(idx + 1));
  } else {
    const decodedFull = Buffer.from(withoutScheme, "base64").toString("utf8");
    const [methodPass, hostPort] = decodedFull.split("@");
    [method, password] = methodPass.split(":");
    const idx = hostPort.lastIndexOf(":");
    host = hostPort.slice(0, idx);
    port = Number(hostPort.slice(idx + 1));
  }

  return {
    tag: "proxy",
    protocol: "shadowsocks",
    settings: { servers: [{ address: host, port, method, password }] },
  };
}

// طبق مستندات رسمی xtls.github.io: پروتکل "hysteria" است، نه "hysteria2"
function buildHysteria(link) {
  const u = new URL(link);
  const auth = u.username ? decodeURIComponent(u.username) : "";
  const host = u.hostname;
  const port = Number(u.port) || 443;
  const q = (k, d = "") => u.searchParams.get(k) || d;

  return {
    tag: "proxy",
    protocol: "hysteria",
    settings: { version: 2, address: host, port },
    streamSettings: {
      network: "hysteria",
      security: "tls",
      tlsSettings: {
        serverName: q("sni", host),
        allowInsecure: q("insecure", "0") === "1",
      },
      hysteriaSettings: { version: 2, auth },
    },
  };
}

function buildFullConfig(outbound, socksPort) {
  return {
    log: { loglevel: "warning" },
    inbounds: [
      {
        listen: "127.0.0.1",
        port: socksPort,
        protocol: "socks",
        settings: { auth: "noauth", udp: false },
      },
    ],
    outbounds: [outbound, { tag: "direct", protocol: "freedom" }],
  };
}

// ---------------------------------------------------------------------
// تست یک سرور: spawn پروسه‌ی xray + curl از طریق SOCKS
// ---------------------------------------------------------------------
async function testOne(server, port) {
  let outbound;
  try {
    outbound = parseLinkToOutbound(server.uri);
  } catch {
    return null; // لینک پشتیبانی‌نشده یا ناقص
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
      "--socks5", `127.0.0.1:${port}`,
      "-m", String(TEST_TIMEOUT_S),
      "-s", "-o", "/dev/null",
      "-w", "%{http_code}",
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
    child.kill("SIGKILL");
    await fs.rm(configPath, { force: true });
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ---------------------------------------------------------------------
// اجرای موازی با محدودیت تعداد هم‌زمان
// ---------------------------------------------------------------------
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
        healthy.push({ ...server, ping });
        console.log(`✅ سالم (${ping}ms): ${server.name}`);
      } else {
        console.log(`❌ ناسالم: ${server.name}`);
      }
    }
  }

  await Promise.all(Array.from({ length: concurrency }, worker));
  healthy.sort((a, b) => a.ping - b.ping);
  return { healthy, tested };
}

// ---------------------------------------------------------------------
// merge: فقط سرورهای واقعاً تست‌شده حذف/به‌روز می‌شوند
// ---------------------------------------------------------------------
function mergeResults(remoteList, testedUris, healthyResults) {
  const healthyByKey = new Map(healthyResults.map((s) => [dedupKey(s.uri), s]));

  const kept = remoteList
    .map((existing) => {
      const key = dedupKey(existing.uri);
      if (healthyByKey.has(key)) return healthyByKey.get(key);
      if (testedUris.has(key)) return null; // تست شد و رد شد
      return existing; // تست نشد → دست‌نخورده
    })
    .filter(Boolean);

  const keptKeys = new Set(kept.map((s) => dedupKey(s.uri)));
  const newlyAdded = healthyResults.filter((s) => !keptKeys.has(dedupKey(s.uri)));

  return [...kept, ...newlyAdded];
}

async function uploadToCloudflare(url, servers) {
  const unique = [];
  const seen = new Set();
  for (const s of servers) {
    const key = dedupKey(s.uri);
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(s);
    }
  }

  const body = JSON.stringify(
    unique.map((s, i) => ({
      id: String(i),
      address: s.uri.trim(),
      port: "v2ray",
      country: s.name,
      ping: s.ping ?? -1,
      icon: "https://raw.githubusercontent.com/alinarooi/icons/main/global.png",
    }))
  );

  const headers = { "Content-Type": "application/json; charset=UTF-8" };

  const res = await fetch(url, { method: "POST", headers, body, signal: AbortSignal.timeout(15000) });
  return res.ok;
}

// ---------------------------------------------------------------------
// main
// ---------------------------------------------------------------------
async function main() {
  console.log("در حال دریافت لیست‌ها...");
  const [cfServers, ghServers] = await Promise.all([
    fetchCloudflareServers(CF_ALL_URL).catch((e) => {
      console.error("خطا در دریافت کلودفلر:", e.message);
      return [];
    }),
    fetchGithubConfigs(GH_RAW_URL).catch((e) => {
      console.error("خطا در دریافت گیت‌هاب:", e.message);
      return [];
    }),
  ]);
  console.log(`کلودفلر: ${cfServers.length} | گیت‌هاب: ${ghServers.length}`);

  const seen = new Set();
  const combined = [...cfServers, ...ghServers]
    .filter((s) => {
      const key = dedupKey(s.uri);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, MAX_CANDIDATES);

  console.log(`تعداد یکتا برای تست: ${combined.length}`);
  if (combined.length === 0) {
    console.log("چیزی برای تست نیست، خروج.");
    return;
  }

  console.log(`شروع تست با ${CONCURRENCY} پروسه‌ی هم‌زمان...`);
  const { healthy, tested } = await testAll(combined, CONCURRENCY);
  console.log(`نتیجه: ${healthy.length} سالم از ${tested.size} تست‌شده.`);

  if (healthy.length === 0) {
    console.log("هیچ سرور سالمی پیدا نشد — لیست کلودفلر دست‌نخورده می‌ماند.");
    return;
  }

  console.log("دریافت مجدد لیست کلودفلر برای merge امن...");
  const freshRemote = await fetchCloudflareServers(CF_ALL_URL).catch(() => cfServers);
  const merged = mergeResults(freshRemote, tested, healthy);

  // محافظ در برابر کوچک شدن ناگهانی و مخرب لیست (چون Worker خودش
  // چنین چکی ندارد و جایگزینی را بدون سؤال قبول می‌کند)
  if (freshRemote.length > 0) {
    const ratio = merged.length / freshRemote.length;
    if (ratio < MIN_KEEP_RATIO) {
      console.error(
        `⚠️ آپلود متوقف شد: لیست نهایی (${merged.length}) کمتر از ` +
        `${Math.round(MIN_KEEP_RATIO * 100)}% لیست فعلی (${freshRemote.length}) است. ` +
        `این می‌تواند نشانه‌ی یک مشکل شبکه‌ی runner یا باگ باشد، نه واقعاً ` +
        `خراب بودن این‌همه سرور. برای عبور از این محافظ، MIN_KEEP_RATIO را کم کنید.`
      );
      process.exit(1);
    }
  }

  console.log(`آپلود ${merged.length} سرور نهایی به کلودفلر...`);
  const ok = await uploadToCloudflare(CF_UPDATE_URL, merged);
  console.log(ok ? "✅ آپلود موفق بود." : "❌ آپلود ناموفق بود.");

  if (!ok) process.exit(1);
}

main().catch((e) => {
  console.error("خطای کلی:", e);
  process.exit(1);
});
