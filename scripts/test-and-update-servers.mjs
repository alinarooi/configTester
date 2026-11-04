import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import tls from "node:tls";
import net from "node:net";

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

const CONCURRENCY = Number(process.env.CONCURRENCY || 20);
const TEST_TIMEOUT_MS = Number(process.env.TEST_TIMEOUT_MS || 5000);
const MIN_KEEP_RATIO = Number(process.env.MIN_KEEP_RATIO || 0.5);
const SSTP_TIMEOUT_MS = Number(process.env.SSTP_TIMEOUT_MS || 30000);

// =====================================================================
// Cloudflare - GET (دریافت لیست سرورها از ورکر کلودفلر)
// =====================================================================
async function fetchCloudflareServers(url) {
  console.log(`در حال دریافت لیست سرورها از ورکر کلودفلر: ${url}`);
  const res = await fetch(url, {
    signal: AbortSignal.timeout(15000),
  });

  if (!res.ok) {
    throw new Error(`Cloudflare HTTP ${res.status}`);
  }

  const arr = await res.json();

  if (!Array.isArray(arr)) {
    throw new Error("پاسخ ورکر کلودفلر آرایه نیست.");
  }

  return arr
    .map((o, i) => {
      const address = String(o.address || o.uri || "").trim();
      const rawPort = String(o.port ?? "443").trim();
      const numericPort = Number(rawPort) || 443;
      const protocol = String(o.protocol || "softether_tcp").trim();
      const operator = String(o.operator || "").trim();

      return {
        id: String(o.id ?? i),
        address,
        port: numericPort,
        protocol,
        operator,
        country: String(o.country || o.name || "Unknown").trim(),
        ping: Number.isFinite(Number(o.ping)) ? Number(o.ping) : -1,
        icon: String(o.icon || "").trim(),
      };
    })
    .filter(s => s.address.length > 0);
}

// =====================================================================
// Cloudflare - UPDATE (با محافظ امنیتی برای جلوگیری از حذف کل سرورها)
// =====================================================================
async function uploadToCloudflare(url, newServers, existingServersCount) {
  if (!Array.isArray(newServers)) {
    throw new Error("لیست نهایی آرایه نیست.");
  }

  if (existingServersCount > 10 && newServers.length < existingServersCount * MIN_KEEP_RATIO) {
    console.warn(`⚠️ هشدار امنیتی: تعداد سرورهای سالم (${newServers.length}) کمتر از حد مجاز نسبت به قبلی‌ها (${existingServersCount}) است. آپدیت لغو شد تا سرورها پاک نشوند.`);
    return;
  }

  const body = newServers.map((s, index) => ({
    id: String(index),
    address: String(s.address || "").trim(),
    port: String(s.port || 443),
    protocol: String(s.protocol || "softether_tcp").trim(),
    operator: String(s.operator || "").trim(),
    country: String(s.country || "Unknown").trim(),
    icon: String(s.icon || "").trim(),
    ok: true,
    reason: "ok",
    ms: s.ping || 0,
    tested_at: Math.floor(Date.now() / 1000)
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
    throw new Error(`Cloudflare update HTTP ${res.status}: ${responseText.slice(0, 500)}`);
  }

  console.log(`☁️ Cloudflare با موفقیت آپدیت شد: ${body.length} سرور`);
}

// =====================================================================
// SoftEther TCP Probe Tester
// =====================================================================
function testSoftEtherTcp(ip, port, timeoutMs = TEST_TIMEOUT_MS) {
  return new Promise(resolve => {
    const start = Date.now();
    const socket = new net.Socket();
    let settled = false;

    const finish = (ok) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(ok ? Date.now() - start : null);
    };

    socket.setTimeout(timeoutMs);
    socket.on("connect", () => finish(true));
    socket.on("timeout", () => finish(false));
    socket.on("error", () => finish(false));

    try {
      socket.connect(port, ip);
    } catch {
      finish(false);
    }
  });
}

async function testAllSoftEther(servers, concurrency) {
  const healthy = [];
  let nextIndex = 0;

  async function worker() {
    while (true) {
      const i = nextIndex++;
      if (i >= servers.length) return;

      const server = servers[i];
      const address = server.address;
      const port = Number(server.port) || 443;

      const ping = await testSoftEtherTcp(address, port, TEST_TIMEOUT_MS);

      if (ping !== null) {
        healthy.push({ ...server, ping, protocol: "softether_tcp" });
        console.log(`✅ [SoftEther] سالم (${ping}ms): ${address}:${port} [operator=${server.operator}]`);
      } else {
        console.log(`❌ [SoftEther] ناسالم: ${address}:${port} [operator=${server.operator}]`);
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
// SSTP Handshake Tester
// =====================================================================
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
      const req =
        `SSTP_DUPLEX_POST /sra_{${guid}} HTTP/1.1\r\n` +
        `Content-Length: 18446744073709551615\r\n` +
        `Host: ${host}\r\n\r\n`;
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

async function testAllSstp(servers, concurrency) {
  const healthy = [];
  let nextIndex = 0;

  async function worker() {
    while (true) {
      const i = nextIndex++;
      if (i >= servers.length) return;

      const server = servers[i];
      const host = server.address;
      const ping = await testSstpHandshake(host, server.port);

      if (ping !== null) {
        healthy.push({ ...server, ping, protocol: "sstp" });
        console.log(`✅ [SSTP] سالم (${ping}ms): ${host}:${server.port} [operator=${server.operator}]`);
      } else {
        console.log(`❌ [SSTP] ناسالم: ${host}:${server.port} [operator=${server.operator}]`);
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
// Main Workflow
// =====================================================================
async function main() {
  console.log("🚀 شروع فرایند تست و بروزرسانی سرورها از ورکر کلودفلر...");

  let servers = [];
  try {
    servers = await fetchCloudflareServers(CF_ALL_URL);
    console.log(`☁️ تعداد کل سرورهای دریافتی از ورکر: ${servers.length}`);
  } catch (e) {
    console.error("❌ خطا در دریافت سرورها از ورکر:", e.message);
    process.exit(1);
  }

  if (servers.length === 0) {
    console.log("⚠️ هیچ سروری برای تست در ورکر وجود ندارد.");
    return;
  }

  // تفکیک سرورها بر اساس پروتکل ذخیره شده در ورکر
  const softetherServers = servers.filter(s => s.protocol === "softether_tcp" || !s.protocol);
  const sstpServers = servers.filter(s => s.protocol === "sstp");

  console.log(`📊 تفکیک برای تست: ${softetherServers.length} SoftEther و ${sstpServers.length} SSTP`);

  // تست همزمان سرورها با پورت و پروتکل خودشان
  console.log("🧪 در حال تست سرورهای SoftEther...");
  const healthySoftEther = await testAllSoftEther(softetherServers, CONCURRENCY);

  console.log("🧪 در حال تست سرورهای SSTP...");
  const healthySstp = await testAllSstp(sstpServers, 5);

  const allHealthyServers = [
    ...healthySoftEther,
    ...healthySstp
  ];

  console.log(`🎉 کل سرورهای سالم نهایی جهت آپدیت به ورکر: ${allHealthyServers.length} از ${servers.length}`);

  try {
    await uploadToCloudflare(CF_UPDATE_URL, allHealthyServers, servers.length);
  } catch (e) {
    console.error("❌ خطا در ارسال سرورهای سالم به ورکر:", e.message);
    process.exit(1);
  }

  console.log("✅ عملیات تست و بروزرسانی با موفقیت به پایان رسید.");
}

main().catch(err => {
  console.error("❌ خطای ناشناخته:", err);
  process.exit(1);
});
