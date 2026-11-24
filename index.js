const fs = require('fs/promises');
const net = require('net');
const https = require('https');

// تنظیمات تست
const TIMEOUT_MS = 3500;
const SSTP_HANDSHAKE_PATH = '/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/';

/**
 * تست پروتکل SSTP روی هاست/IP و پورت مشخص (پیش‌فرض 443)
 */
function testSstpServer(host, port = 443) {
    return new Promise((resolve) => {
        const options = {
            hostname: host,
            port,
            path: SSTP_HANDSHAKE_PATH,
            method: 'GET',
            rejectUnauthorized: false,
            timeout: TIMEOUT_MS
        };

        const req = https.request(options, (res) => {
            resolve(res.statusCode > 0);
        });

        req.on('error', () => resolve(false));
        req.on('timeout', () => {
            req.destroy();
            resolve(false);
        });

        req.end();
    });
}

/**
 * تست اتصال TCP خام برای سرورهای SoftEther TCP
 */
function testTcpSocket(host, port = 443) {
    return new Promise((resolve) => {
        const socket = new net.Socket();

        const timer = setTimeout(() => {
            socket.destroy();
            resolve(false);
        }, TIMEOUT_MS);

        socket.connect(port, host, () => {
            clearTimeout(timer);
            socket.destroy();
            resolve(true);
        });

        socket.on('error', () => {
            clearTimeout(timer);
            resolve(false);
        });
    });
}

/**
 * تست متناسب با پروتکل SoftEther TCP:
 * ابتدا باز بودن سوکت TCP را چک می‌کند و سپس یک handshake سبک HTTP/TLS روی همان پورت می‌فرستد
 */
function testSoftEtherTcpServer(host, port = 443) {
    return new Promise(async (resolve) => {
        const tcpOk = await testTcpSocket(host, port);
        if (!tcpOk) {
            return resolve(false);
        }

        const options = {
            hostname: host,
            port,
            path: '/',
            method: 'GET',
            rejectUnauthorized: false,
            timeout: TIMEOUT_MS
        };

        const req = https.request(options, (res) => {
            resolve(res.statusCode > 0);
        });

        // اگر سوکت TCP باز بود ولی پاسخ HTTPS نداد، همچنان اگر پورت TCP پاسخ داده باشد قابل بررسی است
        req.on('error', () => resolve(true));
        req.on('timeout', () => {
            req.destroy();
            resolve(true);
        });

        req.end();
    });
}

/**
 * نرمال‌سازی نام پروتکل
 */
function normalizeProtocol(rawProto) {
    const p = (rawProto || '').trim().toLowerCase();
    if (p === 'softether' || p === 'softether_tcp' || p === 'se_tcp' || p === 'tcp') {
        return 'softether_tcp';
    }
    if (p === 'sstp') {
        return 'sstp';
    }
    return 'sstp';
}

/**
 * تجزیه یک خط از فایل servers.txt
 * فرمت‌های پشتیبانی‌شده:
 * - host
 * - host:port
 * - host:port|protocol
 * - host,port,protocol
 * - یا یک شیء JSON در هر خط (مثلاً خروجی کلاینت: {"address":"...","port":"443","protocol":"softether_tcp"})
 */
function parseTarget(line) {
    const cleaned = line.trim();
    if (!cleaned || cleaned.startsWith('#')) return null;

    // اگر خط به صورت JSON باشد
    if (cleaned.startsWith('{')) {
        const obj = JSON.parse(cleaned);
        const host = String(obj.address || obj.full_host || obj.host || '').trim();
        const port = parseInt(obj.port, 10) || 443;
        const protocol = normalizeProtocol(obj.protocol || obj.type);
        if (!host) return null;
        return {
            name: String(obj.name || obj.id || host).trim(),
            host,
            port,
            protocol,
            raw: cleaned,
            meta: obj
        };
    }

    let mainPart = cleaned;
    let explicitProtocol = '';

    if (cleaned.includes('|')) {
        const [left, right] = cleaned.split('|').map((s) => s.trim());
        mainPart = left;
        explicitProtocol = right;
    }

    let host = mainPart;
    let port = 443;

    if (mainPart.includes(',')) {
        const parts = mainPart.split(',').map((s) => s.trim());
        host = parts[0] || '';
        const parsedPort = parseInt(parts[1], 10);
        if (Number.isInteger(parsedPort) && parsedPort > 0) port = parsedPort;
        if (parts[2]) explicitProtocol = parts[2];
    } else if (mainPart.startsWith('[')) {
        const closeBracketIdx = mainPart.indexOf(']');
        if (closeBracketIdx !== -1) {
            host = mainPart.slice(1, closeBracketIdx).trim();
            const rest = mainPart.slice(closeBracketIdx + 1).trim();
            if (rest.startsWith(':')) {
                const parsedPort = parseInt(rest.slice(1), 10);
                if (Number.isInteger(parsedPort) && parsedPort > 0) port = parsedPort;
            }
        }
    } else {
        const colonCount = (mainPart.match(/:/g) || []).length;
        if (colonCount === 1) {
            const [rawHost, rawPort] = mainPart.split(':').map((s) => s.trim());
            const parsedPort = parseInt(rawPort, 10);
            if (rawHost && Number.isInteger(parsedPort) && parsedPort > 0) {
                host = rawHost;
                port = parsedPort;
            }
        }
    }

    if (!host) return null;

    // اگر در خود رشته نشانی softether نوشته شده بود و پروتکل صریح داده نشده بود
    if (!explicitProtocol && host.toLowerCase().includes('softether')) {
        explicitProtocol = 'softether_tcp';
    }

    const protocol = normalizeProtocol(explicitProtocol);
    return {
        name: host,
        host,
        port,
        protocol,
        raw: cleaned,
        meta: null
    };
}

/**
 * اجرای تست متناسب با پروتکل سرور
 */
async function runProtocolTest(target) {
    if (target.protocol === 'softether_tcp') {
        return testSoftEtherTcpServer(target.host, target.port);
    }
    return testSstpServer(target.host, target.port);
}

/**
 * پردازش و تست یک خط از servers.txt
 */
async function processConfig(line) {
    const target = parseTarget(line);
    if (!target) return null;

    try {
        const isAlive = await runProtocolTest(target);
        if (isAlive) {
            return {
                ...(target.meta || {}),
                name: target.name,
                type: target.protocol,
                protocol: target.protocol,
                host: target.host,
                address: target.host,
                port: target.port,
                raw: target.raw
            };
        }
    } catch (_) {
        // نادیده گرفتن ورودی‌های نامعتبر یا ناموفق
    }

    return null;
}

/**
 * آپدیت دیتابیس Cloudflare KV
 */
async function updateCloudflareKV(serversList) {
    const accountId = process.env.CF_ACCOUNT_ID;
    const namespaceId = process.env.CF_NAMESPACE_ID;
    const apiToken = process.env.CF_API_TOKEN;

    if (!accountId || !namespaceId || !apiToken) {
        console.error("خطا: متغیرهای محیطی Cloudflare تنظیم نشده‌اند!");
        return;
    }

    const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values/active_servers`;

    console.log(`در حال آپلود ${serversList.length} سرور به Cloudflare KV...`);

    const response = await fetch(url, {
        method: 'PUT',
        headers: {
            'Authorization': `Bearer ${apiToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(serversList)
    });

    if (response.ok) {
        console.log("✅ لیست سرورها با موفقیت در Cloudflare KV آپدیت شد.");
    } else {
        const errorText = await response.text();
        console.error("❌ خطا در آپدیت KV:", errorText);
    }
}

/**
 * تابع اصلی اجرای برنامه
 */
async function main() {
    console.log("شروع خواندن فایل servers.txt...");

    try {
        const fileContent = await fs.readFile('servers.txt', 'utf8');
        const lines = fileContent.split(/\r?\n/);
        console.log(`تعداد ${lines.length} خط خوانده شد. در حال تست سرورها...`);

        const validServers = [];
        const batchSize = 10;

        for (let i = 0; i < lines.length; i += batchSize) {
            const batch = lines.slice(i, i + batchSize);
            const results = await Promise.all(batch.map(processConfig));

            for (const result of results) {
                if (result) {
                    validServers.push(result);
                    console.log(`✅ سرور فعال پیدا شد: ${result.name}:${result.port} [${result.protocol}]`);
                }
            }
        }

        console.log(`تست تمام شد. مجموع سرورهای فعال: ${validServers.length}`);

        if (validServers.length > 0) {
            await updateCloudflareKV(validServers);
        } else {
            console.log("هیچ سرور فعالی پیدا نشد. دیتابیس آپدیت نمی‌شود.");
        }
    } catch (error) {
        console.error("خطا در اجرای برنامه:", error.message);
    }
}

// اجرای برنامه
main();
