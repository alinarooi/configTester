const fs = require('fs/promises');
const net = require('net');
const https = require('https');

// لیست نام‌های ایرانی برای اختصاص به سرورهای موفق
const iranianNames = ["سیمرغ", "سورنا", "آرتین", "ققنوس", "آریو", "کوروش", "بردیا", "رستم", "کاوه", "آرش"];

// تنظیمات تست
const TIMEOUT_MS = 3500; // 3.5 ثانیه زمان برای تست هر سرور

/**
 * تست پورت TCP برای سرورهای V2Ray (VMess)
 */
function testTcpPort(host, port) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        
        const timer = setTimeout(() => {
            socket.destroy();
            resolve(false);
        }, TIMEOUT_MS);

        socket.connect(port, host, () => {
            clearTimeout(timer);
            socket.destroy();
            resolve(true); // پورت باز است
        });

        socket.on('error', () => {
            clearTimeout(timer);
            resolve(false);
        });
    });
}

/**
 * تست پروتکل SSTP روی پورت 443
 */
function testSstpServer(ip) {
    return new Promise((resolve) => {
        const options = {
            hostname: ip,
            port: 443,
            path: '/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/',
            method: 'GET',
            rejectUnauthorized: false, // نادیده گرفتن خطای گواهی SSL
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
 * پردازش و تست یک کانفیگ
 */
async function processConfig(line) {
    line = line.trim();
    if (!line) return null;

    try {
        // تشخیص و پردازش VMess
        if (line.startsWith('vmess://')) {
            const base64Data = line.replace('vmess://', '');
            const decodedStr = Buffer.from(base64Data, 'base64').toString('utf8');
            const config = JSON.parse(decodedStr);
            
            const host = config.add || config.host;
            const port = parseInt(config.port, 10);

            if (host && port) {
                const isAlive = await testTcpPort(host, port);
                if (isAlive) {
                    return { type: 'vmess', raw: line, host, port };
                }
            }
        } 
        // فرض بر اینکه خطوط دیگر IP یا دامنه برای SSTP هستند
        else {
            const ip = line.split(':')[0]; // در صورت وجود پورت در متن، فقط IP را می‌گیریم
            const isAlive = await testSstpServer(ip);
            if (isAlive) {
                return { type: 'sstp', raw: line, host: ip, port: 443 };
            }
        }
    } catch (error) {
        // نادیده گرفتن کانفیگ‌های خراب یا غیرقابل پارس
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
        const lines = fileContent.split('\n');
        console.log(`تعداد ${lines.length} خط خوانده شد. در حال تست سرورها...`);

        const validServers = [];
        let nameIndex = 0;

        // برای جلوگیری از مسدود شدن شبکه، سرورها را 10 تا 10 تا تست می‌کنیم (Concurrency Limit)
        const batchSize = 10;
        for (let i = 0; i < lines.length; i += batchSize) {
            const batch = lines.slice(i, i + batchSize);
            const results = await Promise.all(batch.map(processConfig));
            
            for (const result of results) {
                if (result) {
                    // اختصاص نام ایرانی به سرور موفق
                    result.name = iranianNames[nameIndex % iranianNames.length];
                    nameIndex++;
                    validServers.push(result);
                    console.log(`✅ سرور فعال پیدا شد: ${result.name} (${result.type})`);
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
