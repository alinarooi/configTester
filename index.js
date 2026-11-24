const shuffle = (array) => {
  const arr = [...array];
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
};

const corsHeaders = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, HEAD, OPTIONS",
  "access-control-allow-headers": "Content-Type, X-Update-Key",
};

const normalizeServer = (server) => {
  const address = String(server.address || server.full_host || server.host || server.link || "")
    .trim()
    .toLowerCase();
  const port = String(server.port || "443").trim();
  const protocol = String(server.protocol || server.type || "softether_tcp")
    .trim()
    .toLowerCase();
  const operator = String(server.operator || "unknown")
    .trim()
    .toLowerCase();

  return {
    ...server,
    address,
    full_host: String(server.full_host || address).trim(),
    port,
    protocol,
    operator,
  };
};

const getUniqueKey = (server) => {
  const s = normalizeServer(server);
  return `${s.address}:${s.port}_${s.protocol}_${s.operator}`;
};

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    // ۱. آپدیت و ادغام سرورها در کلید اصلی server_list
    if (url.pathname === "/update_servers" && request.method === "POST") {
      if (env.UPDATE_KEY) {
        const providedKey = request.headers.get("X-Update-Key") || "";
        if (providedKey !== env.UPDATE_KEY) {
          return new Response(JSON.stringify({ success: false, error: "Unauthorized" }), {
            status: 401,
            headers: { ...corsHeaders, "content-type": "application/json" },
          });
        }
      }

      try {
        const body = await request.text();
        const parsed = JSON.parse(body);
        const incomingRaw = Array.isArray(parsed) ? parsed : [parsed];

        const existingData = await env.SERVER.get("server_list");
        let existingServers = [];
        if (existingData) {
          const parsedExisting = JSON.parse(existingData);
          if (Array.isArray(parsedExisting)) {
            existingServers = parsedExisting;
          }
        }

        const combinedMap = new Map();

        for (const srv of existingServers) {
          if (srv && typeof srv === "object") {
            const normalized = normalizeServer(srv);
            if (normalized.address) {
              combinedMap.set(getUniqueKey(normalized), normalized);
            }
          }
        }

        for (const srv of incomingRaw) {
          if (srv && typeof srv === "object") {
            const normalized = normalizeServer(srv);
            if (normalized.address) {
              combinedMap.set(getUniqueKey(normalized), normalized);
            }
          }
        }

        const updatedServers = Array.from(combinedMap.values());
        await env.SERVER.put("server_list", JSON.stringify(updatedServers));

        return new Response(
          JSON.stringify({
            success: true,
            kvKey: "server_list",
            message: "Servers updated and merged successfully!",
            totalServers: updatedServers.length,
          }),
          {
            status: 200,
            headers: { ...corsHeaders, "content-type": "application/json; charset=utf-8" },
          }
        );
      } catch (e) {
        return new Response(JSON.stringify({ success: false, error: e.message }), {
          status: 400,
          headers: { ...corsHeaders, "content-type": "application/json; charset=utf-8" },
        });
      }
    }

    // ۲. دریافت کل server_list بدون شافل و برش
    if (url.pathname === "/get_all_servers") {
      const data = await env.SERVER.get("server_list");
      if (!data) {
        return new Response(JSON.stringify({ error: "not found" }), {
          status: 404,
          headers: { ...corsHeaders, "content-type": "application/json; charset=utf-8" },
        });
      }
      return new Response(data, {
        headers: {
          ...corsHeaders,
          "content-type": "application/json; charset=utf-8",
        },
      });
    }

    // ۳. دریافت ۱۵ سرور از هر ۴ اپراتور از server_list
    if (url.pathname === "/four_operators") {
      const data = await env.SERVER.get("server_list");
      if (!data) {
        return new Response("not found", { status: 404, headers: corsHeaders });
      }

      try {
        const servers = JSON.parse(data);
        const byOp = (op) =>
          shuffle(
            servers.filter((s) => s.operator && String(s.operator).toLowerCase() === op)
          ).slice(0, 15);

        const combined = [
          ...byOp("irancell"),
          ...byOp("mci"),
          ...byOp("rightel"),
          ...byOp("wifi"),
        ];

        return new Response(JSON.stringify(shuffle(combined), null, 2), {
          headers: {
            ...corsHeaders,
            "content-type": "application/json; charset=utf-8",
            "Cache-Control": "public, max-age=60",
          },
        });
      } catch (e) {
        return new Response("Invalid JSON data in KV", { status: 500, headers: corsHeaders });
      }
    }

    if (url.pathname === "/checker") {
      const status = await env.SERVER.get("checker");
      return new Response(status || "not found", {
        headers: { ...corsHeaders, "content-type": "text/plain; charset=utf-8" },
      });
    }

    // ۴. نگاشت مسیرها به کلیدهای KV (همگی روی server_list هماهنگ شده‌اند)
    const routeMap = {
      "/server_list": "server_list",
      "/server_list1": "server_list1",
      "/server_list2": "server_list2",
      "/server_list3": "server_list3",
      "/server_list4": "server_list4",
      "/server_list5": "server_list5",
      "/server_list6": "server_list6",
      "/text_custom": "text_custom",
      "/allservers": "server_list",
    };

    const kvKey = routeMap[url.pathname];
    if (kvKey) {
      const data = await env.SERVER.get(kvKey);
      if (!data) {
        return new Response("not found", { status: 404, headers: corsHeaders });
      }

      if (url.pathname === "/text_custom") {
        return new Response(data, {
          headers: {
            ...corsHeaders,
            "content-type": "text/plain; charset=utf-8",
          },
        });
      }

      try {
        const servers = JSON.parse(data);
        let resultServers = [];

        if (url.pathname === "/server_list") {
          const softetherServers = shuffle(
            servers.filter((s) => s.protocol === "softether_tcp" || !s.protocol)
          ).slice(0, 20);
          const sstpServers = shuffle(servers.filter((s) => s.protocol === "sstp")).slice(0, 10);
          resultServers = shuffle([...softetherServers, ...sstpServers]);
        } else if (url.pathname === "/allservers") {
          resultServers = shuffle(servers);
        } else {
          resultServers = shuffle(servers).slice(0, 15);
        }

        return new Response(JSON.stringify(resultServers, null, 2), {
          headers: {
            ...corsHeaders,
            "content-type": "application/json; charset=utf-8",
            "Cache-Control": "public, max-age=60",
          },
        });
      } catch (e) {
        return new Response("Invalid JSON data in KV", { status: 500, headers: corsHeaders });
      }
    }

    return new Response("404 not found", { status: 404, headers: corsHeaders });
  },
};
