import https from "node:https";
import { generateKeyPairSync } from "node:crypto";

function api(method, path, body, token) {
  return new Promise((ok, fail) => {
    const headers = {
      "User-Agent": "okhttp/3.12.1",
      "CF-Client-Version": "a-6.3-1922",
      "Content-Type": "application/json; charset=UTF-8",
    };
    if (token) headers.Authorization = `Bearer ${token}`;
    const req = https.request(
      `https://api.cloudflareclient.com/v0a1922${path}`,
      { method, headers, maxVersion: "TLSv1.2", timeout: 4000 },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          if (res.statusCode !== 200)
            return fail(new Error(`HTTP ${res.statusCode}`));
          try { ok(JSON.parse(data)); } catch (e) { fail(e); }
        });
      });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", fail);
    req.end(JSON.stringify(body));
  });
}

// Đăng ký 1 tài khoản WARP, trả về dữ liệu chung cho mọi định dạng
async function register() {
  const jwk = generateKeyPairSync("x25519")
    .privateKey.export({ format: "jwk" });
  const b64 = (s) => Buffer.from(s, "base64url").toString("base64");
  const reg = await api("POST", "/reg", {
    key: b64(jwk.x), install_id: "", fcm_token: "",
    tos: new Date().toISOString(),
    type: "Android", locale: "en_US",
  });
  const res = await api("PATCH", `/reg/${reg.id}`,
    { warp_enabled: true }, reg.token);
  const c = res.config, peer = c.peers[0];
  const endpoint = peer.endpoint.host; // dạng "host:port"
  const cut = endpoint.lastIndexOf(":");
  return {
    name: `WARP-${reg.id.slice(0, 8)}`,
    endpoint,
    host: endpoint.slice(0, cut),
    port: Number(endpoint.slice(cut + 1)),
    publicKey: peer.public_key,
    privateKey: b64(jwk.d),
    v4: c.interface.addresses.v4,
    v6: c.interface.addresses.v6,
    reserved: [...Buffer.from(c.client_id, "base64")],
    mtu: 1280,
  };
}

// 1. Shadowrocket
function shadowrocket(w) {
  const e = encodeURIComponent;
  return `wg://${w.endpoint}`
    + `?publicKey=${e(w.publicKey)}`
    + `&privateKey=${e(w.privateKey)}`
    + `&ip=${w.v4}%2F32`
    + `&mtu=${w.mtu}&dns=1.1.1.1&udp=1`
    + `&reserved=${w.reserved}`
    + `#${w.name}`;
}

// 2. Link wireguard://
function wireguardUri(w) {
  const e = encodeURIComponent;
  return `wireguard://${e(w.privateKey)}@${w.endpoint}`
    + `?publickey=${e(w.publicKey)}`
    + `&address=${e(`${w.v4}/32,${w.v6}/128`)}`
    + `&reserved=${e(w.reserved.join(","))}`
    + `&mtu=${w.mtu}`
    + `#${w.name}`;
}

// 3. File .conf chuẩn WireGuard (không có trường reserved)
const wireguardConf = (w) => `[Interface]
PrivateKey = ${w.privateKey}
Address = ${w.v4}/32, ${w.v6}/128
DNS = 1.1.1.1, 2606:4700:4700::1111
MTU = ${w.mtu}

[Peer]
PublicKey = ${w.publicKey}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${w.endpoint}
PersistentKeepalive = 25
`;

// 4. sing-box 1.12 trở lên
const singbox = (w) => JSON.stringify({
  dns: {
    servers: [
      { type: "https", tag: "cf", server: "1.1.1.1", detour: w.name },
      { type: "local", tag: "local" },
    ],
    final: "cf",
  },
  inbounds: [{
    type: "tun", tag: "tun-in",
    address: ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
    auto_route: true, strict_route: true,
  }],
  endpoints: [{
    type: "wireguard", tag: w.name, mtu: w.mtu,
    address: [`${w.v4}/32`, `${w.v6}/128`],
    private_key: w.privateKey,
    peers: [{
      address: w.host, port: w.port,
      public_key: w.publicKey,
      allowed_ips: ["0.0.0.0/0", "::/0"],
      reserved: w.reserved,
    }],
  }],
  route: {
    rules: [
      { action: "sniff" },
      { protocol: "dns", action: "hijack-dns" },
    ],
    final: w.name,
    auto_detect_interface: true,
    default_domain_resolver: "local",
  },
}, null, 2);

// 5. Clash Meta (Mihomo)
const mihomo = (w) => `proxies:
  - name: "${w.name}"
    type: wireguard
    server: ${w.host}
    port: ${w.port}
    ip: ${w.v4}
    ipv6: "${w.v6}"
    private-key: "${w.privateKey}"
    public-key: "${w.publicKey}"
    allowed-ips: ["0.0.0.0/0", "::/0"]
    reserved: [${w.reserved.join(", ")}]
    mtu: ${w.mtu}
    udp: true

proxy-groups:
  - name: PROXY
    type: select
    proxies: ["${w.name}", DIRECT]

rules:
  - MATCH,PROXY
`;

// 6. Thông số thô để nhập tay
const raw = (w) => `Server: ${w.host}
Port: ${w.port}
PublicKey: ${w.publicKey}
PrivateKey: ${w.privateKey}
IPv4: ${w.v4}/32
IPv6: ${w.v6}/128
Reserved: ${w.reserved.join(",")}
Client ID (base64): ${Buffer.from(w.reserved).toString("base64")}
DNS: 1.1.1.1
MTU: ${w.mtu}
AllowedIPs: 0.0.0.0/0, ::/0`;

// Trang kết quả: văn bản thuần, giống xem raw trên GitHub
const output = (w) => [
  ["Shadowrocket (iOS)", shadowrocket(w)],
  ["v2rayNG, v2rayN", wireguardUri(w)],
  ["WireGuard chính thức (.conf)", wireguardConf(w)],
  ["Raw (nhập tay)", raw(w)],
  ["sing-box 1.12+: SFI, SFA, SFM (.json)", singbox(w)],
  ["Clash Verge Rev, FlClash, Clash Meta for Android (.yaml)", mihomo(w)],
].map(([app, text]) => `===== ${app} =====\n${text.trim()}`)
  .join("\n\n\n") + "\n";

const reply = (body, status = 200, type = "text/plain") =>
  new Response(body, {
    status,
    headers: {
      "Content-Type": `${type}; charset=utf-8`,
      "Cache-Control": "no-store",
    },
  });

const page = (siteKey) => `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<title>WARP</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<form id="f" method="post" action="/">
  <div class="cf-turnstile" data-sitekey="${siteKey}"
       data-callback="done"></div>
</form>
<script>function done() { f.submit(); }</script>`;

export default async (request, context) => {
  const siteKey = process.env.TURNSTILE_SITEKEY;
  const secret = process.env.TURNSTILE_SECRET;
  if (!siteKey || !secret)
    return reply("Lỗi: thiếu biến môi trường Turnstile", 500);

  if (request.method !== "POST")
    return reply(page(siteKey), 200, "text/html");

  try {
    const form = await request.formData();
    const token = form.get("cf-turnstile-response");
    if (!token) return Response.redirect(new URL("/", request.url), 303);

    const check = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        body: new URLSearchParams({
          secret, response: token, remoteip: context.ip || "",
        }),
        signal: AbortSignal.timeout(4000),
      });
    const result = await check.json();

    if (!result.success) {
      const codes = result["error-codes"] || [];
      // Token cũ (refresh trang kết quả): quay về trang captcha
      if (codes.includes("timeout-or-duplicate"))
        return Response.redirect(new URL("/", request.url), 303);
      return reply("Captcha lỗi: " + codes.join(", "), 403);
    }

    return reply(output(await register()));
  } catch (err) {
    console.error(err.message);
    return reply("Lỗi: " + err.message, 502);
  }
};

export const config = {
  path: "/",
  rateLimit: { windowLimit: 6, windowSize: 60,
               aggregateBy: ["ip", "domain"] },
};
