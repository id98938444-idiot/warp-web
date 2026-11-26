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

async function makeLink() {
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
  const e = encodeURIComponent;
  return `wg://${peer.endpoint.host}`
    + `?publicKey=${e(peer.public_key)}`
    + `&privateKey=${e(b64(jwk.d))}`
    + `&ip=${c.interface.addresses.v4}%2F32`
    + `&mtu=1280&dns=1.1.1.1&udp=1`
    + `&reserved=${[...Buffer.from(c.client_id, "base64")]}`
    + `#WARP-${reg.id.slice(0, 8)}`;
}

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

    return reply(await makeLink());
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
