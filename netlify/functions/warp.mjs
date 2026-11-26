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
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => {
          if (res.statusCode !== 200)
            return fail(new Error(`HTTP ${res.statusCode}`));
          try { ok(JSON.parse(text)); } catch (e) { fail(e); }
        });
      });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", fail);
    req.end(JSON.stringify(body));
  });
}

const text = (body, status = 200) =>
  new Response(body, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });

export default async () => {
  try {
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
    return text(`wg://${peer.endpoint.host}`
      + `?publicKey=${e(peer.public_key)}`
      + `&privateKey=${e(b64(jwk.d))}`
      + `&ip=${c.interface.addresses.v4}%2F32`
      + `&mtu=1280&dns=1.1.1.1&udp=1`
      + `&reserved=${[...Buffer.from(c.client_id, "base64")]}`
      + `#WARP-${reg.id.slice(0, 8)}`);
  } catch (err) {
    console.error(err.message);
    return text("Lỗi: " + err.message, 502);
  }
};

export const config = {
  path: "/",
  rateLimit: { windowLimit: 2, windowSize: 60,
               aggregateBy: ["ip", "domain"] },
};
