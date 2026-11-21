import { json, getToken, sha256, clearCookie } from "../_lib/auth.js";
export async function onRequestPost({ request, env }) {
  const token = getToken(request);
  if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(token)).run();
  return json({ ok: true }, 200, { "set-cookie": clearCookie() });
}
