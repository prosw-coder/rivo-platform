export const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
export const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
export const fromB64 = (value) => { const normalized = value.replaceAll("-", "+").replaceAll("_", "/"); const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4); return Uint8Array.from(atob(padded), c => c.charCodeAt(0)); };
export async function sha256(value) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return b64(bytes);
}
export async function passwordHash(password, salt, iterations = 600000) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: fromB64(salt), iterations, hash: "SHA-256" }, key, 256);
  return b64(bits);
}
export function newToken(bytes = 32) {
  const value = crypto.getRandomValues(new Uint8Array(bytes));
  return b64(value).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
export function cookie(token) {
  return `rivo_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000`;
}
export function clearCookie() {
  return "rivo_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}
export function getToken(request) {
  const raw = request.headers.get("Cookie") || "";
  const match = raw.match(/(?:^|; )rivo_session=([^;]+)/);
  return match ? match[1] : null;
}
export async function currentUser(request, env) {
  const token = getToken(request);
  if (!token) return null;
  const tokenHash = await sha256(token);
  const row = await env.DB.prepare("SELECT u.id, u.handle, u.profile_cipher, u.profile_iv, u.profile_salt, u.avatar_key FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?").bind(tokenHash, Date.now()).first();
  return row || null;
}
export async function startSession(userId, env) {
  const token = newToken();
  const tokenHash = await sha256(token);
  const now = Date.now();
  await env.DB.prepare("INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,?,?,?)").bind(tokenHash, userId, now + 30 * 24 * 60 * 60 * 1000, new Date(now).toISOString()).run();
  return token;
}

export async function consumeRateLimit(env, keyHash, maxAttempts = 8, windowMs = 15 * 60 * 1000, blockMs = 15 * 60 * 1000) {
  const now = Date.now();
  const current = await env.DB.prepare("SELECT window_start,attempts,blocked_until FROM auth_rate_limits WHERE key_hash=?").bind(keyHash).first();
  if (current?.blocked_until && Number(current.blocked_until) > now) return { allowed:false, retryAfter:Math.ceil((Number(current.blocked_until)-now)/1000) };
  const reset = !current || Number(current.window_start) <= now - windowMs;
  const attempts = reset ? 1 : Number(current.attempts) + 1;
  const windowStart = reset ? now : Number(current.window_start);
  const blockedUntil = attempts > maxAttempts ? now + blockMs : null;
  await env.DB.prepare("INSERT INTO auth_rate_limits(key_hash,window_start,attempts,blocked_until) VALUES(?,?,?,?) ON CONFLICT(key_hash) DO UPDATE SET window_start=excluded.window_start,attempts=excluded.attempts,blocked_until=excluded.blocked_until")
    .bind(keyHash,windowStart,attempts,blockedUntil).run();
  return { allowed:!blockedUntil, retryAfter:blockMs/1000 };
}
