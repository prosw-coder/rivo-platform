import { json, sha256, passwordHash, cookie, startSession, consumeRateLimit } from "../_lib/auth.js";
export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!email || !password) return json({ error: "أدخل البريد الإلكتروني وكلمة المرور." }, 400);
    const emailHash = await sha256(email);
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const limitKey = await sha256("login:"+emailHash+":"+ip);
    const limit = await consumeRateLimit(env,limitKey,8,15*60*1000,15*60*1000);
    if(!limit.allowed) return json({error:"محاولات تسجيل الدخول كثيرة. حاول بعد قليل."},429,{"retry-after":String(limit.retryAfter)});
    const user = await env.DB.prepare("SELECT id,handle,password_salt,password_hash,password_iterations,profile_cipher,profile_iv,profile_salt,avatar_key FROM users WHERE email_hash=?").bind(emailHash).first();
    if (!user) return json({ error: "بيانات الدخول غير صحيحة." }, 401);
    const iterations = Number(user.password_iterations) || 100000;
    const digest = await passwordHash(password, user.password_salt, iterations);
    if (digest !== user.password_hash) return json({ error: "بيانات الدخول غير صحيحة." }, 401);
    if (iterations < 600000) {
      const upgraded = await passwordHash(password, user.password_salt, 600000);
      await env.DB.prepare("UPDATE users SET password_hash=?,password_iterations=600000 WHERE id=?").bind(upgraded,user.id).run();
    }
    const session = await startSession(user.id, env);
    return json({ ok: true, id: user.id, handle: user.handle, profileCipher: user.profile_cipher, profileIv: user.profile_iv, profileSalt: user.profile_salt, avatarKey: user.avatar_key }, 200, { "set-cookie": cookie(session) });
  } catch {
    return json({ error: "تعذّر تسجيل الدخول حالياً." }, 500);
  }
}
