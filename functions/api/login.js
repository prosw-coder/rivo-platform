import { json, sha256, passwordHash, cookie, startSession } from "../_lib/auth.js";
export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!email || !password) return json({ error: "أدخل البريد الإلكتروني وكلمة المرور." }, 400);
    const emailHash = await sha256(email);
    const user = await env.DB.prepare("SELECT id,handle,password_salt,password_hash,profile_cipher,profile_iv,profile_salt,avatar_key FROM users WHERE email_hash=?").bind(emailHash).first();
    if (!user) return json({ error: "بيانات الدخول غير صحيحة." }, 401);
    const digest = await passwordHash(password, user.password_salt);
    if (digest !== user.password_hash) return json({ error: "بيانات الدخول غير صحيحة." }, 401);
    const session = await startSession(user.id, env);
    return json({ ok: true, id: user.id, handle: user.handle, profileCipher: user.profile_cipher, profileIv: user.profile_iv, profileSalt: user.profile_salt, avatarKey: user.avatar_key }, 200, { "set-cookie": cookie(session) });
  } catch {
    return json({ error: "تعذّر تسجيل الدخول حالياً." }, 500);
  }
}
