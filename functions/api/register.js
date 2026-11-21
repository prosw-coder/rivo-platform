import { json, sha256, passwordHash, newToken, cookie, startSession } from "../_lib/auth.js";
export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json();
    const email = String(body.email || "").trim().toLowerCase();
    const handle = String(body.handle || "").trim().toLowerCase();
    const password = String(body.password || "");
    const profileCipher = String(body.profileCipher || "");
    const profileIv = String(body.profileIv || "");
    const profileSalt = String(body.profileSalt || "");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "أدخل بريداً إلكترونياً صحيحاً." }, 400);
    if (!/^[a-z0-9_]{4,24}$/.test(handle)) return json({ error: "المعرّف يجب أن يكون 4 إلى 24 حرفاً أو رقماً أو _." }, 400);
    if (password.length < 10) return json({ error: "كلمة المرور يجب أن تكون 10 أحرف على الأقل." }, 400);
    if (!profileCipher || !profileIv || !profileSalt) return json({ error: "بيانات الملف المشفّرة غير مكتملة." }, 400);
    const emailHash = await sha256(email);
    const passwordSalt = newToken(16);
    const passwordDigest = await passwordHash(password, passwordSalt);
    const id = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO users (id,handle,email_hash,password_salt,password_hash,profile_cipher,profile_iv,profile_salt,created_at) VALUES (?,?,?,?,?,?,?,?,?)")
      .bind(id, handle, emailHash, passwordSalt, passwordDigest, profileCipher, profileIv, profileSalt, new Date().toISOString()).run();
    const session = await startSession(id, env);
    return json({ ok: true, id, handle, profileCipher, profileIv, profileSalt, avatarKey: null }, 201, { "set-cookie": cookie(session) });
  } catch (error) {
    const message = String(error?.message || "Unknown registration error");
    console.error("RIVO_REGISTER_ERROR", message);
    if (message.includes("UNIQUE")) return json({ error: "البريد الإلكتروني أو المعرّف مستخدم بالفعل." }, 409);
    if (message.includes("no such table")) return json({ error: "قاعدة بيانات الحسابات غير مهيأة بشكل صحيح." }, 500);
    if (message.includes("D1") || message.includes("database") || message.includes("SQLITE")) return json({ error: "تعذّر حفظ الحساب في قاعدة البيانات. رمز التشخيص: DB_WRITE_FAILED" }, 500);
    return json({ error: "تعذّر إنشاء الحساب. رمز التشخيص: " + message.slice(0, 120) }, 500);
  }
}
