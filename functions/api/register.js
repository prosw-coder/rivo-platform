import { json, sha256, passwordHash, newToken, cookie, startSession, consumeRateLimit } from "../_lib/auth.js";
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
    const emailHash = await sha256(email);\n    const ip = request.headers.get("CF-Connecting-IP") || "unknown";\n    const limitKey = await sha256("register:"+ip);\n    const limit = await consumeRateLimit(env,limitKey,5,30*60*1000,30*60*1000);\n    if(!limit.allowed) return json({error:"تم تجاوز عدد محاولات إنشاء الحساب. حاول لاحقاً."},429,{"retry-after":String(limit.retryAfter)});
    const passwordSalt = newToken(16);
    const passwordIterations = 600000;\n    const passwordDigest = await passwordHash(password, passwordSalt, passwordIterations);
    const id = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO users (id,handle,email_hash,password_salt,password_hash,password_iterations,profile_cipher,profile_iv,profile_salt,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
      .bind(id, handle, emailHash, passwordSalt, passwordDigest, passwordIterations, profileCipher, profileIv, profileSalt, new Date().toISOString()).run();
    const session = await startSession(id, env);
    return json({ ok: true, id, handle, profileCipher, profileIv, profileSalt, avatarKey: null }, 201, { "set-cookie": cookie(session) });
  } catch (error) {
    const message = String(error?.message || "Unknown registration error");
    console.error("RIVO_REGISTER_ERROR", message);
    if (message.includes("UNIQUE")) return json({ error: "البريد الإلكتروني أو المعرّف مستخدم بالفعل." }, 409);
    if (message.includes("no such table")) return json({ error: "قاعدة بيانات الحسابات غير مهيأة بشكل صحيح." }, 500);
    if (message.includes("D1") || message.includes("database") || message.includes("SQLITE")) return json({ error: "تعذّر حفظ الحساب في قاعدة البيانات. رمز التشخيص: DB_WRITE_FAILED" }, 500);
    return json({ error: "تعذّر إنشاء الحساب. حاول مرة أخرى." }, 500);
  }
}
