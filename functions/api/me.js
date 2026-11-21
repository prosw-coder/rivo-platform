import { json, currentUser } from "../_lib/auth.js";
export async function onRequestGet({ request, env }) {
  const user = await currentUser(request, env);
  if (!user) return json({ authenticated: false }, 401);
  return json({ authenticated: true, id: user.id, handle: user.handle, profileCipher: user.profile_cipher, profileIv: user.profile_iv, profileSalt: user.profile_salt, avatarKey: user.avatar_key });
}
export async function onRequestPut({ request, env }) {
  const user = await currentUser(request, env);
  if (!user) return json({ error: "يلزم تسجيل الدخول." }, 401);
  try {
    const body = await request.json();
    if (!body.profileCipher || !body.profileIv || !body.profileSalt) return json({ error: "الملف المشفّر غير مكتمل." }, 400);
    await env.DB.prepare("UPDATE users SET profile_cipher=?,profile_iv=?,profile_salt=? WHERE id=?")
      .bind(String(body.profileCipher), String(body.profileIv), String(body.profileSalt), user.id).run();
    return json({ ok: true });
  } catch {
    return json({ error: "تعذّر حفظ الملف الشخصي." }, 500);
  }
}
