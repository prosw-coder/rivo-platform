import { json, currentUser } from "../_lib/auth.js";
export async function onRequestPost({ request, env }) {
  const user = await currentUser(request, env);
  if (!user) return json({ error: "يلزم تسجيل الدخول." }, 401);
  const type = request.headers.get("content-type") || "application/octet-stream";
  const bytes = await request.arrayBuffer();
  if (!bytes.byteLength || bytes.byteLength > 5 * 1024 * 1024) return json({ error: "حجم الصورة المشفّرة يجب ألا يتجاوز 5 ميغابايت." }, 413);
  const key = `avatars/${user.id}/${crypto.randomUUID()}.enc`;
  await env.MEDIA.put(key, bytes, { httpMetadata: { contentType: "application/octet-stream", cacheControl: "private, no-store" }, customMetadata: { encrypted: "true", owner: user.id } });
  await env.DB.prepare("UPDATE users SET avatar_key=? WHERE id=?").bind(key, user.id).run();
  return json({ ok: true, avatarKey: key });
}
export async function onRequestGet({ request, env }) {
  const user = await currentUser(request, env);
  if (!user) return json({ error: "يلزم تسجيل الدخول." }, 401);
  if (!user.avatar_key) return json({ error: "لا توجد صورة." }, 404);
  const object = await env.MEDIA.get(user.avatar_key);
  if (!object) return json({ error: "الصورة غير موجودة." }, 404);
  return new Response(object.body, { headers: { "content-type": "application/octet-stream", "cache-control": "private, no-store", "x-content-type-options": "nosniff" } });
}
