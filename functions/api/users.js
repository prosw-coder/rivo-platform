import { json, currentUser } from "../_lib/auth.js";
export async function onRequestGet({ request, env }) {
  const me = await currentUser(request, env);
  if (!me) return json({ error: "يلزم تسجيل الدخول." }, 401);
  const q = (new URL(request.url).searchParams.get("q") || "").trim().toLowerCase().replace(/^@/,"");
  if (q.length < 2) return json({ users: [] });
  const rows = await env.DB.prepare("SELECT u.id,u.handle FROM users u WHERE u.id<>? AND u.handle LIKE ? ESCAPE '\\' AND NOT EXISTS (SELECT 1 FROM friend_requests f WHERE ((f.requester_id=? AND f.addressee_id=u.id) OR (f.requester_id=u.id AND f.addressee_id=?)) AND f.status IN ('pending','accepted')) ORDER BY u.handle LIMIT 20")
    .bind(me.id, "%" + q.replace(/[\\%_]/g, "\\$&") + "%", me.id, me.id).all();
  return json({ users: rows.results || [] });
}