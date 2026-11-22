import { json, currentUser, sha256, consumeRateLimit } from "../_lib/auth.js";
export async function onRequestGet({ request, env }) {
  const me = await currentUser(request, env);
  if (!me) return json({ error: "يلزم تسجيل الدخول." }, 401);
  const limitKey=await sha256("user-search:"+me.id);
  const limit=await consumeRateLimit(env,limitKey,120,60*1000,60*1000);
  if(!limit.allowed)return json({error:"تبحث بسرعة كبيرة. انتظر قليلاً."},429,{"retry-after":String(limit.retryAfter)});
  const q = (new URL(request.url).searchParams.get("q") || "").trim().toLowerCase().replace(/^@/,"");
  if (q.length < 2) return json({ users: [] });
  const rows = await env.DB.prepare("SELECT u.id,u.handle FROM users u WHERE u.id<>? AND u.handle LIKE ? ESCAPE '\\' AND NOT EXISTS (SELECT 1 FROM friend_requests f WHERE ((f.requester_id=? AND f.addressee_id=u.id) OR (f.requester_id=u.id AND f.addressee_id=?)) AND f.status IN ('pending','accepted')) AND NOT EXISTS (SELECT 1 FROM blocked_users b WHERE (b.blocker_id=? AND b.blocked_id=u.id) OR (b.blocker_id=u.id AND b.blocked_id=?)) ORDER BY u.handle LIMIT 20")
    .bind(me.id, "%" + q.replace(/[\\%_]/g, "\\.bind(me.id, "%" + q.replace(/[\\%_]/g, "\\$&") + "%", me.id, me.id).all();") + "%", me.id, me.id, me.id, me.id).all();
  return json({ users: rows.results || [] });
}