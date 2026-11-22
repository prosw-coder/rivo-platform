import { json, currentUser, sha256, consumeRateLimit } from "../_lib/auth.js";
export async function onRequestGet({ request, env }) {
  const me = await currentUser(request, env);
  if (!me) return json({ error: "يلزم تسجيل الدخول." }, 401);
  const [friends, incoming, outgoing] = await Promise.all([
    env.DB.prepare("SELECT u.id,u.handle,f.created_at,(SELECT COUNT(*) FROM videos v WHERE v.sender_id=u.id AND v.recipient_id=? AND v.status='available' AND v.recipient_read_at IS NULL) AS unread_count,EXISTS(SELECT 1 FROM conversation_hides h WHERE h.user_id=? AND h.friend_id=u.id) AS hidden_by_me FROM friend_requests f JOIN users u ON u.id=CASE WHEN f.requester_id=? THEN f.addressee_id ELSE f.requester_id END WHERE f.status='accepted' AND (f.requester_id=? OR f.addressee_id=?) AND NOT EXISTS (SELECT 1 FROM blocked_users b WHERE (b.blocker_id=? AND b.blocked_id=u.id) OR (b.blocker_id=u.id AND b.blocked_id=?)) ORDER BY u.handle").bind(me.id,me.id,me.id,me.id,me.id,me.id,me.id).all(),
    env.DB.prepare("SELECT f.id,u.id AS user_id,u.handle,f.created_at FROM friend_requests f JOIN users u ON u.id=f.requester_id WHERE f.addressee_id=? AND f.status='pending' AND NOT EXISTS (SELECT 1 FROM blocked_users b WHERE (b.blocker_id=f.requester_id AND b.blocked_id=f.addressee_id) OR (b.blocker_id=f.addressee_id AND b.blocked_id=f.requester_id)) AND COALESCE((SELECT allow_friend_requests FROM privacy_settings WHERE user_id=f.addressee_id),1)=1 ORDER BY f.created_at DESC").bind(me.id).all(),
    env.DB.prepare("SELECT f.id,u.id AS user_id,u.handle,f.created_at FROM friend_requests f JOIN users u ON u.id=f.addressee_id WHERE f.requester_id=? AND f.status='pending' AND NOT EXISTS (SELECT 1 FROM blocked_users b WHERE (b.blocker_id=f.requester_id AND b.blocked_id=f.addressee_id) OR (b.blocker_id=f.addressee_id AND b.blocked_id=f.requester_id)) ORDER BY f.created_at DESC").bind(me.id).all()
  ]);
  return json({ friends: friends.results || [], incoming: incoming.results || [], outgoing: outgoing.results || [] });
}
export async function onRequestPost({ request, env }) {
  const me = await currentUser(request, env);
  if (!me) return json({ error: "يلزم تسجيل الدخول." }, 401);
  try {
    const body = await request.json();
    const action = String(body.action || "");
    if (action === "request") {
      const requestLimit=await consumeRateLimit(env,await sha256("friend-request:"+me.id),30,60*60*1000,60*60*1000);
      if(!requestLimit.allowed)return json({error:"وصلت للحد المؤقت لطلبات الصداقة. حاول لاحقاً."},429,{"retry-after":String(requestLimit.retryAfter)});
      const target = String(body.userId || "");
      if (!target || target === me.id) return json({ error: "اختر مستخدماً صالحاً." }, 400);
      const targetUser=await env.DB.prepare("SELECT id FROM users WHERE id=?").bind(target).first();
      if(!targetUser)return json({error:"لم نعثر على هذا المستخدم."},404);
      const blocked=await env.DB.prepare("SELECT 1 FROM blocked_users WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)").bind(me.id,target,target,me.id).first();
      if(blocked)return json({error:"لا يمكن إرسال طلب لهذا المستخدم."},403);
      const privacy=await env.DB.prepare("SELECT allow_friend_requests FROM privacy_settings WHERE user_id=?").bind(target).first();
      if(privacy && Number(privacy.allow_friend_requests)===0)return json({error:"هذا المستخدم لا يستقبل طلبات صداقة حالياً."},403);
      const exists = await env.DB.prepare("SELECT id,status FROM friend_requests WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)").bind(me.id,target,target,me.id).first();
      if (exists?.status === "accepted") return json({ error: "هذا المستخدم ضمن أصدقائك بالفعل." }, 409);
      if (exists?.status === "pending" && exists.id) {
        const reverse = await env.DB.prepare("SELECT id FROM friend_requests WHERE requester_id=? AND addressee_id=? AND status='pending'").bind(target,me.id).first();
        if (reverse) {
          await env.DB.prepare("UPDATE friend_requests SET status='accepted',updated_at=? WHERE id=?").bind(new Date().toISOString(),reverse.id).run();
          return json({ ok:true, accepted:true });
        }
        return json({ error: "طلب الصداقة موجود بالفعل." }, 409);
      }
      await env.DB.prepare("INSERT INTO friend_requests (id,requester_id,addressee_id,status,created_at,updated_at) VALUES (?,?,?,'pending',?,?) ON CONFLICT(requester_id,addressee_id) DO UPDATE SET status='pending',updated_at=excluded.updated_at")
        .bind(crypto.randomUUID(),me.id,target,new Date().toISOString(),new Date().toISOString()).run();
      return json({ ok:true });
    }
    if (action === "accept" || action === "reject") {
      const requestId = String(body.requestId || "");
      const row = await env.DB.prepare("SELECT id FROM friend_requests WHERE id=? AND addressee_id=? AND status='pending'").bind(requestId,me.id).first();
      if (!row) return json({ error:"طلب الصداقة غير موجود." },404);
      await env.DB.prepare("UPDATE friend_requests SET status=?,updated_at=? WHERE id=?").bind(action === "accept" ? "accepted" : "rejected",new Date().toISOString(),requestId).run();
      return json({ ok:true });
    }
    return json({ error:"طلب غير معروف." },400);
  } catch { return json({ error:"تعذّر تحديث قائمة الأصدقاء." },500); }
}