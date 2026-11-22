import { json, currentUser } from "../_lib/auth.js";

export async function onRequestGet({request,env}) {
  const me=await currentUser(request,env);
  if(!me)return json({error:"يلزم تسجيل الدخول."},401);
  await env.DB.prepare("INSERT INTO privacy_settings(user_id,allow_friend_requests) VALUES(?,1) ON CONFLICT(user_id) DO NOTHING").bind(me.id).run();
  const [settings,blocked]=await Promise.all([
    env.DB.prepare("SELECT allow_friend_requests FROM privacy_settings WHERE user_id=?").bind(me.id).first(),
    env.DB.prepare("SELECT u.id,u.handle,b.created_at FROM blocked_users b JOIN users u ON u.id=b.blocked_id WHERE b.blocker_id=? ORDER BY b.created_at DESC").bind(me.id).all()
  ]);
  return json({allowFriendRequests:!!settings?.allow_friend_requests,blocked:blocked.results||[]});
}
export async function onRequestPut({request,env}) {
  const me=await currentUser(request,env);
  if(!me)return json({error:"يلزم تسجيل الدخول."},401);
  try {
    const body=await request.json();
    if(typeof body.allowFriendRequests!=="boolean")return json({error:"إعداد الخصوصية غير صالح."},400);
    await env.DB.prepare("INSERT INTO privacy_settings(user_id,allow_friend_requests) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET allow_friend_requests=excluded.allow_friend_requests").bind(me.id,body.allowFriendRequests?1:0).run();
    return json({ok:true,allowFriendRequests:body.allowFriendRequests});
  } catch { return json({error:"تعذّر حفظ إعدادات الخصوصية."},500); }
}
export async function onRequestPost({request,env}) {
  const me=await currentUser(request,env);
  if(!me)return json({error:"يلزم تسجيل الدخول."},401);
  try {
    const body=await request.json(),action=String(body.action||"");
    let targetId=String(body.userId||"").trim();
    if(!targetId&&body.handle) {
      const handle=String(body.handle).trim().replace(/^@/,"").toLowerCase();
      const target=await env.DB.prepare("SELECT id FROM users WHERE handle=?").bind(handle).first();
      targetId=target?.id||"";
    }
    if(!targetId||targetId===me.id)return json({error:"حدد مستخدماً صالحاً."},400);
    const target=await env.DB.prepare("SELECT id FROM users WHERE id=?").bind(targetId).first();
    if(!target)return json({error:"لم نعثر على هذا المستخدم."},404);
    if(action==="block") {
      await env.DB.prepare("INSERT INTO blocked_users(blocker_id,blocked_id,created_at) VALUES(?,?,?) ON CONFLICT(blocker_id,blocked_id) DO NOTHING").bind(me.id,targetId,new Date().toISOString()).run();
      await env.DB.prepare("DELETE FROM friend_requests WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)").bind(me.id,targetId,targetId,me.id).run();
      await env.DB.prepare("DELETE FROM avatar_key_shares WHERE (owner_id=? AND friend_id=?) OR (owner_id=? AND friend_id=?)").bind(me.id,targetId,targetId,me.id).run();
      await env.DB.prepare("DELETE FROM conversation_hides WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)").bind(me.id,targetId,targetId,me.id).run();
      return json({ok:true,action:"blocked"});
    }
    if(action==="unblock") {
      await env.DB.prepare("DELETE FROM blocked_users WHERE blocker_id=? AND blocked_id=?").bind(me.id,targetId).run();
      return json({ok:true,action:"unblocked"});
    }
    return json({error:"إجراء غير معروف."},400);
  } catch(error) {
    console.error("RIVO_PRIVACY_ERROR",String(error?.message||error));
    return json({error:"تعذّر تحديث إعدادات الحظر."},500);
  }
}