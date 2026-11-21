import { json, currentUser } from "../_lib/auth.js";
export async function onRequestPost({request,env}) {
  const me=await currentUser(request,env);
  if(!me)return json({error:"يلزم تسجيل الدخول."},401);
  try {
    const body=await request.json();
    const friendId=String(body.friendId||"");
    if(!friendId||friendId===me.id)return json({error:"حدد محادثة صحيحة."},400);
    const friend=await env.DB.prepare("SELECT id FROM friend_requests WHERE status='accepted' AND ((requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?))").bind(me.id,friendId,friendId,me.id).first();
    if(!friend)return json({error:"يمكن حذف محادثات الأصدقاء فقط."},403);
    await env.DB.prepare("INSERT INTO conversation_hides(user_id,friend_id,hidden_at) VALUES(?,?,?) ON CONFLICT(user_id,friend_id) DO UPDATE SET hidden_at=excluded.hidden_at").bind(me.id,friendId,new Date().toISOString()).run();
    return json({ok:true,scope:"you"});
  } catch {
    return json({error:"تعذّر حذف المحادثة حالياً."},500);
  }
}
