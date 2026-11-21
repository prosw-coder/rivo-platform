import { json, currentUser } from "../_lib/auth.js";
export async function onRequestGet({request,env}) {
  const me=await currentUser(request,env);
  if(!me) return json({error:"يلزم تسجيل الدخول."},401);
  const cutoff=new Date(Date.now()-7*24*60*60*1000).toISOString();\n  await env.DB.prepare("DELETE FROM video_uploads WHERE created_at < ?").bind(cutoff).run();\n  const friendId=new URL(request.url).searchParams.get("friendId");
  if(!friendId) return json({error:"حدد الصديق."},400);
  const friend=await env.DB.prepare("SELECT id FROM friend_requests WHERE status='accepted' AND ((requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?))").bind(me.id,friendId,friendId,me.id).first();
  if(!friend) return json({error:"هذا المستخدم ليس ضمن أصدقائك."},403);
  const rows=await env.DB.prepare("SELECT v.id,v.sender_id,v.recipient_id,v.file_name,v.mime_type,v.file_size,v.created_at,v.status,u.handle AS sender_handle FROM videos v JOIN users u ON u.id=v.sender_id WHERE ((v.sender_id=? AND v.recipient_id=?) OR (v.sender_id=? AND v.recipient_id=?)) AND v.status='available' ORDER BY v.created_at ASC").bind(me.id,friendId,friendId,me.id).all();
  return json({videos:rows.results||[]});
}