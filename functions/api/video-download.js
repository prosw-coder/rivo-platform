import { json, currentUser } from "../_lib/auth.js";
export async function onRequestGet({request,env}) {
  const me=await currentUser(request,env);
  if(!me) return json({error:"يلزم تسجيل الدخول."},401);
  const id=new URL(request.url).searchParams.get("id");
  const row=await env.DB.prepare("SELECT * FROM videos WHERE id=? AND recipient_id=? AND status='available' AND EXISTS (SELECT 1 FROM friend_requests f WHERE f.status='accepted' AND ((f.requester_id=videos.sender_id AND f.addressee_id=videos.recipient_id) OR (f.requester_id=videos.recipient_id AND f.addressee_id=videos.sender_id)))").bind(id,me.id).first();
  if(!row) return json({error:"الفيديو غير متاح أو تم تنزيله سابقاً."},404);
  const object=await env.MEDIA.get(row.object_key);
  if(!object) return json({error:"ملف الفيديو غير موجود."},404);
  const safeName=encodeURIComponent(row.file_name||"video");
  return new Response(object.body,{headers:{"content-type":"application/octet-stream","content-length":String(row.file_size),"content-disposition":`attachment; filename*=UTF-8''${safeName}`,"cache-control":"private, no-store","x-content-type-options":"nosniff"}});
}