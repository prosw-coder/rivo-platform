import { json, currentUser } from "../_lib/auth.js";

export async function onRequestGet({request,env}) {
  const me=await currentUser(request,env);
  if(!me) return json({error:"يلزم تسجيل الدخول."},401);

  const id=new URL(request.url).searchParams.get("id");
  if(!id) return json({error:"حدد الفيديو."},400);

  const row=await env.DB.prepare(
    "SELECT id,sender_id,recipient_id,object_key,file_name,mime_type,file_size,status FROM videos WHERE id=? AND status='available' AND (sender_id=? OR recipient_id=?)"
  ).bind(id,me.id,me.id).first();

  if(!row) return json({error:"الفيديو غير متاح أو ليس لديك صلاحية لمشاهدته."},404);

  const friendId=row.sender_id===me.id?row.recipient_id:row.sender_id;
  const friendship=await env.DB.prepare(
    "SELECT id FROM friend_requests WHERE status='accepted' AND ((requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?))"
  ).bind(me.id,friendId,friendId,me.id).first();

  if(!friendship) return json({error:"مشاهدة الفيديو متاحة للأصدقاء فقط."},403);

  const object=await env.MEDIA.get(row.object_key,{range:request.headers});
  if(!object) return json({error:"ملف الفيديو غير موجود."},404);

  const headers=new Headers({
    "content-type":row.mime_type||"video/mp4",
    "content-disposition":"inline",
    "cache-control":"private, no-store",
    "x-content-type-options":"nosniff",
    "accept-ranges":"bytes"
  });
  if(object.size!==undefined) headers.set("content-length",String(object.size));
  if(object.range) {
    headers.set("content-range",`bytes ${object.range.offset}-${object.range.offset+object.range.length-1}/${row.file_size}`);
  }
  return new Response(object.body,{status:object.range?206:200,headers});
}
