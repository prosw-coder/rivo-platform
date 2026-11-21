import { json, currentUser } from "../../_lib/auth.js";
const MAX_SIZE = 5 * 1024 * 1024 * 1024;
export async function onRequestPost({ request, env }) {
  const me = await currentUser(request, env);
  if (!me) return json({ error:"يلزم تسجيل الدخول." },401);
  try {
    const body = await request.json();
    if (body.action === "create") {
      const recipientId = String(body.recipientId || "");
      const size = Number(body.fileSize);
      const mime = String(body.mimeType || "");
      const fileName = String(body.fileName || "video").replace(/[\\r\\n"]/g,"_").slice(0,180);
      if (!Number.isSafeInteger(size) || size < 1 || size > MAX_SIZE) return json({ error:"حجم الفيديو يجب ألا يتجاوز 5 جيجابايت." },413);
      if (!mime.startsWith("video/")) return json({ error:"يمكن إرسال ملفات الفيديو فقط." },400);
      const friend = await env.DB.prepare("SELECT id FROM friend_requests WHERE status='accepted' AND ((requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?))").bind(me.id,recipientId,recipientId,me.id).first();
      if (!friend) return json({ error:"يمكنك إرسال الفيديوهات إلى أصدقائك المقبولين فقط." },403);
      const id=crypto.randomUUID(), key="videos/"+me.id+"/"+id;
      const upload=await env.MEDIA.createMultipartUpload(key,{httpMetadata:{contentType:"application/octet-stream",cacheControl:"private, no-store"},customMetadata:{sender:me.id,recipient:recipientId}});
      await env.DB.prepare("INSERT INTO video_uploads (id,sender_id,recipient_id,object_key,upload_id,file_name,mime_type,file_size,created_at) VALUES (?,?,?,?,?,?,?,?,?)").bind(id,me.id,recipientId,key,upload.uploadId,fileName,mime,size,new Date().toISOString()).run();
      return json({ id, key, uploadId:upload.uploadId, partSize:8*1024*1024 });
    }
    if (body.action === "complete") {
      const id=String(body.id||"");
      const row=await env.DB.prepare("SELECT * FROM video_uploads WHERE id=? AND sender_id=?").bind(id,me.id).first();
      if (!row) return json({error:"جلسة رفع الفيديو غير موجودة."},404);
      const parts=Array.isArray(body.parts)?body.parts:[];
      if (!parts.length || parts.length>10000 || parts.some(p=>!Number.isInteger(Number(p.partNumber)) || !p.etag)) return json({error:"بيانات أجزاء الفيديو غير مكتملة."},400);
      const upload=env.MEDIA.resumeMultipartUpload(row.object_key,row.upload_id);
      const completed=await upload.complete(parts.map(p=>({partNumber:Number(p.partNumber),etag:String(p.etag)})));
      const videoId=crypto.randomUUID();
      await env.DB.prepare("INSERT INTO videos (id,sender_id,recipient_id,object_key,file_name,mime_type,file_size,created_at,status) VALUES (?,?,?,?,?,?,?,?,'available')").bind(videoId,me.id,row.recipient_id,row.object_key,row.file_name,row.mime_type,row.file_size,new Date().toISOString()).run();
      await env.DB.prepare("DELETE FROM video_uploads WHERE id=?").bind(id).run();
      return json({ok:true,videoId,etag:completed.httpEtag});
    }
    return json({error:"إجراء غير معروف."},400);
  } catch(error) { console.error("RIVO_VIDEO_UPLOAD",error); return json({error:"تعذّر إكمال رفع الفيديو. حاول مرة أخرى."},500); }
}
export async function onRequestPut({ request, env }) {
  const me=await currentUser(request,env);
  if(!me) return json({error:"يلزم تسجيل الدخول."},401);
  const url=new URL(request.url), id=url.searchParams.get("id"), uploadId=url.searchParams.get("uploadId"), partNumber=Number(url.searchParams.get("partNumber"));
  if(!id||!uploadId||!Number.isInteger(partNumber)||partNumber<1||partNumber>10000||!request.body) return json({error:"بيانات جزء الفيديو غير صحيحة."},400);
  const row=await env.DB.prepare("SELECT object_key,upload_id FROM video_uploads WHERE id=? AND sender_id=?").bind(id,me.id).first();
  if(!row||row.upload_id!==uploadId) return json({error:"جلسة الرفع غير صالحة."},403);
  const length=Number(request.headers.get("content-length")||0);
  if(length>10*1024*1024) return json({error:"حجم الجزء أكبر من الحد المسموح."},413);
  try {
    const bytes=await request.arrayBuffer();
    if(bytes.byteLength>10*1024*1024) return json({error:"حجم الجزء أكبر من الحد المسموح."},413);
    const upload=env.MEDIA.resumeMultipartUpload(row.object_key,row.upload_id);
    const part=await upload.uploadPart(partNumber,bytes);
    return json(part);
  } catch(error) { console.error("RIVO_VIDEO_PART",error); return json({error:"تعذّر رفع جزء الفيديو."},500); }
}