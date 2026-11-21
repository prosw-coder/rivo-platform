import { json, currentUser } from "../_lib/auth.js";
export async function onRequestPost({request,env}) {
  const me=await currentUser(request,env);
  if(!me) return json({error:"يلزم تسجيل الدخول."},401);
  try {
    const {id}=await request.json();
    const row=await env.DB.prepare("SELECT object_key FROM videos WHERE id=? AND recipient_id=? AND status='available'").bind(String(id||""),me.id).first();
    if(!row) return json({error:"الفيديو غير متاح أو تم تأكيد تنزيله."},404);
    await env.MEDIA.delete(row.object_key);
    await env.DB.prepare("UPDATE videos SET status='downloaded',downloaded_at=? WHERE id=? AND recipient_id=? AND status='available'").bind(new Date().toISOString(),String(id),me.id).run();
    return json({ok:true,deleted:true});
  } catch { return json({error:"اكتمل التنزيل لكن تعذّر تأكيد الحذف."},500); }
}