import { json, currentUser } from "../_lib/auth.js";
export async function onRequestGet({request,env}) {
 const me=await currentUser(request,env); if(!me)return json({error:"يلزم تسجيل الدخول."},401);
 const rows=await env.DB.prepare("SELECT u.id,u.handle,k.public_key FROM friend_requests f JOIN users u ON u.id=CASE WHEN f.requester_id=? THEN f.addressee_id ELSE f.requester_id END LEFT JOIN user_crypto_keys k ON k.user_id=u.id WHERE f.status='accepted' AND (f.requester_id=? OR f.addressee_id=?) ORDER BY u.handle").bind(me.id,me.id,me.id).all();
 const own=await env.DB.prepare("SELECT public_key FROM user_crypto_keys WHERE user_id=?").bind(me.id).first();
 return json({friends:rows.results||[],publicKey:own?.public_key||null});
}
export async function onRequestPost({request,env}) {
 const me=await currentUser(request,env); if(!me)return json({error:"يلزم تسجيل الدخول."},401);
 try {
  const body=await request.json();
  if(body.action==="publish") {
   const key=String(body.publicKey||"");
   const bytes=Uint8Array.from(atob(key),c=>c.charCodeAt(0));
   if(bytes.length!==65||bytes[0]!==4)return json({error:"المفتاح العام غير صالح."},400);
   await env.DB.prepare("INSERT INTO user_crypto_keys(user_id,public_key,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET public_key=excluded.public_key,updated_at=excluded.updated_at").bind(me.id,key,new Date().toISOString()).run();
   return json({ok:true});
  }
  if(body.action==="share") {
   const owner=await env.DB.prepare("SELECT avatar_key FROM users WHERE id=?").bind(me.id).first();
   if(!owner?.avatar_key||!Array.isArray(body.shares))return json({error:"لا توجد صورة مشفّرة لمشاركتها."},404);
   for(const s of body.shares) {
    const friendId=String(s.userId||"");
    const friend=await env.DB.prepare("SELECT id FROM friend_requests WHERE status='accepted' AND ((requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?))").bind(me.id,friendId,friendId,me.id).first();
    if(!friend||!s.iv||!s.wrappedKey)return json({error:"لا يمكن مشاركة مفتاح الصورة مع هذا المستخدم."},403);
    const ivBytes=Uint8Array.from(atob(String(s.iv)),c=>c.charCodeAt(0)),keyBytes=Uint8Array.from(atob(String(s.wrappedKey)),c=>c.charCodeAt(0));
    if(ivBytes.length!==12||keyBytes.length!==48)return json({error:"صيغة مفتاح الصورة غير صالحة."},400);
    await env.DB.prepare("INSERT INTO avatar_key_shares(owner_id,friend_id,avatar_key,wrap_iv,wrapped_key,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(owner_id,friend_id) DO UPDATE SET avatar_key=excluded.avatar_key,wrap_iv=excluded.wrap_iv,wrapped_key=excluded.wrapped_key,created_at=excluded.created_at").bind(me.id,friendId,owner.avatar_key,String(s.iv),String(s.wrappedKey),new Date().toISOString()).run();
   }
   return json({ok:true});
  }
  return json({error:"طلب غير معروف."},400);
 } catch { return json({error:"تعذّر تحديث مفاتيح التشفير."},500); }
}