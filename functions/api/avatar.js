import { json, currentUser } from "../_lib/auth.js";
const b64 = bytes => { const data=new Uint8Array(bytes); let out=""; for(let i=0;i<data.length;i+=32768) out+=String.fromCharCode(...data.subarray(i,i+32768)); return btoa(out); };
const fromB64 = value => Uint8Array.from(atob(String(value)), c => c.charCodeAt(0));
async function isFriend(env,a,b){if(a===b)return true;return !!(await env.DB.prepare("SELECT id FROM friend_requests WHERE status='accepted' AND ((requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?))").bind(a,b,b,a).first())}
export async function onRequestPost({request,env}){
 const user=await currentUser(request,env);if(!user)return json({error:"يلزم تسجيل الدخول."},401);
 try{
  const body=await request.json();if(!body.ciphertext||!Array.isArray(body.shares)||body.shares.length>101)return json({error:"بيانات الصورة المشفّرة غير مكتملة."},400);
  const ciphertext=fromB64(body.ciphertext);if(!ciphertext.length||ciphertext.length>5*1024*1024)return json({error:"حجم الصورة المشفّرة يجب ألا يتجاوز 5 ميغابايت."},413);\n  const contentType=String(body.contentType||"image/jpeg");if(!["image/jpeg","image/png","image/webp","image/gif","image/avif"].includes(contentType))return json({error:"صيغة الصورة غير مدعومة."},400);
  const self=await env.DB.prepare("SELECT public_key FROM user_crypto_keys WHERE user_id=?").bind(user.id).first();if(!self?.public_key)return json({error:"مفتاح التشفير غير مهيأ."},409);
  const seen=new Set();
  for(const s of body.shares){const id=String(s.userId||"");if(!id||seen.has(id)||!s.iv||!s.wrappedKey||!await isFriend(env,user.id,id))return json({error:"مشاركة مفتاح غير صالحة أو مع مستخدم ليس صديقاً."},403);seen.add(id);if(fromB64(s.iv).length!==12||fromB64(s.wrappedKey).length!==48)return json({error:"صيغة مفتاح الصورة غير صحيحة."},400)}
  if(!seen.has(user.id))return json({error:"يجب تضمين مفتاحك الشخصي."},400);
  const key=`avatars/${user.id}/${crypto.randomUUID()}.enc`;
  await env.MEDIA.put(key,ciphertext,{httpMetadata:{contentType:"application/octet-stream",cacheControl:"private, no-store"},customMetadata:{encrypted:"true",owner:user.id,contentType}});
  await env.DB.prepare("UPDATE users SET avatar_key=? WHERE id=?").bind(key,user.id).run();
  await env.DB.prepare("DELETE FROM avatar_key_shares WHERE owner_id=?").bind(user.id).run();
  for(const s of body.shares)await env.DB.prepare("INSERT INTO avatar_key_shares(owner_id,friend_id,avatar_key,wrap_iv,wrapped_key,created_at) VALUES(?,?,?,?,?,?)").bind(user.id,String(s.userId),key,String(s.iv),String(s.wrappedKey),new Date().toISOString()).run();
  return json({ok:true});
 }catch{return json({error:"تعذّر حفظ الصورة المشفّرة."},500)}
}
export async function onRequestGet({request,env}){
 const user=await currentUser(request,env);if(!user)return json({error:"يلزم تسجيل الدخول."},401);
 const ownerId=new URL(request.url).searchParams.get("userId")||user.id;
 if(!await isFriend(env,user.id,ownerId))return json({error:"الصورة متاحة لصاحب الحساب وأصدقائه المقبولين فقط."},403);
 const owner=await env.DB.prepare("SELECT avatar_key FROM users WHERE id=?").bind(ownerId).first();if(!owner?.avatar_key)return json({error:"لا توجد صورة شخصية."},404);
 const [share,pub,obj]=await Promise.all([env.DB.prepare("SELECT wrap_iv,wrapped_key FROM avatar_key_shares WHERE owner_id=? AND friend_id=? AND avatar_key=?").bind(ownerId,user.id,owner.avatar_key).first(),env.DB.prepare("SELECT public_key FROM user_crypto_keys WHERE user_id=?").bind(ownerId).first(),env.MEDIA.get(owner.avatar_key)]);
 if(!share||!pub?.public_key||!obj)return json({error:"الصورة تحتاج إلى إعادة رفع من صاحب الحساب لتفعيل المشاركة المشفّرة."},404);
 const bytes=new Uint8Array(await new Response(obj.body).arrayBuffer());
 return json({ciphertext:b64(bytes),wrapIv:share.wrap_iv,wrappedKey:share.wrapped_key,ownerPublicKey:pub.public_key,contentType:obj.customMetadata?.contentType||"image/jpeg"});
}