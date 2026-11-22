import { json, sha256 } from "../../_lib/auth.js";
export async function onRequestPost({request,env}){
 try{
  const body=await request.json(),visitor=String(body.visitor||"");
  if(!/^[a-zA-Z0-9_-]{20,100}$/.test(visitor))return json({error:"معرّف زيارة غير صالح."},400);
  const day=new Date().toISOString().slice(0,10),hash=await sha256(visitor),stamp=new Date().toISOString();
  await env.DB.prepare("INSERT OR IGNORE INTO visitor_daily(visitor_hash,visit_day,first_seen_at) VALUES(?,?,?)").bind(hash,day,stamp).run();
  return json({ok:true});
 }catch(e){console.error("RIVO_ANALYTICS",String(e?.message||e));return json({error:"تعذّر تسجيل الزيارة."},500)}
}
