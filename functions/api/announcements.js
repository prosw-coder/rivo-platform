import { json, currentUser } from "../_lib/auth.js";
export async function onRequestGet({request,env}){
 const me=await currentUser(request,env);if(!me)return json({announcements:[]});
 try{
  const rows=await env.DB.prepare("SELECT a.id,a.message,a.created_at,u.handle FROM admin_announcements a JOIN users u ON u.id=a.admin_user_id ORDER BY a.created_at DESC LIMIT 5").all();
  return json({announcements:rows.results||[]});
 }catch(e){console.error("RIVO_ANNOUNCEMENTS",String(e?.message||e));return json({announcements:[]})}
}
