import { json, currentUser, sha256, consumeRateLimit } from "../_lib/auth.js";
async function adminUser(request,env){
 const me=await currentUser(request,env);if(!me)return null;
 const row=await env.DB.prepare("SELECT a.user_id,u.handle FROM admin_accounts a JOIN users u ON u.id=a.user_id WHERE a.singleton=1 AND a.user_id=?").bind(me.id).first();
 return row?{...me,isAdmin:true}:null;
}
export async function onRequestGet({request,env}){
 const me=await currentUser(request,env);if(!me)return json({error:"يلزم تسجيل الدخول."},401);
 try{
  const row=await env.DB.prepare("SELECT a.user_id,u.handle FROM admin_accounts a JOIN users u ON u.id=a.user_id WHERE a.singleton=1").first();
  const isAdmin=!!row&&row.user_id===me.id;
  if(!isAdmin)return json({ok:true,isAdmin:false,adminExists:!!row});
  const [total,visitors,series,usersSeries,revenue,paidSubs,announcements]=await Promise.all([
   env.DB.prepare("SELECT COUNT(*) AS n FROM users").first(),
   env.DB.prepare("SELECT COUNT(DISTINCT visitor_hash) AS n FROM visitor_daily WHERE visit_day>=date('now','-6 days')").first(),
   env.DB.prepare("SELECT visit_day AS day,COUNT(DISTINCT visitor_hash) AS visitors FROM visitor_daily WHERE visit_day>=date('now','-6 days') GROUP BY visit_day ORDER BY visit_day").all(),
   env.DB.prepare("SELECT date(created_at) AS day,COUNT(*) AS users FROM users WHERE date(created_at)>=date('now','-6 days') GROUP BY date(created_at) ORDER BY day").all(),
   env.DB.prepare("SELECT COALESCE(SUM(amount_minor),0) AS amount,COUNT(*) AS count FROM payment_records WHERE status='paid' AND currency='JOD'").first(),
   env.DB.prepare("SELECT COUNT(*) AS n FROM subscriptions WHERE status='active' AND expires_at>?").bind(Date.now()).first(),
   env.DB.prepare("SELECT a.id,a.message,a.created_at,u.handle FROM admin_announcements a JOIN users u ON u.id=a.admin_user_id ORDER BY a.created_at DESC LIMIT 8").all()
  ]);
  return json({ok:true,isAdmin:true,adminHandle:row.handle,stats:{users:Number(total?.n||0),visitors7d:Number(visitors?.n||0),revenueJod:Number(revenue?.amount||0)/100,paidPayments:Number(revenue?.count||0),activeSubscriptions:Number(paidSubs?.n||0)},visitorsSeries:series.results||[],usersSeries:usersSeries.results||[],announcements:announcements.results||[]});
 }catch(e){console.error("RIVO_ADMIN_DASHBOARD",String(e?.message||e));return json({error:"تعذّر تحميل لوحة الإدارة."},500)}
}
export async function onRequestPost({request,env}){
 const me=await currentUser(request,env);if(!me)return json({error:"يلزم تسجيل الدخول."},401);
 try{
  const body=await request.json(),action=String(body.action||"");
  if(action==="setup"){
   const ip=request.headers.get("CF-Connecting-IP")||"unknown";
   const setupLimit=await consumeRateLimit(env,await sha256("admin-setup:"+ip),5,60*60*1000,60*60*1000);
   if(!setupLimit.allowed)return json({error:"تم تجاوز محاولات تهيئة الإدارة. حاول بعد ساعة."},429,{"retry-after":String(setupLimit.retryAfter)});
   const secret=String(body.setupSecret||"");
   if(!env.ADMIN_SETUP_SECRET||secret.length<20||secret!==env.ADMIN_SETUP_SECRET)return json({error:"رمز التهيئة غير صحيح أو غير مضبوط في Cloudflare."},403);
   const existing=await env.DB.prepare("SELECT user_id FROM admin_accounts WHERE singleton=1").first();
   if(existing)return json({error:"تم إنشاء حساب الإدارة الرئيسي مسبقاً. لا يمكن إنشاء حساب ثانٍ."},409);
   await env.DB.prepare("INSERT OR IGNORE INTO admin_accounts(singleton,user_id,created_at) VALUES(1,?,?)").bind(me.id,new Date().toISOString()).run();
   const confirmed=await env.DB.prepare("SELECT user_id FROM admin_accounts WHERE singleton=1").first();
   if(confirmed?.user_id!==me.id)return json({error:"تم حجز حساب الإدارة من قبل حساب آخر."},409);
   return json({ok:true,isAdmin:true,message:"تم اعتماد هذا الحساب كحساب الإدارة الرئيسي."});
  }
  const admin=await adminUser(request,env);if(!admin)return json({error:"هذا الإجراء مخصص لحساب الإدارة الرئيسي."},403);
  if(action==="announce"){
   const message=String(body.message||"").trim();
   if(!message||message.length>1000)return json({error:"اكتب إعلاناً من 1 إلى 1000 حرف."},400);
   const id=crypto.randomUUID(),stamp=new Date().toISOString();
   await env.DB.prepare("INSERT INTO admin_announcements(id,admin_user_id,message,created_at) VALUES(?,?,?,?)").bind(id,me.id,message,stamp).run();
   return json({ok:true,id,created_at:stamp});
  }
  return json({error:"إجراء غير معروف."},400);
 }catch(e){console.error("RIVO_ADMIN_ACTION",String(e?.message||e));return json({error:"تعذّر تنفيذ الإجراء الإداري."},500)}
}
