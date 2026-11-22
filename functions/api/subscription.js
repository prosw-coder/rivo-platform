import { json, currentUser } from "../_lib/auth.js";
import { getSubscriptionAccess } from "../_lib/subscriptions.js";

const now=()=>Date.now();
export async function onRequestGet({request,env}){
  const me=await currentUser(request,env);
  if(!me)return json({error:"يلزم تسجيل الدخول."},401);
  try{
    const time=now(),access=await getSubscriptionAccess(env,me.id,time);
    const own=await env.DB.prepare("SELECT plan,status,started_at,expires_at FROM subscriptions WHERE user_id=?").bind(me.id).first();
    const [members,incoming,membership]=await Promise.all([
      env.DB.prepare("SELECT m.id,m.member_id,m.status,m.expires_at,u.handle FROM team_memberships m JOIN users u ON u.id=m.member_id WHERE m.owner_id=? AND m.status IN ('pending','active') AND m.expires_at>? ORDER BY m.created_at").bind(me.id,time).all(),
      env.DB.prepare("SELECT m.id,m.owner_id,m.expires_at,u.handle FROM team_memberships m JOIN users u ON u.id=m.owner_id JOIN subscriptions s ON s.user_id=m.owner_id WHERE m.member_id=? AND m.status='pending' AND m.expires_at>? AND s.plan='team' AND s.status='active' AND s.expires_at>? ORDER BY m.created_at DESC").bind(me.id,time,time).all(),
      env.DB.prepare("SELECT m.id,m.owner_id,m.expires_at,u.handle FROM team_memberships m JOIN users u ON u.id=m.owner_id WHERE m.member_id=? AND m.status='active' AND m.expires_at>? ORDER BY m.created_at DESC LIMIT 1").bind(me.id,time).first()
    ]);
    return json({ok:true,access,subscription:own?{...own,expires_at:Number(own.expires_at)}:{plan:"free",status:"free"},team:{members:members.results||[],membership:membership||null},incoming:incoming.results||[]});
  }catch(error){console.error("RIVO_SUBSCRIPTION_READ",String(error?.message||error));return json({error:"تعذّر تحميل بيانات الاشتراك."},500)}
}
export async function onRequestPost({request,env}){
  const me=await currentUser(request,env);
  if(!me)return json({error:"يلزم تسجيل الدخول."},401);
  try{
    const body=await request.json(),action=String(body.action||""),time=now(),stamp=new Date(time).toISOString();
    if(action==="invite"){
      const access=await getSubscriptionAccess(env,me.id,time);
      const ownerSub=await env.DB.prepare("SELECT expires_at FROM subscriptions WHERE user_id=? AND plan='team' AND status='active' AND expires_at>?").bind(me.id,time).first();
      if(access.plan!=="team"||!ownerSub)return json({error:"إضافة أعضاء الفريق متاحة لصاحب اشتراك TEAM النشط فقط."},403);
      const targetId=String(body.userId||"").trim();
      if(!targetId||targetId.length>64||targetId===me.id)return json({error:"أدخل RIVO ID صحيحاً."},400);
      const target=await env.DB.prepare("SELECT id,handle FROM users WHERE id=?").bind(targetId).first();
      if(!target)return json({error:"لم نعثر على حساب بهذا المعرّف."},404);
      await env.DB.prepare("UPDATE team_memberships SET status='expired',updated_at=? WHERE status IN ('pending','active') AND expires_at<=?").bind(stamp,time).run();
      const targetOwn=await env.DB.prepare("SELECT 1 FROM subscriptions WHERE user_id=? AND plan='team' AND status='active' AND expires_at>?").bind(targetId,time).first();
      if(targetOwn)return json({error:"هذا المستخدم لديه اشتراك TEAM نشط بالفعل."},409);
      const other=await env.DB.prepare("SELECT id FROM team_memberships WHERE member_id=? AND status IN ('pending','active') AND expires_at>? AND owner_id<>?").bind(targetId,time,me.id).first();
      if(other)return json({error:"هذا المستخدم لديه دعوة أو عضوية فريق أخرى."},409);
      const count=await env.DB.prepare("SELECT COUNT(*) AS n FROM team_memberships WHERE owner_id=? AND status IN ('pending','active') AND expires_at>?").bind(me.id,time).first();
      if(Number(count?.n||0)>=3)return json({error:"وصلت إلى الحد الأقصى: 3 أعضاء إضافيين."},409);
      const existing=await env.DB.prepare("SELECT id,status FROM team_memberships WHERE owner_id=? AND member_id=?").bind(me.id,targetId).first();
      if(existing&&["pending","active"].includes(existing.status))return json({error:"تمت دعوة هذا المستخدم أو إضافته مسبقاً."},409);
      if(existing)await env.DB.prepare("UPDATE team_memberships SET status='pending',expires_at=?,updated_at=? WHERE id=?").bind(Number(ownerSub.expires_at),stamp,existing.id).run();
      else await env.DB.prepare("INSERT INTO team_memberships(id,owner_id,member_id,status,expires_at,created_at,updated_at) VALUES(?,?,?,'pending',?,?,?)").bind(crypto.randomUUID(),me.id,targetId,Number(ownerSub.expires_at),stamp,stamp).run();
      return json({ok:true,message:"تم إرسال دعوة TEAM إلى @"+target.handle});
    }
    if(action==="accept"||action==="decline"){
      const inviteId=String(body.inviteId||"");
      const invite=await env.DB.prepare("SELECT m.id,m.owner_id,m.expires_at,s.expires_at AS owner_expires FROM team_memberships m JOIN subscriptions s ON s.user_id=m.owner_id WHERE m.id=? AND m.member_id=? AND m.status='pending' AND s.plan='team' AND s.status='active' AND s.expires_at>? AND m.expires_at>?").bind(inviteId,me.id,time,time).first();
      if(!invite)return json({error:"الدعوة غير صالحة أو انتهت صلاحيتها."},404);
      if(action==="decline"){await env.DB.prepare("UPDATE team_memberships SET status='revoked',updated_at=? WHERE id=?").bind(stamp,inviteId).run();return json({ok:true})}
      const ownTeam=await env.DB.prepare("SELECT 1 FROM subscriptions WHERE user_id=? AND plan='team' AND status='active' AND expires_at>?").bind(me.id,time).first();
      if(ownTeam)return json({error:"لا يمكنك قبول هدية TEAM وأنت تملك اشتراك TEAM نشطاً."},409);
      await env.DB.prepare("UPDATE team_memberships SET status='expired',updated_at=? WHERE member_id=? AND status IN ('pending','active') AND expires_at<=?").bind(stamp,me.id,time).run();
      const conflict=await env.DB.prepare("SELECT id FROM team_memberships WHERE member_id=? AND status IN ('pending','active') AND expires_at>? AND id<>?").bind(me.id,time,inviteId).first();
      if(conflict)return json({error:"لديك عضوية أو دعوة فريق أخرى نشطة."},409);
      await env.DB.prepare("UPDATE team_memberships SET status='active',expires_at=?,updated_at=? WHERE id=? AND member_id=?").bind(Math.min(Number(invite.expires_at),Number(invite.owner_expires)),stamp,inviteId,me.id).run();
      return json({ok:true,message:"تم تفعيل مزايا PLUS كهدية من TEAM."});
    }
    if(action==="remove"){
      const memberId=String(body.userId||"");
      const result=await env.DB.prepare("UPDATE team_memberships SET status='revoked',updated_at=? WHERE owner_id=? AND member_id=? AND status IN ('pending','active')").bind(stamp,me.id,memberId).run();
      if(!result.meta?.changes)return json({error:"لم يتم العثور على العضو."},404);
      return json({ok:true});
    }
    return json({error:"إجراء غير معروف."},400);
  }catch(error){
    console.error("RIVO_SUBSCRIPTION_ACTION",String(error?.message||error));
    if(String(error?.message||"").includes("UNIQUE"))return json({error:"هذا المستخدم لديه دعوة أو عضوية فريق أخرى."},409);
    return json({error:"تعذّر تنفيذ إجراء الاشتراك."},500);
  }
}
