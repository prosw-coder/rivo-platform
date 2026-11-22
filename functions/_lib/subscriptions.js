export async function getSubscriptionAccess(env,userId,now=Date.now()){
  const own=await env.DB.prepare("SELECT plan,expires_at FROM subscriptions WHERE user_id=? AND status='active' AND expires_at>?").bind(userId,now).first();
  if(own)return {plan:own.plan,source:"subscription",expiresAt:Number(own.expires_at),maxWidth:1920,maxHeight:1080};
  const gift=await env.DB.prepare("SELECT s.expires_at,u.handle FROM team_memberships m JOIN subscriptions s ON s.user_id=m.owner_id JOIN users u ON u.id=m.owner_id WHERE m.member_id=? AND m.status='active' AND m.expires_at>? AND s.plan='team' AND s.status='active' AND s.expires_at>? ORDER BY m.created_at DESC LIMIT 1").bind(userId,now,now).first();
  if(gift)return {plan:"plus",source:"team_gift",expiresAt:Math.min(Number(gift.expires_at),Number(gift.expires_at)),giftedBy:gift.handle,maxWidth:1920,maxHeight:1080};
  return {plan:"free",source:"free",expiresAt:null,maxWidth:1280,maxHeight:720};
}
