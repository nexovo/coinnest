import { randomBytes, createHash } from 'node:crypto';
const COOKIE='cn_session';
const MAX_AGE=30*24*60*60;
function cookie(req){
 const raw=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='));
 const value=raw?raw.slice(COOKIE.length+1):'';
 return /^[a-f0-9]{64}$/.test(value)?value:null;
}
const hash=value=>createHash('sha256').update(value).digest('hex');
export function createSessions(db,{secure=true}={}){
 function set(res,value,age){res.append('Set-Cookie',`${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${secure?'; Secure':''}`);}
 return {
  async issue(req,res,userId){
   const raw=randomBytes(32).toString('hex');
   const c=await db.getConnection();
   try{
    await c.beginTransaction();
    const old=cookie(req);
    if(old)await c.execute('DELETE FROM web_sessions WHERE token_hash=?',[hash(old)]);
    await c.execute('INSERT INTO web_sessions(token_hash,user_id,expires_at) VALUES(?,?,DATE_ADD(UTC_TIMESTAMP(),INTERVAL 30 DAY))',[hash(raw),userId]);
    await c.commit();set(res,raw,MAX_AGE);
   }catch(e){await c.rollback();throw e;}finally{c.release();}
  },
  async resolve(req){
   const raw=cookie(req);if(!raw)return null;
   const [rows]=await db.execute('SELECT s.user_id FROM web_sessions s JOIN users u ON u.id=s.user_id WHERE token_hash=? AND expires_at>UTC_TIMESTAMP()',[hash(raw)]);
   return rows[0]?.user_id||null;
  },
  async revoke(req,res){
   const raw=cookie(req);
   if(raw)await db.execute('DELETE FROM web_sessions WHERE token_hash=?',[hash(raw)]);
   set(res,'',0);
  }
 };
}
