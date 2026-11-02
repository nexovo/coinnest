import { createPublicKey, verify } from 'node:crypto';
export function ssvError(status,message){return Object.assign(new Error(message),{status});}
export function createSsvVerifier({fetchKeys=async()=>{
 const r=await fetch('https://www.gstatic.com/admob/reward/verifier-keys.json',{signal:AbortSignal.timeout(8000)});
 if(!r.ok)throw ssvError(503,'Verification keys unavailable');return r.json();
},now=()=>Date.now()}={}){
 let keys=new Map(),expires=0,pending=null;
 async function update(){if(!pending)pending=(async()=>{const data=await fetchKeys();const next=new Map();for(const k of data.keys||[])next.set(String(k.keyId),createPublicKey(k.pem));if(!next.size)throw ssvError(503,'Verification keys unavailable');keys=next;expires=now()+3600000;})().finally(()=>{pending=null;});await pending;}
 return async function verifyCallback(originalUrl){
  const raw=originalUrl.slice(originalUrl.indexOf('?')+1);
  const marker=raw.indexOf('&signature=');if(marker<1)throw ssvError(400,'Missing signature');
  const signed=raw.slice(0,marker),tail=raw.slice(marker+1);
  if(!/^signature=[^&]+&key_id=\d+$/.test(tail))throw ssvError(400,'Invalid signature fields');
  const params=new URLSearchParams(raw);const seen=new Set();for(const [k] of params){if(seen.has(k))throw ssvError(400,'Duplicate callback parameter');seen.add(k);}
  if(now()>=expires)await update();
  const id=params.get('key_id');if(!keys.has(id))await update();const key=keys.get(id);
  if(!key)throw ssvError(400,'Unknown signing key');
  const sig=params.get('signature');if(!/^[A-Za-z0-9_-]+={0,2}$/.test(sig))throw ssvError(400,'Invalid signature');
  if(!verify('sha256',Buffer.from(signed,'utf8'),key,Buffer.from(sig,'base64url')))throw ssvError(403,'Invalid signature');
  const timestamp=Number(params.get('timestamp'));
  if(!Number.isSafeInteger(timestamp)||timestamp>now()+300000||timestamp<now()-86400000)throw ssvError(400,'Callback timestamp outside allowed window');
  return Object.fromEntries(params);
 };
}
export async function creditAdReward(db,p){
 const c=await db.getConnection();try{await c.beginTransaction();
 const [rows]=await c.execute('SELECT * FROM ad_reward_sessions WHERE id=? FOR UPDATE',[p.custom_data]);const s=rows[0];
 if(!s||s.user_id!==p.user_id||s.ad_unit!==p.ad_unit)throw ssvError(400,'Reward session mismatch');
 if(s.transaction_id===p.transaction_id){await c.commit();return {duplicate:true};}
 if(s.transaction_id)throw ssvError(409,'Reward session already used');
 const ts=Number(p.timestamp),created=new Date(s.created_at).getTime();
 if(ts<created-300000||ts>created+3600000)throw ssvError(400,'Ad event outside session window');
 if(Number(p.reward_amount)!==10||p.reward_item!=='coins')throw ssvError(400,'Ad unit reward must be 10 coins');
 await c.execute('SELECT id FROM users WHERE id=? FOR UPDATE',[s.user_id]);
 await c.execute('UPDATE users SET coins=coins+10 WHERE id=?',[s.user_id]);
 await c.execute('INSERT INTO ledger(id,user_id,amount,kind,reference) VALUES(UUID(),?,10,?,?)',[s.user_id,'admob_reward','admob:'+p.transaction_id]);
 await c.execute('UPDATE ad_reward_sessions SET transaction_id=? WHERE id=?',[p.transaction_id,s.id]);
 await c.commit();return {coins:10};
 }catch(e){await c.rollback();throw e;}finally{c.release();}
}
