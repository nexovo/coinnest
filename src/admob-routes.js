import { randomUUID } from 'node:crypto';
import {createSsvVerifier,creditAdReward,ssvError} from './admob-ssv.js';
export const adRewardSchema=`CREATE TABLE IF NOT EXISTS ad_reward_sessions (
 id CHAR(36) PRIMARY KEY, user_id CHAR(36) NOT NULL,
 ad_unit VARCHAR(100) NOT NULL, transaction_id VARCHAR(80) UNIQUE,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 INDEX ads_user_created(user_id,created_at),
 FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`;
const units={rewarded:'ca-app-pub-5282003945839371/7951182099',rewarded_interstitial:'ca-app-pub-5282003945839371/7665734922'};
export function installAdmob(app,db,auth,{enabled=false}={}){
 const verify=createSsvVerifier();
 app.post('/ads/session',auth,async(req,res)=>{
  if(!enabled)throw ssvError(503,'Reward setup is not enabled yet');
  const unit=units[req.body.format];if(!unit)throw ssvError(400,'Unknown rewarded format');
  const c=await db.getConnection();try{await c.beginTransaction();
   await c.execute('SELECT id FROM users WHERE id=? FOR UPDATE',[req.uid]);
   const [rows]=await c.execute('SELECT COUNT(*) n,MAX(created_at) last FROM ad_reward_sessions WHERE user_id=? AND created_at>=UTC_DATE()',[req.uid]);
   if(Number(rows[0].n)>=20||(rows[0].last&&Date.now()-new Date(rows[0].last).getTime()<60000))throw ssvError(429,'Up to 20 attempts daily; wait 60 seconds between ads');
   const id=randomUUID();await c.execute('INSERT INTO ad_reward_sessions(id,user_id,ad_unit) VALUES(?,?,?)',[id,req.uid,unit]);await c.commit();res.json({id,userId:req.uid,coins:10});
  }catch(e){await c.rollback();throw e;}finally{c.release();}
 });
 app.get('/ads/session/:id',auth,async(req,res)=>{res.set('Cache-Control','no-store');const [r]=await db.execute('SELECT transaction_id FROM ad_reward_sessions WHERE id=? AND user_id=?',[req.params.id,req.uid]);if(!r[0])throw ssvError(404,'Session not found');res.json({credited:!!r[0].transaction_id});});
 app.get('/ads/admob/ssv',async(req,res)=>{
  if(!enabled)throw ssvError(503,'Reward verification not enabled');
  const p=await verify(req.originalUrl);
  if(p.custom_data==='test'&&p.user_id==='test'){return res.json({ok:true,test:true,coins:0});}
  const normalized=Object.values(units).find(unit=>unit===p.ad_unit||unit.split('/')[1]===p.ad_unit);
  if(!normalized||!/^[-a-zA-Z0-9_]{1,80}$/.test(p.transaction_id||'')||!/^[-a-f0-9]{36}$/.test(p.custom_data||''))throw ssvError(400,'Invalid reward parameters');
  p.ad_unit=normalized;
  const out=await creditAdReward(db,p);res.json({ok:true,...out});
 });
}
