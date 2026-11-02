import 'dotenv/config';
import express from 'express';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import helmet from 'helmet';
import cors from 'cors';
import { rateLimit } from 'express-rate-limit';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { initializeSchema } from './init-schema.js';
import { createSessions } from './sessions.js';
import { installAdmob,adRewardSchema } from './admob-routes.js';
const env=process.env;
if(!env.JWT_SECRET || env.JWT_SECRET.length<32 || env.JWT_SECRET.startsWith('replace-')) throw Error('Set a random JWT_SECRET (32+ characters)');
const demo=env.ENABLE_DEMO_REWARDS==='true' && env.NODE_ENV!=='production';
const db=mysql.createPool({host:env.DB_HOST,port:Number(env.DB_PORT||3306),user:env.DB_USER,password:env.DB_PASSWORD,database:env.DB_NAME||'defaultdb',ssl:{rejectUnauthorized:true,...(env.DB_CA?{ca:env.DB_CA.split(String.fromCharCode(92)+'n').join(String.fromCharCode(10))}:{})},connectionLimit:5,supportBigNumbers:true,bigNumberStrings:true,timezone:'Z'});
const app=express(); app.set('trust proxy',1); app.use(helmet());
const origins=(env.CORS_ORIGINS||'').split(',').map(x=>x.trim());
app.use(cors({origin(origin,cb){cb(null,!origin||origins.includes(origin));}}));
const sessions=createSessions(db,{secure:env.NODE_ENV!=='development'});
// Cookie-authenticated writes must come from a configured or same-site origin.
app.use((req,res,next)=>{
 const origin=req.get('origin');
 const sameOrigin=`${req.protocol}://${req.get('host')}`;
 if(!['GET','HEAD','OPTIONS'].includes(req.method)&&origin&&origin!==sameOrigin&&!origins.includes(origin))return res.status(403).json({error:'Request origin is not allowed'});
 if(req.path.startsWith('/auth/')||['/me','/history','/rewards'].includes(req.path))res.set('Cache-Control','no-store');
 next();
});
app.use(express.json({limit:'16kb'}));
app.use(rateLimit({windowMs:60000,limit:100}));
// Serve the web client and API from the same origin.
app.use(express.static(fileURLToPath(new URL('../public/', import.meta.url))));
installAdmob(app,db,auth,{enabled:env.ENABLE_AD_REWARDS==='true'});
const authLimit=rateLimit({windowMs:15*60000,limit:20});
function fail(status,message){const e=Error(message);e.status=status;throw e;}
async function auth(req,res,next){
 const header=req.headers.authorization;
 if(header){
  try{req.uid=jwt.verify(header.replace(/^Bearer /,''),env.JWT_SECRET,{algorithms:['HS256'],issuer:'coinnest'}).sub;return next();}
  catch{return res.status(401).json({error:'Please sign in again'});}
 }
 try{req.uid=await sessions.resolve(req);if(!req.uid)return res.status(401).json({error:'Please sign in again'});next();}catch(e){next(e);}
}
const tokenFor=id=>jwt.sign({},env.JWT_SECRET,{subject:id,expiresIn:'12h',issuer:'coinnest',algorithm:'HS256'});
app.get('/health',async(req,res)=>{await db.query('SELECT 1');res.json({status:'ok',demo});});
app.post('/auth/signup',authLimit,async(req,res)=>{
 const {name,email,password}=req.body;
 if(typeof name!=='string'||name.trim().length<2||name.length>80||typeof email!=='string'||email.length>190||!/^\S+@\S+\.\S+$/.test(email)||typeof password!=='string'||password.length<10||Buffer.byteLength(password)>72) fail(400,'Use a valid name/email and password of 10–72 bytes');
 const id=randomUUID(),hash=await bcrypt.hash(password,12);
 try{await db.execute('INSERT INTO users(id,name,email,password_hash) VALUES(?,?,?,?)',[id,name.trim(),email.toLowerCase().trim(),hash]);}catch(e){if(e.code==='ER_DUP_ENTRY')fail(409,'Email already registered');throw e;}
 await sessions.issue(req,res,id);
 res.status(201).json({token:tokenFor(id)});
});
app.post('/auth/login',authLimit,async(req,res)=>{
 const {email,password}=req.body;
 if(typeof email!=='string'||typeof password!=='string')fail(400,'Email and password required');
 const [rows]=await db.execute('SELECT * FROM users WHERE email=?',[email.toLowerCase().trim()]);
 const hash=rows[0]?.password_hash||'$2b$12$.....................................................';
 const ok=await bcrypt.compare(password,hash);
 if(!rows[0]||!ok)fail(401,'Incorrect email or password');
 await sessions.issue(req,res,rows[0].id);
 res.json({token:tokenFor(rows[0].id)});
});
app.post('/auth/logout',async(req,res)=>{await sessions.revoke(req,res);res.json({ok:true});});
app.get('/me',auth,async(req,res)=>{const [u]=await db.execute('SELECT id,name,email,coins FROM users WHERE id=?',[req.uid]);if(!u[0])fail(401,'Account unavailable');res.json({...u[0],demo,adRewards:env.ENABLE_AD_REWARDS==='true'});});
app.get('/rewards',auth,async(req,res)=>{const [rows]=await db.query('SELECT * FROM rewards');res.json(rows);});
app.get('/history',auth,async(req,res)=>{const [ledger]=await db.execute('SELECT amount,kind,created_at FROM ledger WHERE user_id=? ORDER BY created_at DESC LIMIT 100',[req.uid]);const [redemptions]=await db.execute('SELECT r.*,w.title FROM redemptions r JOIN rewards w ON r.reward_id=w.id WHERE user_id=? ORDER BY created_at DESC LIMIT 100',[req.uid]);res.json({ledger,redemptions});});
app.post('/redeem',auth,async(req,res)=>{
 const {rewardId,gameId}=req.body;if(typeof rewardId!=='string'||(gameId!=null&&(typeof gameId!=='string'||gameId.length>80)))fail(400,'Invalid reward or player ID');
 const c=await db.getConnection();try{await c.beginTransaction();
 const [u]=await c.execute('SELECT coins FROM users WHERE id=? FOR UPDATE',[req.uid]);
 const [rr]=await c.execute('SELECT * FROM rewards WHERE id=?',[rewardId]);const reward=rr[0];
 if(!reward||!reward.active||reward.external)fail(400,'This reward is unavailable. External game top-ups are disabled.');
 if(!u[0]||BigInt(u[0].coins)<BigInt(reward.cost))fail(400,'Not enough coins');
 const id=randomUUID();await c.execute('UPDATE users SET coins=coins-? WHERE id=?',[reward.cost,req.uid]);
 await c.execute('INSERT INTO redemptions(id,user_id,reward_id,game_id,cost,status) VALUES(?,?,?,?,?,?)',[id,req.uid,reward.id,gameId||null,reward.cost,'completed']);
 await c.execute('INSERT INTO ledger(id,user_id,amount,kind,reference) VALUES(?,?,?,?,?)',[randomUUID(),req.uid,-reward.cost,'redeem',id]);
 await c.commit();res.status(201).json({id,status:'completed'});
 }catch(e){await c.rollback();throw e;}finally{c.release();}
});
// Development-only integration path: not proof of a real ad view. Disabled in production.
app.post('/demo/session',auth,async(req,res)=>{if(!demo)fail(403,'Demo rewards disabled');const id=randomUUID();await db.execute('INSERT INTO demo_sessions(id,user_id) VALUES(?,?)',[id,req.uid]);res.json({id});});
app.post('/demo/claim',auth,async(req,res)=>{
 if(!demo)fail(403,'Demo rewards disabled');if(typeof req.body.sessionId!=='string')fail(400,'Session required');
 const c=await db.getConnection();try{await c.beginTransaction();
 await c.execute('SELECT id FROM users WHERE id=? FOR UPDATE',[req.uid]);
 const [rows]=await c.execute('SELECT * FROM demo_sessions WHERE id=? AND user_id=? FOR UPDATE',[req.body.sessionId,req.uid]);const s=rows[0];
 if(!s||s.consumed||Date.now()-new Date(s.created_at).getTime()>600000)fail(409,'Invalid, expired or already claimed session');
 const [recent]=await c.execute("SELECT COUNT(*) n,MAX(created_at) last FROM ledger WHERE user_id=? AND kind='demo_ad' AND created_at>=UTC_DATE()",[req.uid]);
 if(Number(recent[0].n)>=20||(recent[0].last&&Date.now()-new Date(recent[0].last).getTime()<60000))fail(429,'Daily limit 20; wait 60 seconds between rewards');
 await c.execute('UPDATE demo_sessions SET consumed=TRUE WHERE id=?',[s.id]);await c.execute('UPDATE users SET coins=coins+10 WHERE id=?',[req.uid]);
 await c.execute('INSERT INTO ledger(id,user_id,amount,kind,reference) VALUES(?,?,?,?,?)',[randomUUID(),req.uid,10,'demo_ad',s.id]);await c.commit();res.json({coins:10});
 }catch(e){await c.rollback();throw e;}finally{c.release();}
});
// No client-trusted production reward endpoint. Implement verified AdMob SSV before enabling live rewards.
app.use((err,req,res,next)=>{if(!err.status)console.error('REQUEST_FAILED', req.method, req.path, 'code='+String(err.code||err.name), 'errno='+String(err.errno||''), 'sqlState='+String(err.sqlState||''));res.status(err.status||500).json({error:err.status?err.message:'Server unavailable; try again later'});});
try {
  await initializeSchema(db);
  await db.query(adRewardSchema);
  await db.execute('DELETE FROM web_sessions WHERE expires_at<=UTC_TIMESTAMP()');
  console.log('Database schema ready');
  app.listen(Number(env.PORT||5000),'0.0.0.0',()=>console.log('CoinNest API ready v0.2.0'));
} catch (error) {
  console.error('DATABASE_SETUP_FAILED', 'code='+String(error.code||error.name), 'errno='+String(error.errno||''), 'sqlState='+String(error.sqlState||''));
  await db.end();
  process.exitCode=1;
}
