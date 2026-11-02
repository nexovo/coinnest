import { readFile } from 'node:fs/promises';
export async function initializeSchema(db) {
  const sql = await readFile(new URL('../schema.sql', import.meta.url), 'utf8');
  // Trusted bundled SQL only. Execute statements individually; no multiStatements flag.
  for (const statement of sql.split(';').map(s => s.trim()).filter(Boolean)) {
    await db.query(statement);
  }
  // Existing incompatible tables must fail explicitly rather than silently appearing ready.
  for (const query of [
    'SELECT id,name,email,password_hash,coins FROM users LIMIT 0',
    'SELECT id,user_id,amount,kind,reference,created_at FROM ledger LIMIT 0',
    'SELECT id,title,cost,external,active FROM rewards LIMIT 0',
    'SELECT id,user_id,reward_id,game_id,cost,status,created_at FROM redemptions LIMIT 0',
    'SELECT id,user_id,consumed,created_at FROM demo_sessions LIMIT 0',
    'SELECT token_hash,user_id,expires_at FROM web_sessions LIMIT 0'
  ]) await db.query(query);
}
