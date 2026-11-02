// Embedded schema avoids depending on an outdated separately uploaded schema.sql.
// CREATE IF NOT EXISTS / INSERT IGNORE preserve existing accounts and coin balances.
const SCHEMA = "CREATE TABLE IF NOT EXISTS users (\n id CHAR(36) PRIMARY KEY, name VARCHAR(80) NOT NULL, email VARCHAR(190) UNIQUE NOT NULL,\n password_hash VARCHAR(100) NOT NULL, coins BIGINT UNSIGNED NOT NULL DEFAULT 0,\n created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n);\nCREATE TABLE IF NOT EXISTS ledger (\n id CHAR(36) PRIMARY KEY, user_id CHAR(36) NOT NULL, amount BIGINT NOT NULL,\n kind VARCHAR(40) NOT NULL, reference VARCHAR(100) UNIQUE NOT NULL,\n created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n FOREIGN KEY (user_id) REFERENCES users(id)\n);\nCREATE TABLE IF NOT EXISTS rewards (\n id VARCHAR(40) PRIMARY KEY, title VARCHAR(100) NOT NULL, cost INT UNSIGNED NOT NULL,\n external BOOLEAN NOT NULL DEFAULT FALSE, active BOOLEAN NOT NULL DEFAULT TRUE\n);\nINSERT IGNORE INTO rewards VALUES ('theme-violet','Violet profile theme',1000,FALSE,TRUE),('pubg-uc','PUBG UC \u2014 not available',20000,TRUE,FALSE);\nCREATE TABLE IF NOT EXISTS redemptions (\n id CHAR(36) PRIMARY KEY, user_id CHAR(36) NOT NULL, reward_id VARCHAR(40) NOT NULL,\n game_id VARCHAR(80), cost INT UNSIGNED NOT NULL,\n status ENUM('pending','completed','rejected') NOT NULL DEFAULT 'pending',\n created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (reward_id) REFERENCES rewards(id)\n);\nCREATE TABLE IF NOT EXISTS demo_sessions (\n id CHAR(36) PRIMARY KEY, user_id CHAR(36) NOT NULL, consumed BOOLEAN NOT NULL DEFAULT FALSE,\n created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n FOREIGN KEY (user_id) REFERENCES users(id)\n);\n\nCREATE TABLE IF NOT EXISTS web_sessions (\n token_hash CHAR(64) PRIMARY KEY,\n user_id CHAR(36) NOT NULL,\n expires_at DATETIME NOT NULL,\n created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n INDEX web_sessions_expiry (expires_at),\n FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE\n);\n";
export async function initializeSchema(db) {
  for (const statement of SCHEMA.split(';').map(s=>s.trim()).filter(Boolean)) {
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
