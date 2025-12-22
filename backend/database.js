const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const path = require('path');

let db;

async function initDB() {
  if (db) return db;

  const isVercel = process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_VERSION;
  const dbPath = isVercel
    ? path.join('/tmp', 'alacard.db')
    : path.join(__dirname, 'alacard.db');

  db = await open({
    filename: dbPath,
    driver: sqlite3.Database
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS citizens (
      citizen_id TEXT PRIMARY KEY,
      income INTEGER,
      eligibility_status TEXT
    );

    CREATE TABLE IF NOT EXISTS issued_tokens (
      token_id TEXT PRIMARY KEY,
      token_hash TEXT,
      expiry TEXT,
      issuer_signature TEXT,
      status TEXT DEFAULT 'ACTIVE'
    );

    CREATE TABLE IF NOT EXISTS verification_terminals (
      terminal_id TEXT PRIMARY KEY,
      location TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
      token_hash TEXT,
      terminal_id TEXT,
      location TEXT,
      risk_data TEXT,
      timestamp TEXT,
      result TEXT,
      prev_hash TEXT,
      current_hash TEXT
    );

    CREATE TABLE IF NOT EXISTS pending_verifications (
      verification_id TEXT PRIMARY KEY,
      token_hash TEXT,
      wallet_binding TEXT,
      terminal_id TEXT,
      terminal_location TEXT,
      claim_amount REAL,
      risk_score INTEGER,
      risk_reasons TEXT,
      status TEXT DEFAULT 'PENDING',
      created_at TEXT,
      responded_at TEXT
    );
  `);

  // Migration: Add location/risk column if it doesn't exist
  try {
    await db.exec('ALTER TABLE audit_logs ADD COLUMN location TEXT');
  } catch (e) { }

  try {
    await db.exec('ALTER TABLE audit_logs ADD COLUMN risk_data TEXT');
    console.log("Migrated: Added risk_data column");
  } catch (e) { }

  try {
    await db.exec('ALTER TABLE audit_logs ADD COLUMN wallet_binding TEXT');
    console.log("Migrated: Added wallet_binding column");
  } catch (e) { }

  try {
    await db.exec("ALTER TABLE issued_tokens ADD COLUMN status TEXT DEFAULT 'ACTIVE'");
    console.log("Migrated: Added status column to issued_tokens");
  } catch (e) { }

  try {
    await db.exec("ALTER TABLE citizens ADD COLUMN subsidy_quota REAL DEFAULT 300.00");
    console.log("Migrated: Added subsidy_quota column to citizens");
  } catch (e) { }

  try {
    await db.exec('ALTER TABLE issued_tokens ADD COLUMN citizen_id TEXT');
    console.log("Migrated: Added citizen_id column to issued_tokens");
  } catch (e) { }


  console.log('Database initialized');
  return db;
}

async function getDB() {
  if (!db) await initDB();
  return db;
}

module.exports = { initDB, getDB };
