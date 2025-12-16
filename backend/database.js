const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const path = require('path');

let db;

async function initDB() {
  if (db) return db;
  
  db = await open({
    filename: path.join(__dirname, 'alacard.db'),
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
      issuer_signature TEXT
    );

    CREATE TABLE IF NOT EXISTS verification_terminals (
      terminal_id TEXT PRIMARY KEY,
      location TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
      token_hash TEXT,
      terminal_id TEXT,
      timestamp TEXT,
      result TEXT,
      prev_hash TEXT,
      current_hash TEXT
    );
  `);

  console.log('Database initialized');
  return db;
}

async function getDB() {
  if (!db) await initDB();
  return db;
}

module.exports = { initDB, getDB };
