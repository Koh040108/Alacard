const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const path = require('path');

async function checkDB() {
    console.log("=== DB CHECKER ===");
    try {
        const dbPath = path.resolve(__dirname, 'database.sqlite');
        console.log("Opening DB at:", dbPath);

        const db = await open({
            filename: dbPath,
            driver: sqlite3.Database
        });

        const logs = await db.all('SELECT * FROM audit_logs');
        const citizens = await db.all('SELECT * FROM citizens');

        console.log(`\n[CITIZENS] Count: ${citizens.length}`);
        console.log(`[AUDIT LOGS] Count: ${logs.length}`);

        if (logs.length === 0) {
            console.log("\n--> RESULT: DATABASE IS EMPTY. No scans have been recorded.");
        } else {
            console.log("\n--> RESULT: Logs found!");
            console.log("    First Log ID:", logs[0].audit_id);
            console.log("    First Log Hash:", logs[0].token_hash);
            console.log("    First Log Result:", logs[0].result);
        }
    } catch (e) {
        console.error("DB Error:", e);
    }
}

checkDB();
