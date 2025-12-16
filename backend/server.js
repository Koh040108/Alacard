const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { initDB, getDB } = require('./database');
const { ensureKeys, signData, verifySignature, hashData, getPublicKey } = require('./cryptoUtils');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(bodyParser.json());

// Initialize DB and Keys
initDB().then(() => {
    ensureKeys();
});

// Middleware to get DB
app.use(async (req, res, next) => {
    req.db = await getDB();
    next();
});

// GET /public-key - To allow terminals/wallets to get issuer public key
app.get('/public-key', (req, res) => {
    res.json({ publicKey: getPublicKey() });
});

// POST /issue-token
// Inputs: citizen_id, wallet_public_key (PEM string)
app.post('/issue-token', async (req, res) => {
    const { citizen_id, wallet_public_key } = req.body;

    if (!citizen_id || !wallet_public_key) {
        return res.status(400).json({ error: 'Missing citizen_id or wallet_public_key' });
    }

    const citizen = await req.db.get('SELECT * FROM citizens WHERE citizen_id = ?', [citizen_id]);

    if (!citizen) {
        return res.status(404).json({ error: 'Citizen not found' });
    }

    // Check eligibility logic (Mock: income < 5000)
    const isEligible = citizen.income < 5000 && citizen.eligibility_status !== 'false';

    if (!isEligible) {
        return res.status(403).json({ error: 'Not eligible for subsidy' });
    }

    const token_id = crypto.randomUUID();
    const expiry = Date.now() + (30 * 24 * 60 * 60 * 1000); // 30 days

    const tokenData = {
        token_id,
        subsidy_type: 'Government Tech Subsidy',
        eligible: true,
        expiry,
        wallet_public_key // Bind token to this wallet
    };

    const signature = signData(tokenData);

    // Store validity in DB (optional, for revocation checks, but we use it here)
    await req.db.run(
        'INSERT INTO issued_tokens (token_id, token_hash, expiry, issuer_signature) VALUES (?, ?, ?, ?)',
        [token_id, hashData(JSON.stringify(tokenData)), expiry, signature]
    );

    res.json({
        token: tokenData,
        signature
    });
});

// POST /verify-token
// Verifies the proof and logs the audit
// Proof = { token, token_signature, challenge_nonce, wallet_signature }
app.post('/verify-token', async (req, res) => {
    const { token, token_signature, challenge_nonce, wallet_signature, terminal_id } = req.body;

    if (!token || !token_signature || !challenge_nonce || !wallet_signature || !terminal_id) {
        return res.status(400).json({ error: 'Missing verification data' });
    }

    // 1. Verify Issuer Signature
    const isIssuerValid = verifySignature(token, token_signature);
    if (!isIssuerValid) {
        return res.status(400).json({ error: 'Invalid Issuer Signature' });
    }

    // 2. Verify Wallet Binding (Proof of Ownership)
    // The wallet should have signed the nonce with its private key.
    const verifyWallet = crypto.createVerify('SHA256');
    verifyWallet.update(challenge_nonce);
    verifyWallet.end();

    const isWalletValid = verifyWallet.verify(token.wallet_public_key, wallet_signature, 'hex');
    if (!isWalletValid) {
        return res.status(400).json({ error: 'Invalid Wallet Proof' });
    }

    // 3. Check Expiry
    if (Date.now() > token.expiry) {
        return res.status(400).json({ error: 'Token Expired' });
    }

    // 4. Audit Logging
    const token_hash = hashData(JSON.stringify(token));
    const timestamp = new Date().toISOString();

    // Get previous hash
    const lastLog = await req.db.get('SELECT current_hash FROM audit_logs ORDER BY audit_id DESC LIMIT 1');
    const prev_hash = lastLog ? lastLog.current_hash : 'GENESIS_HASH';

    const record_data = prev_hash + token_hash + terminal_id + timestamp + 'ELIGIBLE';
    const current_hash = hashData(record_data);

    await req.db.run(
        'INSERT INTO audit_logs (token_hash, terminal_id, timestamp, result, prev_hash, current_hash) VALUES (?, ?, ?, ?, ?, ?)',
        [token_hash, terminal_id, timestamp, 'ELIGIBLE', prev_hash, current_hash]
    );

    res.json({ status: 'ELIGIBLE', audit_logged: true });
});

// GET /audit-logs
// Optional: Filter by token_id/hash
app.get('/audit-logs', async (req, res) => {
    const logs = await req.db.all('SELECT * FROM audit_logs ORDER BY audit_id DESC LIMIT 50');
    res.json(logs);
});

// SEED DATA
app.post('/seed', async (req, res) => {
    await req.db.exec(`DELETE FROM citizens`);
    await req.db.run(`INSERT INTO citizens (citizen_id, income, eligibility_status) VALUES ('CITIZEN_001', 3000, 'true')`);
    await req.db.run(`INSERT INTO citizens (citizen_id, income, eligibility_status) VALUES ('CITIZEN_002', 8000, 'false')`); // High income
    await req.db.run(`INSERT INTO citizens (citizen_id, income, eligibility_status) VALUES ('CITIZEN_003', 2500, 'true')`);
    res.json({ message: 'Seeded' });
});

// ADMIN APIs

// GET /citizens
app.get('/citizens', async (req, res) => {
    try {
        const citizens = await req.db.all('SELECT * FROM citizens');
        res.json(citizens);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST /update-citizen
app.post('/update-citizen', async (req, res) => {
    const { citizen_id, income, eligibility_status } = req.body;
    if (!citizen_id) return res.status(400).json({ error: 'Missing citizen_id' });

    try {
        // Upsert logic (Insert or Replace)
        const exists = await req.db.get('SELECT citizen_id FROM citizens WHERE citizen_id = ?', [citizen_id]);

        if (exists) {
            await req.db.run(
                'UPDATE citizens SET income = ?, eligibility_status = ? WHERE citizen_id = ?',
                [income, eligibility_status, citizen_id]
            );
        } else {
            await req.db.run(
                'INSERT INTO citizens (citizen_id, income, eligibility_status) VALUES (?, ?, ?)',
                [citizen_id, income, eligibility_status]
            );
        }

        res.json({ success: true, citizen_id });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// GET /issued-tokens (Registry)
app.get('/issued-tokens', async (req, res) => {
    try {
        const tokens = await req.db.all('SELECT * FROM issued_tokens ORDER BY expiry DESC');
        res.json(tokens);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`Backend running on http://localhost:${PORT}`);
});

