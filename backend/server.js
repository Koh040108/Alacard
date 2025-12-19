const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const { initDB, getDB } = require('./database');
const crypto = require('./crypto');
const fraudEngine = require('./fraudEngine');

const app = express();
const PORT = 3000;

// =============================================================================
// RATE LIMITING
// =============================================================================
const rateLimit = require('express-rate-limit');

// Stricter limit for issuance (prevent token mining)
const issueLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10, // Limit each IP to 10 requests per windowMs
    message: { error: 'Too many tokens issued from this IP, please try again after an hour' }
});

// General limit for verification/challenges
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
});

// Apply global API limiter to all routes starting with /
app.use(apiLimiter);

app.use(cors({
    origin: '*', // Allow all origins for the simulator demo
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(bodyParser.json());

// =============================================================================
// KEY MANAGEMENT (Persistence Layer)
// -----------------------------------------------------------------------------
// The crypto module provides logic, but we need to persist keys to disk
// so the issuer identity remains consistent across restarts.
// =============================================================================

const KEYS_DIR = path.join(__dirname, 'keys');
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, 'issuer-private.pem');
const PUBLIC_KEY_PATH = path.join(KEYS_DIR, 'issuer-public.pem');

// Ensure keys directory exists
if (!fs.existsSync(KEYS_DIR)) {
    fs.mkdirSync(KEYS_DIR);
}

let issuerKeys = null;

function loadOrGenerateKeys() {
    // 1. Try Environment Variables (Cloud/Stateless)
    if (process.env.ISSUER_PRIVATE_KEY && process.env.ISSUER_PUBLIC_KEY) {
        console.log('Loading issuer keys from Environment Variables...');
        try {
            // Support both raw multiline string or base64 encoded env vars if needed
            // For now assuming standard PEM string in env
            const privateKeyPem = process.env.ISSUER_PRIVATE_KEY.replace(/\\n/g, '\n');
            const publicKeyPem = process.env.ISSUER_PUBLIC_KEY.replace(/\\n/g, '\n');

            issuerKeys = {
                privateKey: crypto.importPrivateKeyPem(privateKeyPem),
                publicKey: crypto.importPublicKeyPem(publicKeyPem),
            };
            return;
        } catch (e) {
            console.error('Failed to load keys from ENV:', e.message);
            // Fallback to file generation not safe if env was intended but failed
        }
    }

    // 2. Try File System (Persistence)
    if (fs.existsSync(PRIVATE_KEY_PATH) && fs.existsSync(PUBLIC_KEY_PATH)) {
        console.log('Loading existing issuer keys from File System...');
        try {
            const privateKeyPem = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
            const publicKeyPem = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');

            issuerKeys = {
                privateKey: crypto.importPrivateKeyPem(privateKeyPem),
                publicKey: crypto.importPublicKeyPem(publicKeyPem),
            };
        } catch (e) {
            console.error('Failed to load keys:', e.message);
            process.exit(1);
        }
    } else {
        console.log('Generating new issuer key pair (ECDSA P-256)...');
        const keys = crypto.generateIssuerKeyPair();

        // Only save to file if we can (might fail on read-only cloud fs)
        try {
            if (!fs.existsSync(KEYS_DIR)) fs.mkdirSync(KEYS_DIR);
            fs.writeFileSync(PRIVATE_KEY_PATH, keys.privateKey.pem);
            fs.writeFileSync(PUBLIC_KEY_PATH, keys.publicKey.pem);
        } catch (e) {
            console.warn("Could not save keys to disk (Read-Only FS?):", e.message);
        }

        issuerKeys = {
            privateKey: keys.privateKey.keyObject,
            publicKey: keys.publicKey.keyObject,
        };
    }
}

// Initialize DB and Keys
initDB().then(async () => {
    loadOrGenerateKeys();

    // Auto-seed if citizens table is empty (for Stateless Demos)
    const db = await getDB();
    const count = await db.get('SELECT count(*) as count FROM citizens');
    if (count && count.count === 0) {
        console.log('Database empty. Auto-seeding default citizens...');
        await db.run(`INSERT INTO citizens (citizen_id, income, eligibility_status) VALUES ('CITIZEN_001', 3000, 'true')`);
        await db.run(`INSERT INTO citizens (citizen_id, income, eligibility_status) VALUES ('CITIZEN_002', 8000, 'false')`);
        await db.run(`INSERT INTO citizens (citizen_id, income, eligibility_status) VALUES ('CITIZEN_003', 2500, 'true')`);
    }
});

// Middleware to get DB
app.use(async (req, res, next) => {
    req.db = await getDB();
    next();
});

// Nonce Store (In-Memory for now)
const nonceStore = new crypto.NonceStore();

// Cleanup expired nonces every minute
setInterval(() => {
    nonceStore.cleanup();
}, 60 * 1000);

// =============================================================================
// API ROUTES
// =============================================================================

// GET /public-key
// Returns the issuer's public key (Raw Base64URL format preferred for mobile)
app.get('/public-key', (req, res) => {
    if (!issuerKeys) return res.status(503).json({ error: 'Keys not initialized' });

    // Export to raw format (compact, standard for this system)
    const rawKey = crypto.exportPublicKeyRaw(issuerKeys.publicKey);
    res.json({ publicKey: rawKey });
});

// POST /challenge
// Generate a nonce for the wallet to sign
app.post('/challenge', (req, res) => {
    const terminalId = req.body.terminalId || 'UNKNOWN_TERMINAL';
    const challenge = crypto.generateChallenge(terminalId);

    // Store it to prevent replay later
    nonceStore.storeChallenge(challenge.nonce, challenge);

    res.json(challenge);
});

// POST /issue-token
// Issues a signed eligibility token bound to the user's wallet public key
// Input: { citizen_id, wallet_public_key }
app.post('/issue-token', issueLimiter, async (req, res) => {
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

    // Create Token (ECDSA P-256)
    try {
        const tokenResult = crypto.createToken({
            eligible: true,
            walletPublicKey: wallet_public_key,
            issuerId: 'GOV_ISSUER',
            issuerPrivateKey: issuerKeys.privateKey,
            validitySeconds: 30 * 24 * 60 * 60 // 30 days
        });

        // Store validity in DB (optional, for revocation checks)
        // Note: We authenticate the token via signature, but logging issuance is good practice
        const expiryMs = Date.now() + (30 * 24 * 60 * 60 * 1000);
        await req.db.run(
            'INSERT INTO issued_tokens (token_id, token_hash, expiry, issuer_signature) VALUES (?, ?, ?, ?)',
            [tokenResult.payload.jti, tokenResult.tokenHash, expiryMs, 'ECDSA_SIG']
        );

        res.json({
            token: tokenResult.token
        });
    } catch (e) {
        console.error('Token creation failed:', e);
        res.status(500).json({ error: 'Failed to issue token: ' + e.message });
    }
});

// POST /verify-token
// Verifies the ZKP proof (Token + Wallet Signature + Challenge)
// Input: Proof object { version, token, nonce, signature, ... }
app.post('/verify-token', async (req, res) => {
    const { proof } = req.body;
    const terminalId = req.body.terminalId || 'UNKNOWN_TERMINAL';

    console.log('[DEBUG] /verify-token body:', JSON.stringify(req.body));

    if (!proof) {
        return res.status(400).json({ error: 'Missing proof object', received: req.body });
    }

    const pNonce = proof.n || proof.nonce;
    const pSig = proof.s || proof.signature;

    if (!pNonce) {
        return res.status(400).json({ error: 'Missing nonce (n/nonce)', proof_keys: Object.keys(proof) });
    }

    // 4. Extract Location
    const locationObj = req.body.location || { state: 'Unknown' };
    const locationStr = JSON.stringify(locationObj);

    // ACTIVE FLOW (Challenge exists)
    if (challenge) {
        const consumed = nonceStore.consumeNonce(pNonce);
        if (!consumed) return res.status(400).json({ error: 'Nonce already used' });

        const result = crypto.verifyProof({
            proof: proof,
            challenge: challenge, // Pass the active challenge
            issuerPublicKey: issuerKeys.publicKey
        });

        if (!result.valid) return res.status(400).json({ error: result.error });

        // 5. AI RISK ANALYSIS
        const riskAnalysis = await fraudEngine.analyzeRisk(req.db, result.tokenHash, locationObj);
        console.log('[AI] Risk Analysis:', riskAnalysis);

        // BLOCK if High Risk? Or just Warner? 
        // For this Simulator, let's BLOCK if Critical > 80 (Impossible Travel)
        let finalStatus = 'ELIGIBLE';
        if (riskAnalysis.score >= 80) finalStatus = 'BLOCKED_FRAUD';
        else if (riskAnalysis.score > 20) finalStatus = 'WARNING';

        // Log & Respond
        await logAudit(req.db, result.tokenHash, terminalId, locationStr, finalStatus, riskAnalysis);

        return res.json({
            status: finalStatus,
            risk: riskAnalysis,
            audit_logged: true,
            details: result,
            mode: 'ACTIVE'
        });
    }

    // PASSIVE FLOW (Time-based Nonce)
    // Check replay cache for signature
    if (signatureCache.has(pSig)) {
        return res.status(400).json({ error: 'Replay detected: Signature already used' });
    }

    // Verify without challenge object (logic inside proof.js handles timestamp validation)
    const result = crypto.verifyProof({
        proof: proof,
        challenge: null, // Indicates passive mode
        issuerPublicKey: issuerKeys.publicKey
    });

    if (!result.valid) {
        return res.status(400).json({ error: result.error });
    }

    // Cache signature to prevent reuse logic
    signatureCache.add(pSig);

    await logAudit(req.db, result.tokenHash, terminalId, locationStr, 'ELIGIBLE');
    return res.json({ status: 'ELIGIBLE', audit_logged: true, details: result, mode: 'PASSIVE' });
});

// Helper for Audit Logging
async function logAudit(db, tokenHash, terminalId, location, resultStatus, riskAnalysis = {}) {
    const timestamp = new Date().toISOString();
    const lastLog = await db.get('SELECT current_hash FROM audit_logs ORDER BY audit_id DESC LIMIT 1');
    const prev_hash = lastLog ? lastLog.current_hash : 'GENESIS_HASH';

    const riskStr = JSON.stringify(riskAnalysis);

    // Include location and risk in the immutable record chain
    const record_data = prev_hash + tokenHash + terminalId + location + riskStr + timestamp + resultStatus;
    const current_hash = crypto.sha256Hex(record_data);

    await db.run(
        'INSERT INTO audit_logs (token_hash, terminal_id, location, risk_data, timestamp, result, prev_hash, current_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [tokenHash, terminalId, location, riskStr, timestamp, resultStatus, prev_hash, current_hash]
    );
}

// Signature Cache for Passive Replay Protection
const signatureCache = {
    cache: new Set(),
    add(sig) {
        this.cache.add(sig);
        setTimeout(() => this.cache.delete(sig), 60 * 1000); // 60s Memory
    },
    has(sig) {
        return this.cache.has(sig);
    }
};

// GET /audit-logs
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
    console.log(`- Crypto Core: ECDSA P-256 (Enabled)`);
    console.log(`- AI Fraud Engine: Enabled`);
});

module.exports = app;
