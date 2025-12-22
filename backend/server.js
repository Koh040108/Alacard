require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const { initDB, getDB, prisma } = require('./database');
const crypto = require('./crypto');
const fraudEngine = require('./fraudEngine');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS Configuration from environment
const corsOrigins = process.env.CORS_ORIGINS?.split(',') || ['http://localhost:5173', 'http://localhost:3000'];
app.use(cors({
    origin: corsOrigins.length === 1 && corsOrigins[0] === '*' ? '*' : corsOrigins,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

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
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_MAX) || 1000,
    standardHeaders: true,
    legacyHeaders: false,
});

// Apply global API limiter to all routes starting with /
app.use(apiLimiter);

// Strip /api prefix for Vercel deployment (routes come in as /api/xxx but handlers expect /xxx)
app.use((req, res, next) => {
    if (req.url.startsWith('/api/')) {
        req.url = req.url.replace('/api', '');
    }
    next();
});

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
    const count = await prisma.citizen.count();
    if (count === 0) {
        console.log('Database empty. Auto-seeding default citizens...');
        await prisma.citizen.createMany({
            data: [
                { citizen_id: 'CITIZEN_001', income: 3000, eligibility_status: 'true', subsidy_quota: 300.00 },
                { citizen_id: 'CITIZEN_002', income: 8000, eligibility_status: 'false', subsidy_quota: 300.00 },
                { citizen_id: 'CITIZEN_003', income: 2500, eligibility_status: 'true', subsidy_quota: 300.00 },
            ],
        });
    }
}).catch(err => {
    console.error('Failed to initialize database:', err);
});

// Middleware to get DB (kept for compatibility, but we use prisma directly now)
app.use(async (req, res, next) => {
    req.db = prisma;
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

    const citizen = await prisma.citizen.findUnique({
        where: { citizen_id }
    });

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
        const expiryMs = Date.now() + (30 * 24 * 60 * 60 * 1000);
        await prisma.issuedToken.create({
            data: {
                token_id: tokenResult.payload.jti,
                token_hash: tokenResult.tokenHash,
                expiry: expiryMs.toString(),
                issuer_signature: 'ECDSA_SIG',
                citizen_id: citizen_id,
                status: 'ACTIVE'
            }
        });

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
    // Enhanced Extraction with Fallback
    let walletLocation = req.body.wallet_location || null;

    // Fallback: Check for flattened coordinates (if object was lost/stripped)
    if (!walletLocation && req.body.wallet_lat && req.body.wallet_lng) {
        console.log('[DEBUG] Reconstructing Wallet Location from flattened params');
        walletLocation = { lat: parseFloat(req.body.wallet_lat), lng: parseFloat(req.body.wallet_lng) };
    }

    // Debug Headers and Body Keys
    console.log('[DEBUG] Req Keys:', Object.keys(req.body));
    console.log('[DEBUG] Received Wallet Location:', walletLocation);

    if (!proof) {
        return res.status(400).json({ error: 'Missing proof object', received: req.body });
    }

    const pNonce = proof.n || proof.nonce;
    const pSig = proof.s || proof.signature;

    if (!pNonce) {
        return res.status(400).json({ error: 'Missing nonce (n/nonce)', proof_keys: Object.keys(proof) });
    }

    // 4. Extract Location
    const terminalLocation = req.body.location || { state: 'Unknown' };
    const locationStr = JSON.stringify(terminalLocation);

    // Check if we have an active challenge for this nonce
    const challenge = nonceStore.getChallenge(pNonce);

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

        // 4.5 CHECK FREEZE STATUS
        const issuedToken = await prisma.issuedToken.findFirst({
            where: { token_hash: result.tokenHash }
        });
        const wbind = result.walletBinding; // Extract Wallet Binding

        if (issuedToken && issuedToken.status === 'FROZEN') {
            await logAudit(result.tokenHash, wbind, terminalId, locationStr, 'BLOCKED_FROZEN', { reason: 'Government Freeze' });
            return res.json({ status: 'BLOCKED_FROZEN', error: 'Token is Frozen by Issuer' });
        }

        // 5. AI RISK ANALYSIS
        const riskAnalysis = await fraudEngine.analyzeRisk(prisma, result.tokenHash, terminalLocation, walletLocation);
        console.log('[AI] Risk Analysis:', riskAnalysis);

        // BLOCK if High Risk? Or just Warner? 
        // User Request: "Just detect and notify, don't block"
        let finalStatus = 'ELIGIBLE';
        if (riskAnalysis.score >= 80) finalStatus = 'WARNING'; // Changed from BLOCKED_FRAUD
        else if (riskAnalysis.score > 20) finalStatus = 'WARNING';

        // Log & Respond
        await logAudit(result.tokenHash, wbind, terminalId, locationStr, finalStatus, riskAnalysis);

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

    // CHECK FREEZE STATUS (Passive)
    const issuedToken = await prisma.issuedToken.findFirst({
        where: { token_hash: result.tokenHash }
    });
    const wbind = result.walletBinding; // Extract Wallet Binding

    if (issuedToken && issuedToken.status === 'FROZEN') {
        await logAudit(result.tokenHash, wbind, terminalId, locationStr, 'BLOCKED_FROZEN', { reason: 'Government Freeze' });
        return res.json({ status: 'BLOCKED_FROZEN', error: 'Token is Frozen by Issuer' });
    }

    // 5. AI RISK ANALYSIS (Passive Flow)
    const riskAnalysis = await fraudEngine.analyzeRisk(prisma, result.tokenHash, terminalLocation || {}, walletLocation);
    console.log('[AI] Risk Analysis (Passive):', riskAnalysis);

    let finalStatus = 'ELIGIBLE';
    if (riskAnalysis.score >= 80) finalStatus = 'WARNING'; // Changed from BLOCKED_FRAUD
    else if (riskAnalysis.score > 20) finalStatus = 'WARNING';

    // Cache signature to prevent reuse logic
    signatureCache.add(pSig);

    await logAudit(result.tokenHash, wbind, terminalId, locationStr, finalStatus, riskAnalysis);
    return res.json({
        status: finalStatus,
        risk: riskAnalysis,
        audit_logged: true,
        details: result,
        mode: 'PASSIVE'
    });
});

// Helper for Audit Logging (Updated for Prisma)
async function logAudit(tokenHash, walletBinding, terminalId, location, resultStatus, riskAnalysis = {}) {
    const timestamp = new Date().toISOString();

    // Get last audit log for hash chain
    const lastLog = await prisma.auditLog.findFirst({
        orderBy: { audit_id: 'desc' },
        select: { current_hash: true }
    });
    const prev_hash = lastLog ? lastLog.current_hash : 'GENESIS_HASH';

    const riskStr = JSON.stringify(riskAnalysis);

    // Include location and risk in the immutable record chain
    const record_data = prev_hash + tokenHash + walletBinding + terminalId + location + riskStr + timestamp + resultStatus;
    const current_hash = crypto.sha256Hex(record_data);

    await prisma.auditLog.create({
        data: {
            token_hash: tokenHash,
            wallet_binding: walletBinding,
            terminal_id: terminalId,
            location: location,
            risk_data: riskStr,
            timestamp: timestamp,
            result: resultStatus,
            prev_hash: prev_hash,
            current_hash: current_hash
        }
    });
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
    const logs = await prisma.auditLog.findMany({
        orderBy: { audit_id: 'desc' },
        take: 50
    });
    res.json(logs);
});

// SEED DATA
app.post('/seed', async (req, res) => {
    await prisma.citizen.deleteMany();
    await prisma.citizen.createMany({
        data: [
            { citizen_id: 'CITIZEN_001', income: 3000, eligibility_status: 'true', subsidy_quota: 300.00 },
            { citizen_id: 'CITIZEN_002', income: 8000, eligibility_status: 'false', subsidy_quota: 300.00 },
            { citizen_id: 'CITIZEN_003', income: 2500, eligibility_status: 'true', subsidy_quota: 300.00 },
        ],
    });
    res.json({ message: 'Seeded' });
});

// ADMIN APIs

// GET /citizens
app.get('/citizens', async (req, res) => {
    try {
        const citizens = await prisma.citizen.findMany();
        res.json(citizens);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST /update-citizen
app.post('/update-citizen', async (req, res) => {
    const { citizen_id, income, eligibility_status, subsidy_quota } = req.body;
    if (!citizen_id) return res.status(400).json({ error: 'Missing citizen_id' });

    try {
        const exists = await prisma.citizen.findUnique({
            where: { citizen_id }
        });
        const quota = subsidy_quota !== undefined ? subsidy_quota : 300.00;

        if (exists) {
            await prisma.citizen.update({
                where: { citizen_id },
                data: { income, eligibility_status, subsidy_quota: quota }
            });
        } else {
            await prisma.citizen.create({
                data: { citizen_id, income, eligibility_status, subsidy_quota: quota }
            });
        }

        res.json({ success: true, citizen_id });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST /admin/reset-quotas
app.post('/admin/reset-quotas', async (req, res) => {
    const { amount } = req.body;
    if (!amount && amount !== 0) return res.status(400).json({ error: 'Missing amount' });
    try {
        await prisma.citizen.updateMany({
            data: { subsidy_quota: amount }
        });
        res.json({ success: true, message: `All quotas reset to ${amount}` });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST /claim-subsidy (Simulated Pump Transaction)
app.post('/claim-subsidy', async (req, res) => {
    const { token, amount } = req.body;
    let { citizen_id } = req.body; // Can be undefined now
    if (!token || !amount) return res.status(400).json({ error: 'Missing token or amount' });

    try {
        if (!citizen_id) {
            // Lookup via token hash
            const tokenHash = crypto.hashToken(token);
            const issued = await prisma.issuedToken.findFirst({
                where: { token_hash: tokenHash }
            });
            if (issued && issued.citizen_id) {
                citizen_id = issued.citizen_id;
            } else {
                return res.status(404).json({ error: 'Token not linked to citizen (Legacy or Invalid)' });
            }
        }

        const citizen = await prisma.citizen.findUnique({
            where: { citizen_id }
        });
        if (!citizen) return res.status(404).json({ error: 'Citizen not found' });

        if ((citizen.subsidy_quota || 0) < amount) {
            return res.status(400).json({ error: 'Insufficient Quota' });
        }

        const newBalance = (citizen.subsidy_quota || 0) - amount;
        await prisma.citizen.update({
            where: { citizen_id },
            data: { subsidy_quota: newBalance }
        });

        // Log it
        const wbind = crypto.parseToken(token).payload.wbind;
        await logAudit(crypto.hashToken(token), wbind, 'PUMP_SIMULATOR', JSON.stringify({ amount, remaining: newBalance }), 'CLAIM_SUCCESS');

        res.json({ success: true, remaining: newBalance });

    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// POST /freeze-token
app.post('/freeze-token', async (req, res) => {
    console.log("[DEBUG] /freeze-token body:", req.body);
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Missing token' });

    try {
        const tokenHash = crypto.hashToken(token);
        await prisma.issuedToken.updateMany({
            where: { token_hash: tokenHash },
            data: { status: 'FROZEN' }
        });
        res.json({ success: true, message: 'Token Frozen' });
    } catch (error) {
        console.error("Freeze Error:", error);
        res.status(500).json({ error: error.message });
    }
});

// POST /unfreeze-token
app.post('/unfreeze-token', async (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Missing token' });

    try {
        const tokenHash = crypto.hashToken(token);
        await prisma.issuedToken.updateMany({
            where: { token_hash: tokenHash },
            data: { status: 'ACTIVE' }
        });
        res.json({ success: true, message: 'Token Activated' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST /token-status
app.post('/token-status', async (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Missing token' });

    try {
        const tokenHash = crypto.hashToken(token);
        const row = await prisma.issuedToken.findFirst({
            where: { token_hash: tokenHash }
        });
        res.json({ status: row ? row.status : 'UNKNOWN' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// GET /issued-tokens (Registry)
app.get('/issued-tokens', async (req, res) => {
    try {
        const tokens = await prisma.issuedToken.findMany({
            orderBy: { expiry: 'desc' }
        });
        res.json(tokens);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST /my-activity (Citizen Personal Logs)
app.post('/my-activity', async (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Missing token' });

    try {
        // 1. Get Token Hash
        const tokenHash = crypto.hashToken(token);

        // 2. Find Citizen ID for this token
        const issueRecord = await prisma.issuedToken.findFirst({
            where: { token_hash: tokenHash }
        });

        if (!issueRecord || !issueRecord.citizen_id) {
            // Fallback: Use wallet binding if legacy token or no citizen link found
            const parsed = crypto.parseToken(token);
            const wbind = parsed.payload.wbind;
            const logs = await prisma.auditLog.findMany({
                where: { wallet_binding: wbind },
                orderBy: { timestamp: 'desc' }
            });
            return res.json(logs);
        }

        const citizenId = issueRecord.citizen_id;

        // 3. Find ALL tokens for this citizen to aggregated history across devices/sessions
        const allTokens = await prisma.issuedToken.findMany({
            where: { citizen_id: citizenId },
            select: { token_hash: true }
        });
        const allHashes = allTokens.map(t => t.token_hash).filter(Boolean);

        if (allHashes.length === 0) return res.json([]);

        // 4. Fetch logs for ALL these tokens
        const logs = await prisma.auditLog.findMany({
            where: { token_hash: { in: allHashes } },
            orderBy: { timestamp: 'desc' }
        });

        res.json(logs);
    } catch (err) {
        console.error("Activity Fetch Error:", err);
        res.status(500).json({ error: err.message });
    }
});

// POST /my-balance
app.post('/my-balance', async (req, res) => {
    const { citizen_id } = req.body;
    if (!citizen_id) return res.status(400).json({ error: 'Missing citizen_id' });

    try {
        const citizen = await prisma.citizen.findUnique({
            where: { citizen_id },
            select: { subsidy_quota: true }
        });
        if (!citizen) return res.status(404).json({ error: 'Citizen not found' });
        res.json({ balance: citizen.subsidy_quota !== undefined ? citizen.subsidy_quota : 300.00 });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.listen(PORT, () => {
    console.log(`Backend running on http://localhost:${PORT}`);
    console.log(`- Crypto Core: ECDSA P-256 (Enabled)`);
    console.log(`- AI Fraud Engine: Enabled`);
    console.log(`- Database: PostgreSQL (Prisma)`);
});

module.exports = app;
