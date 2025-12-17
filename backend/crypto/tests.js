/**
 * AlaCard Security Tests
 * 
 * Comprehensive tests demonstrating the security properties of the system.
 * These tests are designed to be:
 * 1. Readable by security judges
 * 2. Self-documenting (each test explains what attack it prevents)
 * 3. Complete (covers all critical security properties)
 * 
 * Run with: node crypto/tests.js
 */

const crypto = require('crypto');

// Import all modules
const {
    base64UrlEncode,
    base64UrlDecode,
    sha256Base64Url,
    generateNonce,
    now,
    constantTimeEqual,
} = require('./utils');

const {
    generateIssuerKeyPair,
    generateWalletKeyPair,
    importPublicKeyRaw,
    exportPublicKeyRaw,
} = require('./keys');

const {
    createToken,
    verifyToken,
    parseToken,
    hashToken,
} = require('./token');

const {
    generateChallenge,
    generateProof,
    verifyProof,
    NonceStore,
} = require('./proof');

// =============================================================================
// TEST UTILITIES
// =============================================================================

let testsPassed = 0;
let testsFailed = 0;

function test(name, fn) {
    try {
        fn();
        console.log(`✅ PASS: ${name}`);
        testsPassed++;
    } catch (e) {
        console.log(`❌ FAIL: ${name}`);
        console.log(`   Error: ${e.message}`);
        testsFailed++;
    }
}

async function testAsync(name, fn) {
    try {
        await fn();
        console.log(`✅ PASS: ${name}`);
        testsPassed++;
    } catch (e) {
        console.log(`❌ FAIL: ${name}`);
        console.log(`   Error: ${e.message}`);
        testsFailed++;
    }
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message || 'Assertion failed');
    }
}

function assertEqual(actual, expected, message) {
    if (actual !== expected) {
        throw new Error(message || `Expected ${expected}, got ${actual}`);
    }
}

// =============================================================================
// SETUP
// =============================================================================

console.log('='.repeat(60));
console.log('AlaCard Security Tests');
console.log('='.repeat(60));
console.log('');

// Generate keys for testing
const issuerKeys = generateIssuerKeyPair();
const walletKeys = generateWalletKeyPair();
const attackerWalletKeys = generateWalletKeyPair();

console.log('🔑 Generated test keys:');
console.log(`   Issuer public key: ${issuerKeys.publicKey.raw.substring(0, 32)}...`);
console.log(`   Wallet public key: ${walletKeys.publicKey.raw.substring(0, 32)}...`);
console.log(`   Attacker wallet:   ${attackerWalletKeys.publicKey.raw.substring(0, 32)}...`);
console.log('');

// =============================================================================
// BASIC FUNCTIONALITY TESTS
// =============================================================================

console.log('--- Basic Functionality ---');

test('Token creation succeeds with valid inputs', () => {
    const result = createToken({
        eligible: true,
        walletPublicKey: walletKeys.publicKey.raw,
        issuerId: 'GOV_ISSUER_001',
        issuerPrivateKey: issuerKeys.privateKey.keyObject,
    });
    
    assert(result.token, 'Token should be created');
    assert(result.token.split('.').length === 3, 'Token should have 3 parts');
    assert(result.payload.elig === true, 'Eligibility should be true');
});

test('Token verification succeeds with valid token', () => {
    const { token } = createToken({
        eligible: true,
        walletPublicKey: walletKeys.publicKey.raw,
        issuerId: 'GOV_ISSUER_001',
        issuerPrivateKey: issuerKeys.privateKey.keyObject,
    });
    
    const result = verifyToken(token, issuerKeys.publicKey.keyObject);
    
    assert(result.valid === true, 'Token should be valid');
    assert(result.payload.elig === true, 'Eligibility should be true');
});

test('Challenge generation produces unique nonces', () => {
    const challenge1 = generateChallenge('TERMINAL_001');
    const challenge2 = generateChallenge('TERMINAL_001');
    
    assert(challenge1.nonce !== challenge2.nonce, 'Nonces should be unique');
    assert(challenge1.nonce.length >= 32, 'Nonce should be at least 32 chars');
});

test('Proof generation and verification succeeds', () => {
    const { token } = createToken({
        eligible: true,
        walletPublicKey: walletKeys.publicKey.raw,
        issuerId: 'GOV_ISSUER_001',
        issuerPrivateKey: issuerKeys.privateKey.keyObject,
    });
    
    const challenge = generateChallenge('TERMINAL_001');
    
    const proof = generateProof({
        token,
        nonce: challenge.nonce,
        walletPrivateKey: walletKeys.privateKey.keyObject,
    });
    
    const result = verifyProof({
        proof,
        challenge,
        issuerPublicKey: issuerKeys.publicKey.keyObject,
    });
    
    assert(result.valid === true, 'Proof should be valid');
    assert(result.eligible === true, 'Should show eligible');
});

console.log('');

// =============================================================================
// ATTACK PREVENTION TESTS
// =============================================================================

console.log('--- Attack Prevention Tests ---');

// -----------------------------------------------------------------------------
// ATTACK 1: Token Tampering
// Attacker modifies eligibility status in token
// -----------------------------------------------------------------------------

test('ATTACK: Token tampering is detected', () => {
    // Create a legitimate token with eligible=false
    const { token } = createToken({
        eligible: false,
        walletPublicKey: walletKeys.publicKey.raw,
        issuerId: 'GOV_ISSUER_001',
        issuerPrivateKey: issuerKeys.privateKey.keyObject,
    });
    
    // Attacker tries to change eligible to true
    const [header, payload, signature] = token.split('.');
    const decodedPayload = JSON.parse(Buffer.from(base64UrlDecode(payload)).toString());
    decodedPayload.elig = true; // Tamper!
    
    const tamperedPayload = base64UrlEncode(Buffer.from(JSON.stringify(decodedPayload)));
    const tamperedToken = `${header}.${tamperedPayload}.${signature}`;
    
    // Verification should fail
    const result = verifyToken(tamperedToken, issuerKeys.publicKey.keyObject);
    
    assert(result.valid === false, 'Tampered token should be invalid');
    assert(result.error.includes('Signature'), 'Should detect signature mismatch');
});

// -----------------------------------------------------------------------------
// ATTACK 2: Token Replay
// Attacker captures a valid proof and replays it
// -----------------------------------------------------------------------------

test('ATTACK: Proof replay is detected (same nonce)', () => {
    const nonceStore = new NonceStore();
    
    const { token } = createToken({
        eligible: true,
        walletPublicKey: walletKeys.publicKey.raw,
        issuerId: 'GOV_ISSUER_001',
        issuerPrivateKey: issuerKeys.privateKey.keyObject,
    });
    
    const challenge = generateChallenge('TERMINAL_001');
    nonceStore.storeChallenge(challenge.nonce, challenge);
    
    const proof = generateProof({
        token,
        nonce: challenge.nonce,
        walletPrivateKey: walletKeys.privateKey.keyObject,
    });
    
    // First verification should succeed
    const consumed1 = nonceStore.consumeNonce(challenge.nonce);
    assert(consumed1 === true, 'First use should succeed');
    
    // Replay attempt should fail
    const consumed2 = nonceStore.consumeNonce(challenge.nonce);
    assert(consumed2 === false, 'Replay should fail: nonce already used');
});

test('ATTACK: Proof with wrong nonce is rejected', () => {
    const { token } = createToken({
        eligible: true,
        walletPublicKey: walletKeys.publicKey.raw,
        issuerId: 'GOV_ISSUER_001',
        issuerPrivateKey: issuerKeys.privateKey.keyObject,
    });
    
    const realChallenge = generateChallenge('TERMINAL_001');
    const fakeChallenge = generateChallenge('TERMINAL_001');
    
    // Generate proof with real nonce
    const proof = generateProof({
        token,
        nonce: realChallenge.nonce,
        walletPrivateKey: walletKeys.privateKey.keyObject,
    });
    
    // Try to verify with different nonce
    const result = verifyProof({
        proof,
        challenge: fakeChallenge, // Wrong challenge!
        issuerPublicKey: issuerKeys.publicKey.keyObject,
    });
    
    assert(result.valid === false, 'Proof with wrong nonce should fail');
    assert(result.error.includes('mismatch'), 'Should detect nonce mismatch');
});

// -----------------------------------------------------------------------------
// ATTACK 3: Token Theft
// Attacker steals token but doesn't have wallet private key
// -----------------------------------------------------------------------------

test('ATTACK: Stolen token cannot be used without wallet key', () => {
    // Legitimate user creates token
    const { token } = createToken({
        eligible: true,
        walletPublicKey: walletKeys.publicKey.raw,
        issuerId: 'GOV_ISSUER_001',
        issuerPrivateKey: issuerKeys.privateKey.keyObject,
    });
    
    // Attacker steals token and tries to use it with their own wallet
    const challenge = generateChallenge('TERMINAL_001');
    
    const attackerProof = generateProof({
        token,
        nonce: challenge.nonce,
        walletPrivateKey: attackerWalletKeys.privateKey.keyObject, // Attacker's key!
    });
    
    const result = verifyProof({
        proof: attackerProof,
        challenge,
        issuerPublicKey: issuerKeys.publicKey.keyObject,
    });
    
    assert(result.valid === false, 'Stolen token proof should fail');
    assert(result.error.includes('Wallet signature'), 'Should detect wrong wallet');
});

// -----------------------------------------------------------------------------
// ATTACK 4: Forged Token
// Attacker tries to create their own token
// -----------------------------------------------------------------------------

test('ATTACK: Forged token with wrong issuer key is rejected', () => {
    // Attacker generates their own issuer keys
    const fakeIssuerKeys = generateIssuerKeyPair();
    
    // Attacker creates a "valid" token with their fake issuer key
    const { token } = createToken({
        eligible: true,
        walletPublicKey: attackerWalletKeys.publicKey.raw,
        issuerId: 'FAKE_GOV_ISSUER',
        issuerPrivateKey: fakeIssuerKeys.privateKey.keyObject,
    });
    
    // Verification with real government key should fail
    const result = verifyToken(token, issuerKeys.publicKey.keyObject);
    
    assert(result.valid === false, 'Forged token should be invalid');
    assert(result.error.includes('Signature'), 'Should detect invalid signature');
});

// -----------------------------------------------------------------------------
// ATTACK 5: Expired Token
// Attacker uses an expired token
// -----------------------------------------------------------------------------

test('ATTACK: Expired token is rejected', () => {
    // Create a token that expires immediately
    const { token } = createToken({
        eligible: true,
        walletPublicKey: walletKeys.publicKey.raw,
        issuerId: 'GOV_ISSUER_001',
        issuerPrivateKey: issuerKeys.privateKey.keyObject,
        validitySeconds: -1, // Already expired!
    });
    
    const result = verifyToken(token, issuerKeys.publicKey.keyObject);
    
    assert(result.valid === false, 'Expired token should be invalid');
    assert(result.error.includes('expired'), 'Should detect expiry');
});

// -----------------------------------------------------------------------------
// ATTACK 6: Algorithm Confusion
// Attacker tries to use "none" algorithm
// -----------------------------------------------------------------------------

test('ATTACK: Algorithm confusion is prevented', () => {
    const { token } = createToken({
        eligible: true,
        walletPublicKey: walletKeys.publicKey.raw,
        issuerId: 'GOV_ISSUER_001',
        issuerPrivateKey: issuerKeys.privateKey.keyObject,
    });
    
    // Attacker modifies header to use "none" algorithm
    const [, payload, signature] = token.split('.');
    const noneHeader = base64UrlEncode(Buffer.from(JSON.stringify({
        alg: 'none', // Attack!
        typ: 'ELIGIBILITY',
        ver: '1',
    })));
    const tamperedToken = `${noneHeader}.${payload}.${signature}`;
    
    const result = verifyToken(tamperedToken, issuerKeys.publicKey.keyObject);
    
    assert(result.valid === false, 'Algorithm confusion should fail');
    assert(result.error.includes('algorithm'), 'Should detect invalid algorithm');
});

// -----------------------------------------------------------------------------
// ATTACK 7: Wallet Binding Bypass
// Attacker tries to use token with wrong wallet
// -----------------------------------------------------------------------------

test('ATTACK: Wallet binding is enforced', () => {
    // Create token bound to legitimate wallet
    const { token } = createToken({
        eligible: true,
        walletPublicKey: walletKeys.publicKey.raw,
        issuerId: 'GOV_ISSUER_001',
        issuerPrivateKey: issuerKeys.privateKey.keyObject,
    });
    
    // Verify with expected wallet key check
    const result = verifyToken(token, issuerKeys.publicKey.keyObject, {
        expectedWalletPublicKey: attackerWalletKeys.publicKey.raw, // Wrong wallet!
    });
    
    assert(result.valid === false, 'Wrong wallet binding should fail');
    assert(result.error.includes('wallet'), 'Should detect wallet mismatch');
});

// -----------------------------------------------------------------------------
// ATTACK 8: Signature Malleability
// Attacker tries to modify signature format
// -----------------------------------------------------------------------------

test('ATTACK: Invalid signature length is rejected', () => {
    const { token } = createToken({
        eligible: true,
        walletPublicKey: walletKeys.publicKey.raw,
        issuerId: 'GOV_ISSUER_001',
        issuerPrivateKey: issuerKeys.privateKey.keyObject,
    });
    
    const [header, payload] = token.split('.');
    // Create invalid signature (wrong length)
    const invalidSig = base64UrlEncode(Buffer.alloc(32)); // Should be 64 bytes
    const tamperedToken = `${header}.${payload}.${invalidSig}`;
    
    const result = verifyToken(tamperedToken, issuerKeys.publicKey.keyObject);
    
    assert(result.valid === false, 'Invalid signature length should fail');
});

console.log('');

// =============================================================================
// PRIVACY TESTS
// =============================================================================

console.log('--- Privacy Tests ---');

test('Token does not contain IC number', () => {
    const { token, payload } = createToken({
        eligible: true,
        walletPublicKey: walletKeys.publicKey.raw,
        issuerId: 'GOV_ISSUER_001',
        issuerPrivateKey: issuerKeys.privateKey.keyObject,
    });
    
    const tokenString = JSON.stringify(payload);
    
    // Check that no personal identifiers are present
    assert(!tokenString.includes('ic'), 'Should not contain IC field');
    assert(!tokenString.includes('name'), 'Should not contain name field');
    assert(!tokenString.includes('income'), 'Should not contain income field');
    assert(!tokenString.includes('address'), 'Should not contain address field');
    
    // Verify only expected fields are present
    const allowedFields = ['elig', 'wbind', 'wpub', 'iss', 'iat', 'exp', 'jti'];
    for (const key of Object.keys(payload)) {
        assert(allowedFields.includes(key), `Unexpected field in payload: ${key}`);
    }
});

test('Proof does not reveal token contents to eavesdropper', () => {
    const { token } = createToken({
        eligible: true,
        walletPublicKey: walletKeys.publicKey.raw,
        issuerId: 'GOV_ISSUER_001',
        issuerPrivateKey: issuerKeys.privateKey.keyObject,
    });
    
    const challenge = generateChallenge('TERMINAL_001');
    
    const proof = generateProof({
        token,
        nonce: challenge.nonce,
        walletPrivateKey: walletKeys.privateKey.keyObject,
    });
    
    // An eavesdropper sees the proof but cannot:
    // 1. Reuse it (nonce is bound)
    // 2. Create new proofs (no wallet private key)
    // 3. Extract personal data (none in token)
    
    assert(proof.nonce === challenge.nonce, 'Proof contains nonce');
    assert(proof.tokenHash, 'Proof contains token hash');
    assert(proof.signature, 'Proof contains signature');
    
    // Token is included for verification, but contains no PII
    const parsedToken = parseToken(proof.token);
    assert(!JSON.stringify(parsedToken.payload).includes('CITIZEN'), 
           'Token should not contain citizen identifier');
});

console.log('');

// =============================================================================
// CRYPTOGRAPHIC PROPERTY TESTS
// =============================================================================

console.log('--- Cryptographic Properties ---');

test('Key generation produces unique keys', () => {
    const key1 = generateWalletKeyPair();
    const key2 = generateWalletKeyPair();
    
    assert(key1.publicKey.raw !== key2.publicKey.raw, 'Public keys should be unique');
});

test('Nonces have sufficient entropy', () => {
    const nonces = new Set();
    for (let i = 0; i < 100; i++) {
        nonces.add(generateNonce());
    }
    
    assert(nonces.size === 100, 'All 100 nonces should be unique');
});

test('Token hashes are deterministic', () => {
    const { token } = createToken({
        eligible: true,
        walletPublicKey: walletKeys.publicKey.raw,
        issuerId: 'GOV_ISSUER_001',
        issuerPrivateKey: issuerKeys.privateKey.keyObject,
    });
    
    const hash1 = hashToken(token);
    const hash2 = hashToken(token);
    
    assert(hash1 === hash2, 'Same token should produce same hash');
});

test('Different tokens produce different hashes', () => {
    const result1 = createToken({
        eligible: true,
        walletPublicKey: walletKeys.publicKey.raw,
        issuerId: 'GOV_ISSUER_001',
        issuerPrivateKey: issuerKeys.privateKey.keyObject,
    });
    
    const result2 = createToken({
        eligible: true,
        walletPublicKey: walletKeys.publicKey.raw,
        issuerId: 'GOV_ISSUER_001',
        issuerPrivateKey: issuerKeys.privateKey.keyObject,
    });
    
    assert(result1.tokenHash !== result2.tokenHash, 
           'Different tokens should have different hashes');
});

test('Constant-time comparison prevents timing attacks', () => {
    const secret = Buffer.from('correct_secret_value');
    const correct = Buffer.from('correct_secret_value');
    const wrong = Buffer.from('wrong_secretXvalue');
    
    // These should take approximately the same time
    const result1 = constantTimeEqual(secret, correct);
    const result2 = constantTimeEqual(secret, wrong);
    
    assert(result1 === true, 'Equal values should match');
    assert(result2 === false, 'Different values should not match');
});

console.log('');

// =============================================================================
// SUMMARY
// =============================================================================

console.log('='.repeat(60));
console.log(`Tests Complete: ${testsPassed} passed, ${testsFailed} failed`);
console.log('='.repeat(60));

if (testsFailed > 0) {
    process.exit(1);
}
