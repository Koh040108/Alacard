/**
 * Frontend Crypto Test Suite
 * 
 * Run this in the browser to verify the crypto modules work correctly.
 * Import this in a component or run from browser console.
 */

import {
    // Utils
    base64UrlEncode,
    base64UrlDecode,
    sha256Base64Url,
    generateNonce,
    now,
    
    // Keys
    generateWalletKeyPair,
    exportPublicKeyRaw,
    saveWalletKeys,
    loadWalletKeys,
    clearWalletKeys,
    hasWalletKeys,
    
    // Proof
    parseToken,
    hashToken,
    generateProof,
    serializeProof,
    isTokenExpired,
} from './index.js';

// =============================================================================
// TEST UTILITIES
// =============================================================================

let passed = 0;
let failed = 0;

function log(msg, type = 'info') {
    const styles = {
        info: 'color: #888',
        pass: 'color: #4CAF50; font-weight: bold',
        fail: 'color: #f44336; font-weight: bold',
        header: 'color: #2196F3; font-weight: bold; font-size: 14px',
    };
    console.log(`%c${msg}`, styles[type]);
}

async function test(name, fn) {
    try {
        await fn();
        log(`✅ PASS: ${name}`, 'pass');
        passed++;
    } catch (e) {
        log(`❌ FAIL: ${name}`, 'fail');
        log(`   Error: ${e.message}`, 'info');
        failed++;
    }
}

function assert(condition, message) {
    if (!condition) throw new Error(message || 'Assertion failed');
}

// =============================================================================
// RUN TESTS
// =============================================================================

export async function runTests() {
    log('═══════════════════════════════════════════', 'header');
    log('  AlaCard Frontend Crypto Tests', 'header');
    log('═══════════════════════════════════════════', 'header');
    console.log('');
    
    // -------------------------------------------------------------------------
    log('--- Base64URL Encoding ---', 'header');
    // -------------------------------------------------------------------------
    
    await test('Base64URL encode/decode roundtrip', async () => {
        const original = new Uint8Array([1, 2, 3, 4, 5, 255, 0, 128]);
        const encoded = base64UrlEncode(original);
        const decoded = base64UrlDecode(encoded);
        
        assert(decoded.length === original.length, 'Length mismatch');
        for (let i = 0; i < original.length; i++) {
            assert(decoded[i] === original[i], `Byte ${i} mismatch`);
        }
    });
    
    await test('Base64URL produces URL-safe output', async () => {
        const data = new Uint8Array(100);
        crypto.getRandomValues(data);
        const encoded = base64UrlEncode(data);
        
        assert(!encoded.includes('+'), 'Should not contain +');
        assert(!encoded.includes('/'), 'Should not contain /');
        assert(!encoded.includes('='), 'Should not contain =');
    });
    
    // -------------------------------------------------------------------------
    log('--- Hashing ---', 'header');
    // -------------------------------------------------------------------------
    
    await test('SHA-256 produces consistent output', async () => {
        const hash1 = await sha256Base64Url('test message');
        const hash2 = await sha256Base64Url('test message');
        
        assert(hash1 === hash2, 'Same input should produce same hash');
    });
    
    await test('SHA-256 produces different output for different input', async () => {
        const hash1 = await sha256Base64Url('message 1');
        const hash2 = await sha256Base64Url('message 2');
        
        assert(hash1 !== hash2, 'Different input should produce different hash');
    });
    
    // -------------------------------------------------------------------------
    log('--- Key Generation ---', 'header');
    // -------------------------------------------------------------------------
    
    await test('Wallet key pair generation', async () => {
        const keyPair = await generateWalletKeyPair();
        
        assert(keyPair.publicKey, 'Should have public key');
        assert(keyPair.privateKey, 'Should have private key');
        assert(keyPair.publicKey.raw, 'Should have raw public key');
        assert(keyPair.publicKey.jwk, 'Should have JWK public key');
        assert(keyPair.algorithm === 'ES256', 'Should be ES256');
        assert(keyPair.curve === 'P-256', 'Should be P-256');
    });
    
    await test('Key pairs are unique', async () => {
        const keyPair1 = await generateWalletKeyPair();
        const keyPair2 = await generateWalletKeyPair();
        
        assert(keyPair1.publicKey.raw !== keyPair2.publicKey.raw, 
               'Keys should be unique');
    });
    
    await test('Raw public key is 65 bytes (uncompressed)', async () => {
        const keyPair = await generateWalletKeyPair();
        const rawBytes = base64UrlDecode(keyPair.publicKey.raw);
        
        assert(rawBytes.length === 65, `Expected 65 bytes, got ${rawBytes.length}`);
        assert(rawBytes[0] === 0x04, 'Should start with 0x04 (uncompressed)');
    });
    
    // -------------------------------------------------------------------------
    log('--- Key Storage ---', 'header');
    // -------------------------------------------------------------------------
    
    await test('Save and load wallet keys', async () => {
        // Clear any existing keys
        clearWalletKeys();
        assert(!hasWalletKeys(), 'Should have no keys initially');
        
        // Generate and save
        const keyPair = await generateWalletKeyPair();
        saveWalletKeys(keyPair);
        assert(hasWalletKeys(), 'Should have keys after save');
        
        // Load and verify
        const loaded = await loadWalletKeys();
        assert(loaded !== null, 'Should load keys');
        assert(loaded.publicKey.raw === keyPair.publicKey.raw, 
               'Public key should match');
        
        // Cleanup
        clearWalletKeys();
    });
    
    // -------------------------------------------------------------------------
    log('--- Signing ---', 'header');
    // -------------------------------------------------------------------------
    
    await test('Wallet can sign data', async () => {
        const keyPair = await generateWalletKeyPair();
        const message = new TextEncoder().encode('test message');
        
        const signature = await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            keyPair.privateKey.cryptoKey,
            message
        );
        
        assert(signature.byteLength === 64, 'Signature should be 64 bytes');
    });
    
    await test('Signature verification works', async () => {
        const keyPair = await generateWalletKeyPair();
        const message = new TextEncoder().encode('test message');
        
        const signature = await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            keyPair.privateKey.cryptoKey,
            message
        );
        
        const valid = await crypto.subtle.verify(
            { name: 'ECDSA', hash: 'SHA-256' },
            keyPair.publicKey.cryptoKey,
            signature,
            message
        );
        
        assert(valid === true, 'Signature should be valid');
    });
    
    await test('Wrong key fails verification', async () => {
        const keyPair1 = await generateWalletKeyPair();
        const keyPair2 = await generateWalletKeyPair();
        const message = new TextEncoder().encode('test message');
        
        const signature = await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            keyPair1.privateKey.cryptoKey,
            message
        );
        
        const valid = await crypto.subtle.verify(
            { name: 'ECDSA', hash: 'SHA-256' },
            keyPair2.publicKey.cryptoKey, // Wrong key!
            signature,
            message
        );
        
        assert(valid === false, 'Should fail with wrong key');
    });
    
    // -------------------------------------------------------------------------
    log('--- Nonce Generation ---', 'header');
    // -------------------------------------------------------------------------
    
    await test('Nonces are unique', async () => {
        const nonces = new Set();
        for (let i = 0; i < 100; i++) {
            nonces.add(generateNonce());
        }
        assert(nonces.size === 100, 'All nonces should be unique');
    });
    
    await test('Nonces have sufficient length', async () => {
        const nonce = generateNonce();
        const bytes = base64UrlDecode(nonce);
        assert(bytes.length === 32, 'Nonce should be 32 bytes');
    });
    
    // -------------------------------------------------------------------------
    // SUMMARY
    // -------------------------------------------------------------------------
    
    console.log('');
    log('═══════════════════════════════════════════', 'header');
    log(`  Results: ${passed} passed, ${failed} failed`, 'header');
    log('═══════════════════════════════════════════', 'header');
    
    return { passed, failed };
}

// Auto-run if imported directly
// runTests();

export default runTests;
