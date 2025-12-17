/**
 * AlaCard Frontend Key Management
 * 
 * Browser-compatible key generation and management using Web Crypto API.
 * 
 * SECURITY: Private keys never leave the browser.
 * Keys are stored in browser storage and used only for signing.
 */

import { base64UrlEncode, base64UrlDecode } from './utils.js';

// =============================================================================
// KEY PAIR GENERATION
// =============================================================================

/**
 * Generate an ECDSA P-256 key pair for the wallet.
 * 
 * Uses Web Crypto API which provides:
 * - Hardware-backed key generation (when available)
 * - Secure random number generation
 * - Protection against timing attacks
 * 
 * @returns {Promise<Object>} Key pair with CryptoKey objects and exportable formats
 */
export async function generateWalletKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: 'ECDSA',
            namedCurve: 'P-256',
        },
        true, // extractable (needed for JWK export)
        ['sign', 'verify']
    );
    
    // Export to JWK format
    const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    
    // Export public key to raw format (65 bytes: 0x04 || x || y)
    const publicKeyRaw = await exportPublicKeyRaw(keyPair.publicKey);
    
    return {
        publicKey: {
            jwk: publicKeyJwk,
            raw: publicKeyRaw,
            cryptoKey: keyPair.publicKey,
        },
        privateKey: {
            jwk: privateKeyJwk,
            cryptoKey: keyPair.privateKey,
        },
        type: 'wallet',
        algorithm: 'ES256',
        curve: 'P-256',
    };
}

// =============================================================================
// KEY EXPORT
// =============================================================================

/**
 * Export a public key to raw format (uncompressed point).
 * 
 * Raw format is 65 bytes: 0x04 || x (32 bytes) || y (32 bytes)
 * 
 * @param {CryptoKey} publicKey - The public key to export
 * @returns {Promise<string>} Base64URL encoded raw public key
 */
export async function exportPublicKeyRaw(publicKey) {
    const jwk = await crypto.subtle.exportKey('jwk', publicKey);
    
    const x = base64UrlDecode(jwk.x);
    const y = base64UrlDecode(jwk.y);
    
    // Construct uncompressed point: 0x04 || x || y
    const raw = new Uint8Array(65);
    raw[0] = 0x04;
    raw.set(x, 1);
    raw.set(y, 33);
    
    return base64UrlEncode(raw);
}

/**
 * Export a key pair to storable format.
 * 
 * Returns JWK format which can be safely stored in localStorage/IndexedDB.
 * 
 * @param {Object} keyPair - The key pair object
 * @returns {Object} Storable key data
 */
export function exportKeyPairForStorage(keyPair) {
    return {
        publicKey: keyPair.publicKey.jwk,
        publicKeyRaw: keyPair.publicKey.raw,
        privateKey: keyPair.privateKey.jwk,
        type: keyPair.type,
        algorithm: keyPair.algorithm,
        curve: keyPair.curve,
        createdAt: Date.now(),
    };
}

// =============================================================================
// KEY IMPORT
// =============================================================================

/**
 * Import a public key from raw format.
 * 
 * @param {string} rawBase64Url - Base64URL encoded raw public key
 * @returns {Promise<CryptoKey>} Imported public key
 */
export async function importPublicKeyRaw(rawBase64Url) {
    const rawBytes = base64UrlDecode(rawBase64Url);
    
    // Validate format
    if (rawBytes.length !== 65) {
        throw new Error(`Invalid raw public key length: expected 65, got ${rawBytes.length}`);
    }
    if (rawBytes[0] !== 0x04) {
        throw new Error('Raw public key must start with 0x04 (uncompressed point)');
    }
    
    // Extract x and y coordinates
    const x = base64UrlEncode(rawBytes.slice(1, 33));
    const y = base64UrlEncode(rawBytes.slice(33, 65));
    
    const jwk = {
        kty: 'EC',
        crv: 'P-256',
        x: x,
        y: y,
    };
    
    return await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify']
    );
}

/**
 * Import a private key from JWK format.
 * 
 * @param {Object} jwk - JWK object with private key component (d)
 * @returns {Promise<CryptoKey>} Imported private key
 */
export async function importPrivateKeyJwk(jwk) {
    if (!jwk.d) {
        throw new Error('JWK is missing private key component (d)');
    }
    
    return await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false, // not extractable for security
        ['sign']
    );
}

/**
 * Import a public key from JWK format.
 * 
 * @param {Object} jwk - JWK object
 * @returns {Promise<CryptoKey>} Imported public key
 */
export async function importPublicKeyJwk(jwk) {
    const publicJwk = {
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y,
    };
    
    return await crypto.subtle.importKey(
        'jwk',
        publicJwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify']
    );
}

/**
 * Import a stored key pair back into CryptoKey objects.
 * 
 * @param {Object} storedData - Data from exportKeyPairForStorage
 * @returns {Promise<Object>} Restored key pair with CryptoKey objects
 */
export async function importStoredKeyPair(storedData) {
    const privateKey = await crypto.subtle.importKey(
        'jwk',
        storedData.privateKey,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign']
    );
    
    const publicKey = await crypto.subtle.importKey(
        'jwk',
        storedData.publicKey,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify']
    );
    
    return {
        publicKey: {
            jwk: storedData.publicKey,
            raw: storedData.publicKeyRaw,
            cryptoKey: publicKey,
        },
        privateKey: {
            jwk: storedData.privateKey,
            cryptoKey: privateKey,
        },
        type: storedData.type,
        algorithm: storedData.algorithm,
        curve: storedData.curve,
    };
}

// =============================================================================
// KEY STORAGE
// =============================================================================

const STORAGE_KEY = 'alacard_wallet_keys';

/**
 * Save wallet keys to localStorage.
 * 
 * SECURITY NOTE: localStorage is not the most secure storage.
 * In production, consider using:
 * - IndexedDB with encryption
 * - Secure enclave (when available)
 * - Hardware security keys
 * 
 * @param {Object} keyPair - The key pair to save
 */
export function saveWalletKeys(keyPair) {
    const data = exportKeyPairForStorage(keyPair);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
}

/**
 * Load wallet keys from localStorage.
 * 
 * @returns {Promise<Object|null>} Restored key pair or null if not found
 */
export async function loadWalletKeys() {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) {
        return null;
    }
    
    try {
        const data = JSON.parse(stored);
        return await importStoredKeyPair(data);
    } catch (e) {
        console.error('Failed to load wallet keys:', e);
        return null;
    }
}

/**
 * Clear wallet keys from storage.
 */
export function clearWalletKeys() {
    localStorage.removeItem(STORAGE_KEY);
}

/**
 * Check if wallet keys exist in storage.
 * 
 * @returns {boolean} True if keys exist
 */
export function hasWalletKeys() {
    return localStorage.getItem(STORAGE_KEY) !== null;
}
