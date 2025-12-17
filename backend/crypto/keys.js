/**
 * AlaCard Key Generation Module
 * 
 * Generates ECDSA P-256 key pairs for:
 * 1. Government Issuer - Signs eligibility tokens
 * 2. Citizen Wallet - Proves token ownership
 * 
 * Why ECDSA P-256?
 * - Industry standard (NIST, FIPS 186-4)
 * - 128-bit security level (equivalent to RSA-3072)
 * - Compact signatures (64 bytes vs 256+ for RSA)
 * - Fast verification (important for terminal devices)
 * - Widely supported (Web Crypto API, Node.js crypto)
 */

const crypto = require('crypto');
const { base64UrlEncode, base64UrlDecode } = require('./utils');

// =============================================================================
// KEY PAIR GENERATION
// =============================================================================

/**
 * Generate an ECDSA P-256 key pair.
 * 
 * Returns keys in multiple formats for flexibility:
 * - PEM: Standard text format for storage
 * - JWK: JSON format for Web Crypto API interoperability
 * - Raw: Uncompressed public key bytes for compact serialization
 * 
 * @returns {Object} Key pair with publicKey and privateKey in various formats
 */
function generateKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',  // P-256 (also known as secp256r1)
    });
    
    // Export to PEM format (standard text format)
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    
    // Export to JWK format (JSON Web Key - for Web Crypto API compatibility)
    const publicKeyJwk = publicKey.export({ format: 'jwk' });
    const privateKeyJwk = privateKey.export({ format: 'jwk' });
    
    // Export raw public key (65 bytes: 0x04 || x || y)
    const publicKeyRaw = publicKey.export({ type: 'spki', format: 'der' });
    // The raw public key point starts at offset 26 in the SPKI DER encoding
    const publicKeyPoint = publicKeyRaw.slice(-65);
    
    return {
        publicKey: {
            pem: publicKeyPem,
            jwk: publicKeyJwk,
            raw: base64UrlEncode(publicKeyPoint),
            keyObject: publicKey,
        },
        privateKey: {
            pem: privateKeyPem,
            jwk: privateKeyJwk,
            keyObject: privateKey,
        },
    };
}

/**
 * Generate an issuer (government) key pair.
 * 
 * The issuer key is used to:
 * - Sign eligibility tokens
 * - Establish trust anchor for the entire system
 * 
 * Security Note: In production, this key should be stored in an HSM
 * and never leave secure hardware.
 * 
 * @returns {Object} Issuer key pair
 */
function generateIssuerKeyPair() {
    const keyPair = generateKeyPair();
    return {
        ...keyPair,
        type: 'issuer',
        algorithm: 'ES256',
        curve: 'P-256',
    };
}

/**
 * Generate a wallet (citizen) key pair.
 * 
 * The wallet key is used to:
 * - Bind tokens to a specific wallet (public key in token)
 * - Prove ownership via challenge-response (private key signs nonce)
 * 
 * Security Note: Private key should never leave the user's device.
 * 
 * @returns {Object} Wallet key pair
 */
function generateWalletKeyPair() {
    const keyPair = generateKeyPair();
    return {
        ...keyPair,
        type: 'wallet',
        algorithm: 'ES256',
        curve: 'P-256',
    };
}

// =============================================================================
// KEY IMPORT/EXPORT
// =============================================================================

/**
 * Import a public key from PEM format.
 * 
 * @param {string} pem - PEM encoded public key
 * @returns {crypto.KeyObject} Public key object
 */
function importPublicKeyPem(pem) {
    return crypto.createPublicKey({
        key: pem,
        format: 'pem',
    });
}

/**
 * Import a private key from PEM format.
 * 
 * @param {string} pem - PEM encoded private key
 * @returns {crypto.KeyObject} Private key object
 */
function importPrivateKeyPem(pem) {
    return crypto.createPrivateKey({
        key: pem,
        format: 'pem',
    });
}

/**
 * Import a public key from JWK format.
 * 
 * Why JWK?
 * - Native format for Web Crypto API
 * - Easy to serialize as JSON
 * - Self-describing (includes algorithm metadata)
 * 
 * @param {Object} jwk - JWK object
 * @returns {crypto.KeyObject} Public key object
 */
function importPublicKeyJwk(jwk) {
    // Ensure we only have public key components
    const publicJwk = {
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y,
    };
    return crypto.createPublicKey({ key: publicJwk, format: 'jwk' });
}

/**
 * Import a private key from JWK format.
 * 
 * @param {Object} jwk - JWK object with private key component (d)
 * @returns {crypto.KeyObject} Private key object
 */
function importPrivateKeyJwk(jwk) {
    if (!jwk.d) {
        throw new Error('JWK is missing private key component (d)');
    }
    return crypto.createPrivateKey({ key: jwk, format: 'jwk' });
}

/**
 * Import a public key from raw format (uncompressed point).
 * 
 * Raw format is 65 bytes: 0x04 || x (32 bytes) || y (32 bytes)
 * 
 * Why raw format?
 * - Most compact representation
 * - Easy to embed in tokens
 * - No metadata overhead
 * 
 * @param {string} rawBase64Url - Base64URL encoded raw public key
 * @returns {crypto.KeyObject} Public key object
 */
function importPublicKeyRaw(rawBase64Url) {
    const rawBytes = base64UrlDecode(rawBase64Url);
    
    // Validate raw key format
    if (rawBytes.length !== 65) {
        throw new Error(`Invalid raw public key length: expected 65, got ${rawBytes.length}`);
    }
    if (rawBytes[0] !== 0x04) {
        throw new Error('Raw public key must start with 0x04 (uncompressed point)');
    }
    
    // Convert raw bytes to JWK format for import
    const x = rawBytes.slice(1, 33);
    const y = rawBytes.slice(33, 65);
    
    const jwk = {
        kty: 'EC',
        crv: 'P-256',
        x: base64UrlEncode(x),
        y: base64UrlEncode(y),
    };
    
    return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

/**
 * Export a public key to raw format (uncompressed point).
 * 
 * @param {crypto.KeyObject} publicKey - Public key object
 * @returns {string} Base64URL encoded raw public key
 */
function exportPublicKeyRaw(publicKey) {
    const jwk = publicKey.export({ format: 'jwk' });
    const x = base64UrlDecode(jwk.x);
    const y = base64UrlDecode(jwk.y);
    
    // Construct uncompressed point: 0x04 || x || y
    const raw = Buffer.concat([Buffer.from([0x04]), x, y]);
    return base64UrlEncode(raw);
}

/**
 * Extract public key from private key.
 * 
 * Useful when you only have the private key stored.
 * 
 * @param {crypto.KeyObject} privateKey - Private key object
 * @returns {crypto.KeyObject} Corresponding public key object
 */
function getPublicKeyFromPrivate(privateKey) {
    return crypto.createPublicKey(privateKey);
}

// =============================================================================
// KEY VALIDATION
// =============================================================================

/**
 * Validate that a key is a P-256 public key.
 * 
 * Why validate?
 * - Prevents algorithm confusion attacks
 * - Ensures key is on the correct curve
 * - Fails fast on invalid input
 * 
 * @param {crypto.KeyObject} key - Key to validate
 * @returns {boolean} True if valid P-256 public key
 */
function isValidP256PublicKey(key) {
    try {
        if (key.type !== 'public') return false;
        if (key.asymmetricKeyType !== 'ec') return false;
        
        const jwk = key.export({ format: 'jwk' });
        if (jwk.crv !== 'P-256') return false;
        
        return true;
    } catch {
        return false;
    }
}

/**
 * Validate that a key is a P-256 private key.
 * 
 * @param {crypto.KeyObject} key - Key to validate
 * @returns {boolean} True if valid P-256 private key
 */
function isValidP256PrivateKey(key) {
    try {
        if (key.type !== 'private') return false;
        if (key.asymmetricKeyType !== 'ec') return false;
        
        const jwk = key.export({ format: 'jwk' });
        if (jwk.crv !== 'P-256') return false;
        if (!jwk.d) return false;
        
        return true;
    } catch {
        return false;
    }
}

// =============================================================================
// EXPORTS
// =============================================================================

module.exports = {
    // Generation
    generateKeyPair,
    generateIssuerKeyPair,
    generateWalletKeyPair,
    
    // Import
    importPublicKeyPem,
    importPrivateKeyPem,
    importPublicKeyJwk,
    importPrivateKeyJwk,
    importPublicKeyRaw,
    
    // Export
    exportPublicKeyRaw,
    getPublicKeyFromPrivate,
    
    // Validation
    isValidP256PublicKey,
    isValidP256PrivateKey,
};
