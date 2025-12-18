/**
 * AlaCard Frontend Proof Generation
 * 
 * Browser-side proof generation using Web Crypto API.
 * 
 * This module is responsible for:
 * 1. Generating zero-knowledge proofs of token ownership
 * 2. Signing challenges with wallet private key
 * 
 * SECURITY: All cryptographic operations happen in the browser.
 * Private keys never leave the user's device.
 */

import {
    base64UrlEncode,
    base64UrlDecode,
    base64UrlEncodeJson,
    sha256Base64Url,
    now,
} from './utils.js';

// =============================================================================
// CONSTANTS
// =============================================================================

const PROOF_VERSION = '1';

// =============================================================================
// TOKEN PARSING
// =============================================================================

/**
 * Parse a token to extract its components.
 * 
 * WARNING: This does NOT verify the token signature!
 * Verification should be done by the backend/terminal.
 * 
 * @param {string} token - The serialized token
 * @returns {Object} Parsed token parts
 */
export function parseToken(token) {
    if (typeof token !== 'string') {
        throw new Error('Token must be a string');
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('Token must have exactly 3 parts');
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // Decode header
    const headerBytes = base64UrlDecode(headerB64);
    const header = JSON.parse(new TextDecoder().decode(headerBytes));

    // Decode payload
    const payloadBytes = base64UrlDecode(payloadB64);
    const payload = JSON.parse(new TextDecoder().decode(payloadBytes));

    return {
        header,
        payload,
        signatureB64,
        raw: { headerB64, payloadB64, signatureB64 },
    };
}

/**
 * Compute the hash of a token.
 * 
 * @param {string} token - The serialized token
 * @returns {Promise<string>} Base64URL encoded SHA-256 hash
 */
export async function hashToken(token) {
    return await sha256Base64Url(token);
}

// =============================================================================
// PROOF GENERATION
// =============================================================================

/**
 * Generate a zero-knowledge proof of token ownership.
 * 
 * The proof demonstrates:
 * 1. Possession of a valid token
 * 2. Ownership of the bound wallet (can sign with private key)
 * 3. Freshness (signed the terminal's nonce)
 * 
 * What's proven:
 * - "I have an eligibility token"
 * - "The token is bound to my wallet"
 * - "I own this wallet"
 * 
 * What's NOT revealed:
 * - IC number, name, income, or any personal data
 * 
 * @param {Object} options - Proof options
 * @param {string} options.token - The eligibility token
 * @param {string} options.nonce - The challenge nonce from terminal
 * @param {CryptoKey} options.walletPrivateKey - Wallet's private CryptoKey
 * @returns {Promise<Object>} Proof object
 */
export async function generateProof({ token, nonce, walletPrivateKey }) {
    // ==========================================================================
    // INPUT VALIDATION
    // ==========================================================================

    if (typeof token !== 'string' || token.length === 0) {
        throw new Error('token must be a non-empty string');
    }

    if (typeof nonce !== 'string' || nonce.length === 0) {
        throw new Error('nonce must be a non-empty string');
    }

    if (!walletPrivateKey || walletPrivateKey.type !== 'private') {
        throw new Error('walletPrivateKey must be a valid CryptoKey');
    }

    // ==========================================================================
    // BUILD PROOF MESSAGE
    // ==========================================================================

    const tokenHash = await hashToken(token);

    // Message format: nonce || tokenHash
    // Binds this proof to this specific token and challenge
    const message = `${nonce}.${tokenHash}`;
    const messageBytes = new TextEncoder().encode(message);

    // ==========================================================================
    // SIGN PROOF
    // Web Crypto outputs raw signature format directly (r || s, 64 bytes)
    // ==========================================================================

    const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        walletPrivateKey,
        messageBytes
    );

    // ==========================================================================
    // BUILD PROOF OBJECT
    // ==========================================================================

    const proof = {
        v: PROOF_VERSION,
        t: token,
        n: nonce,
        s: base64UrlEncode(new Uint8Array(signature)),
    };

    return proof;
}

/**
 * Serialize a proof to a compact JSON string.
 * 
 * @param {Object} proof - The proof object
 * @returns {string} JSON string (for easy copy/paste)
 */
export function serializeProof(proof) {
    return JSON.stringify(proof, null, 2);
}

/**
 * Serialize a proof to a compact Base64URL string.
 * 
 * @param {Object} proof - The proof object
 * @returns {string} Base64URL encoded proof
 */
export function serializeProofCompact(proof) {
    return base64UrlEncodeJson(proof);
}

/**
 * Deserialize a proof from JSON string.
 * 
 * @param {string} serialized - The serialized proof
 * @returns {Object} Proof object
 */
export function deserializeProof(serialized) {
    // Try JSON first (human-readable format)
    try {
        return JSON.parse(serialized);
    } catch {
        // Try Base64URL (compact format)
        const bytes = base64UrlDecode(serialized);
        return JSON.parse(new TextDecoder().decode(bytes));
    }
}

// =============================================================================
// TOKEN VERIFICATION HELPERS
// =============================================================================

/**
 * Check if a token has expired.
 * 
 * @param {string} token - The serialized token
 * @returns {boolean} True if token is expired
 */
export function isTokenExpired(token) {
    try {
        const { payload } = parseToken(token);
        return now() > payload.exp;
    } catch {
        return true; // Treat parse errors as expired
    }
}

/**
 * Get token expiry date.
 * 
 * @param {string} token - The serialized token
 * @returns {Date} Expiry date
 */
export function getTokenExpiry(token) {
    const { payload } = parseToken(token);
    return new Date(payload.exp * 1000);
}

/**
 * Check if a token is bound to a specific wallet.
 * 
 * @param {string} token - The serialized token
 * @param {string} walletPublicKeyRaw - Base64URL encoded raw public key
 * @returns {Promise<boolean>} True if token is bound to wallet
 */
export async function isTokenBoundToWallet(token, walletPublicKeyRaw) {
    try {
        const { payload } = parseToken(token);
        const expectedBinding = await sha256Base64Url(walletPublicKeyRaw);
        return payload.wbind === expectedBinding;
    } catch {
        return false;
    }
}

/**
 * Get eligibility status from token.
 * 
 * WARNING: This is UNVERIFIED. Always verify through the terminal.
 * 
 * @param {string} token - The serialized token
 * @returns {boolean} Eligibility status from token
 */
export function getTokenEligibility(token) {
    const { payload } = parseToken(token);
    return payload.elig === true;
}
