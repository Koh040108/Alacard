/**
 * AlaCard Proof Module
 * 
 * Implements challenge-response protocol for proving token ownership
 * without revealing any personal data.
 * 
 * Protocol Flow:
 * 1. Terminal generates random nonce (challenge)
 * 2. Wallet signs: nonce + tokenHash using wallet private key
 * 3. Terminal verifies signature using wallet public key from token
 * 
 * Why This Works:
 * - Only the wallet owner has the private key
 * - Token is bound to wallet public key
 * - Nonce prevents replay attacks
 * - No personal data is transmitted
 * 
 * This is a ZKP-style proof: proves "I own a valid eligibility token"
 * without revealing any identity information.
 */

const crypto = require('crypto');
const {
    base64UrlEncode,
    base64UrlDecode,
    base64UrlEncodeJson,
    base64UrlDecodeJson,
    sha256Base64Url,
    now,
    isExpired,
    generateNonce,
} = require('./utils');
const {
    importPublicKeyRaw,
    isValidP256PublicKey,
    isValidP256PrivateKey,
} = require('./keys');
const {
    verifyToken,
    derToRawSignature,
    rawToDerSignature,
    hashToken,
} = require('./token');

// =============================================================================
// CONSTANTS
// =============================================================================

// Nonce validity period: 5 minutes
// Why 5 minutes? Long enough for user to complete flow, short enough to prevent collection
const NONCE_VALIDITY_SECONDS = 5 * 60;

// Proof version for future compatibility
const PROOF_VERSION = '1';

// =============================================================================
// CHALLENGE GENERATION (Terminal Side)
// =============================================================================

/**
 * Generate a verification challenge (nonce).
 * 
 * The challenge includes:
 * - Random nonce (32 bytes = 256 bits of entropy)
 * - Timestamp for freshness validation
 * - Terminal ID for audit purposes
 * 
 * Why include timestamp?
 * - Allows terminal to reject stale proofs
 * - Prevents collection of signed nonces for later replay
 * 
 * @param {string} terminalId - Identifier of the terminal
 * @returns {Object} Challenge object
 */
function generateChallenge(terminalId) {
    if (typeof terminalId !== 'string' || terminalId.length === 0) {
        throw new Error('terminalId must be a non-empty string');
    }
    
    const challenge = {
        nonce: generateNonce(32),
        timestamp: now(),
        terminalId: terminalId,
        expiresAt: now() + NONCE_VALIDITY_SECONDS,
    };
    
    return challenge;
}

/**
 * Validate that a challenge is still fresh.
 * 
 * Why validate freshness?
 * - Prevents replay attacks using old challenges
 * - Limits window for man-in-the-middle attacks
 * 
 * @param {Object} challenge - The challenge object
 * @returns {boolean} True if challenge is still valid
 */
function isChallengeValid(challenge) {
    if (!challenge || typeof challenge !== 'object') {
        return false;
    }
    
    if (!challenge.nonce || !challenge.expiresAt) {
        return false;
    }
    
    return !isExpired(challenge.expiresAt);
}

// =============================================================================
// PROOF GENERATION (Wallet Side)
// =============================================================================

/**
 * Generate a zero-knowledge proof of token ownership.
 * 
 * The proof demonstrates:
 * 1. Possession of a valid token (includes token)
 * 2. Ownership of the wallet (signs with wallet private key)
 * 3. Freshness (signs the terminal's nonce)
 * 
 * What's proven:
 * - "I have an eligibility token signed by the government"
 * - "The token is bound to my wallet"
 * - "I own this wallet" (I can sign with its private key)
 * 
 * What's NOT revealed:
 * - My IC number
 * - My name
 * - My income
 * - Any other personal data
 * 
 * @param {Object} options - Proof options
 * @param {string} options.token - The eligibility token
 * @param {string} options.nonce - The challenge nonce from terminal
 * @param {crypto.KeyObject} options.walletPrivateKey - Wallet's private key
 * @returns {Object} Proof object
 */
function generateProof({ token, nonce, walletPrivateKey }) {
    // ==========================================================================
    // INPUT VALIDATION
    // ==========================================================================
    
    if (typeof token !== 'string' || token.length === 0) {
        throw new Error('token must be a non-empty string');
    }
    
    if (typeof nonce !== 'string' || nonce.length === 0) {
        throw new Error('nonce must be a non-empty string');
    }
    
    if (!isValidP256PrivateKey(walletPrivateKey)) {
        throw new Error('walletPrivateKey must be a valid P-256 private key');
    }
    
    // ==========================================================================
    // BUILD PROOF MESSAGE
    // The message binds the nonce to this specific token
    // ==========================================================================
    
    const tokenHash = hashToken(token);
    
    // Message format: nonce || tokenHash
    // Why include tokenHash? Binds this proof to this specific token
    // Prevents using same signature with a different token
    const message = `${nonce}.${tokenHash}`;
    
    // ==========================================================================
    // SIGN PROOF
    // ==========================================================================
    
    const signature = crypto.sign(
        'sha256',
        Buffer.from(message, 'utf8'),
        walletPrivateKey
    );
    
    // Convert to raw signature format
    const rawSignature = derToRawSignature(signature);
    
    // ==========================================================================
    // BUILD PROOF OBJECT
    // ==========================================================================
    
    const proof = {
        version: PROOF_VERSION,
        
        // The token (contains eligibility claim)
        token: token,
        
        // The challenge nonce (proves freshness)
        nonce: nonce,
        
        // Hash of token (for quick lookup/audit)
        tokenHash: tokenHash,
        
        // Signature proving wallet ownership
        signature: base64UrlEncode(rawSignature),
        
        // Timestamp of proof generation
        timestamp: now(),
    };
    
    return proof;
}

/**
 * Serialize a proof to a compact string format.
 * 
 * @param {Object} proof - The proof object
 * @returns {string} Base64URL encoded proof
 */
function serializeProof(proof) {
    return base64UrlEncodeJson(proof);
}

/**
 * Deserialize a proof from string format.
 * 
 * @param {string} serialized - The serialized proof
 * @returns {Object} Proof object
 */
function deserializeProof(serialized) {
    return base64UrlDecodeJson(serialized);
}

// =============================================================================
// PROOF VERIFICATION (Terminal Side)
// =============================================================================

/**
 * Verify a zero-knowledge proof of eligibility.
 * 
 * Verification steps (in order):
 * 1. Validate proof structure
 * 2. Validate nonce freshness (prevents replay)
 * 3. Verify token signature (ensures government issued it)
 * 4. Extract wallet public key from token
 * 5. Verify proof signature (ensures wallet owner)
 * 6. Check eligibility claim
 * 
 * FAIL CLOSED: Any check failure results in rejection.
 * 
 * @param {Object} options - Verification options
 * @param {Object} options.proof - The proof object
 * @param {Object} options.challenge - The original challenge
 * @param {crypto.KeyObject} options.issuerPublicKey - Government's public key
 * @returns {Object} Verification result
 */
function verifyProof({ proof, challenge, issuerPublicKey }) {
    // ==========================================================================
    // PROOF STRUCTURE VALIDATION
    // Why: Reject malformed proofs before any crypto operations
    // ==========================================================================
    
    if (!proof || typeof proof !== 'object') {
        return { valid: false, error: 'Proof must be an object' };
    }
    
    const requiredFields = ['version', 'token', 'nonce', 'tokenHash', 'signature'];
    for (const field of requiredFields) {
        if (!proof[field]) {
            return { valid: false, error: `Proof missing required field: ${field}` };
        }
    }
    
    // ==========================================================================
    // NONCE VALIDATION
    // Why: Prevents replay attacks
    // An attacker cannot reuse a captured proof with a different nonce
    // ==========================================================================
    
    if (!challenge || typeof challenge !== 'object') {
        return { valid: false, error: 'Challenge must be an object' };
    }
    
    // Check nonce matches
    if (proof.nonce !== challenge.nonce) {
        return { 
            valid: false, 
            error: 'Nonce mismatch: proof was generated for a different challenge' 
        };
    }
    
    // Check challenge hasn't expired
    // Why? Limits time window for man-in-the-middle attacks
    if (!isChallengeValid(challenge)) {
        return { valid: false, error: 'Challenge has expired' };
    }
    
    // ==========================================================================
    // TOKEN VERIFICATION
    // Why: Ensures token was actually signed by the government
    // This is the trust anchor of the entire system
    // ==========================================================================
    
    const tokenResult = verifyToken(proof.token, issuerPublicKey);
    
    if (!tokenResult.valid) {
        return { 
            valid: false, 
            error: `Token verification failed: ${tokenResult.error}` 
        };
    }
    
    // Verify tokenHash matches
    // Why? Ensures proof is bound to this specific token
    const expectedTokenHash = hashToken(proof.token);
    if (proof.tokenHash !== expectedTokenHash) {
        return { valid: false, error: 'Token hash mismatch' };
    }
    
    // ==========================================================================
    // EXTRACT WALLET PUBLIC KEY
    // Why: Need to verify the wallet signature
    // The public key is embedded in the token (bound at issuance)
    // ==========================================================================
    
    let walletPublicKey;
    try {
        walletPublicKey = importPublicKeyRaw(tokenResult.payload.wpub);
    } catch (e) {
        return { valid: false, error: `Invalid wallet public key in token: ${e.message}` };
    }
    
    // ==========================================================================
    // WALLET SIGNATURE VERIFICATION
    // Why: Proves the proof generator owns the wallet
    // Only the wallet owner can produce a valid signature
    // ==========================================================================
    
    let rawSignature;
    try {
        rawSignature = base64UrlDecode(proof.signature);
    } catch (e) {
        return { valid: false, error: 'Invalid signature encoding' };
    }
    
    if (rawSignature.length !== 64) {
        return { valid: false, error: 'Invalid signature length' };
    }
    
    // Reconstruct the signed message
    const message = `${proof.nonce}.${proof.tokenHash}`;
    
    // Convert raw signature to DER for verification
    const derSignature = rawToDerSignature(rawSignature);
    
    const signatureValid = crypto.verify(
        'sha256',
        Buffer.from(message, 'utf8'),
        walletPublicKey,
        derSignature
    );
    
    if (!signatureValid) {
        return { 
            valid: false, 
            error: 'Wallet signature verification failed: proof generator does not own wallet' 
        };
    }
    
    // ==========================================================================
    // SUCCESS
    // At this point we have verified:
    // 1. Token was signed by government (issuerPublicKey)
    // 2. Token is not expired
    // 3. Proof was signed by wallet owner (walletPrivateKey)
    // 4. Nonce is fresh (not a replay)
    // 5. Proof is bound to this specific token
    // ==========================================================================
    
    return {
        valid: true,
        eligible: tokenResult.payload.elig,
        tokenHash: proof.tokenHash,
        issuerId: tokenResult.payload.iss,
        tokenExpiry: tokenResult.payload.exp,
        verifiedAt: now(),
        // Include wallet binding for audit
        walletBinding: tokenResult.payload.wbind,
    };
}

// =============================================================================
// NONCE STORE (For replay protection)
// =============================================================================

/**
 * Simple in-memory nonce store for replay protection.
 * 
 * In production, this should be:
 * - Persistent (Redis, database)
 * - Distributed (if multiple terminals)
 * - TTL-based cleanup
 * 
 * Why track used nonces?
 * - Even with expiry, an attacker could replay within the window
 * - Marking nonces as used prevents any replay
 */
class NonceStore {
    constructor() {
        this.usedNonces = new Map();
        this.challenges = new Map();
    }
    
    /**
     * Store a new challenge.
     * 
     * @param {string} nonce - The nonce
     * @param {Object} challenge - The full challenge object
     */
    storeChallenge(nonce, challenge) {
        this.challenges.set(nonce, challenge);
    }
    
    /**
     * Get a stored challenge.
     * 
     * @param {string} nonce - The nonce
     * @returns {Object|null} The challenge or null
     */
    getChallenge(nonce) {
        return this.challenges.get(nonce) || null;
    }
    
    /**
     * Mark a nonce as used (consumed).
     * 
     * Why mark as used?
     * - Prevents replay attacks within the validity window
     * - Each nonce can only be used once
     * 
     * @param {string} nonce - The nonce to mark
     * @returns {boolean} True if nonce was valid and unused
     */
    consumeNonce(nonce) {
        // Check if already used
        if (this.usedNonces.has(nonce)) {
            return false;
        }
        
        // Check if challenge exists
        const challenge = this.challenges.get(nonce);
        if (!challenge) {
            return false;
        }
        
        // Check if expired
        if (!isChallengeValid(challenge)) {
            return false;
        }
        
        // Mark as used
        this.usedNonces.set(nonce, now());
        this.challenges.delete(nonce);
        
        return true;
    }
    
    /**
     * Check if a nonce has been used.
     * 
     * @param {string} nonce - The nonce to check
     * @returns {boolean} True if nonce has been used
     */
    isNonceUsed(nonce) {
        return this.usedNonces.has(nonce);
    }
    
    /**
     * Clean up expired entries.
     * Should be called periodically in production.
     */
    cleanup() {
        const currentTime = now();
        
        // Clean expired challenges
        for (const [nonce, challenge] of this.challenges) {
            if (!isChallengeValid(challenge)) {
                this.challenges.delete(nonce);
            }
        }
        
        // Clean old used nonces (keep for 1 hour after expiry)
        const maxAge = NONCE_VALIDITY_SECONDS + 3600;
        for (const [nonce, usedAt] of this.usedNonces) {
            if (currentTime - usedAt > maxAge) {
                this.usedNonces.delete(nonce);
            }
        }
    }
}

// =============================================================================
// EXPORTS
// =============================================================================

module.exports = {
    // Challenge
    generateChallenge,
    isChallengeValid,
    
    // Proof
    generateProof,
    serializeProof,
    deserializeProof,
    verifyProof,
    
    // Nonce management
    NonceStore,
    
    // Constants
    NONCE_VALIDITY_SECONDS,
    PROOF_VERSION,
};
