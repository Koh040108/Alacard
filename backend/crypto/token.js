/**
 * AlaCard Token Module
 * 
 * Handles creation, signing, and verification of eligibility tokens.
 * 
 * Token Structure (similar to JWT but minimal):
 * BASE64URL(header).BASE64URL(payload).BASE64URL(signature)
 * 
 * Design Principles:
 * 1. NO PERSONAL DATA - Token contains only eligibility status and binding
 * 2. WALLET BINDING - Token is bound to a specific wallet public key
 * 3. EXPIRY - Tokens have limited validity to force periodic re-verification
 * 4. FAIL CLOSED - Any verification failure results in rejection
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
} = require('./utils');
const {
    importPublicKeyPem,
    importPrivateKeyPem,
    importPublicKeyRaw,
    isValidP256PublicKey,
    isValidP256PrivateKey,
} = require('./keys');

// =============================================================================
// CONSTANTS
// =============================================================================

// Token version for future compatibility
const TOKEN_VERSION = '1';

// Default token validity period: 30 days
const DEFAULT_TOKEN_VALIDITY_SECONDS = 30 * 24 * 60 * 60;

// Algorithm identifier (matches JWT alg)
const ALGORITHM = 'ES256';

// =============================================================================
// TOKEN CREATION
// =============================================================================

/**
 * Create a signed eligibility token.
 * 
 * The token structure:
 * - Header: Algorithm and version metadata
 * - Payload: Eligibility data bound to wallet public key
 * - Signature: ECDSA signature over header.payload
 * 
 * CRITICAL: The payload contains NO personal data.
 * - No IC number
 * - No name
 * - No income
 * - Only: eligible (bool), wallet binding, expiry, issuer ID
 * 
 * @param {Object} options - Token options
 * @param {boolean} options.eligible - Whether citizen is eligible
 * @param {string} options.walletPublicKey - Base64URL raw public key to bind token to
 * @param {string} options.issuerId - Identifier of the issuing authority
 * @param {crypto.KeyObject} options.issuerPrivateKey - Issuer's private key for signing
 * @param {number} [options.validitySeconds] - Token validity in seconds
 * @param {string} [options.tokenId] - Optional unique token identifier
 * @returns {Object} Token object with serialized token and metadata
 */
function createToken({
    eligible,
    walletPublicKey,
    issuerId,
    issuerPrivateKey,
    validitySeconds = DEFAULT_TOKEN_VALIDITY_SECONDS,
    tokenId = null,
}) {
    // ==========================================================================
    // INPUT VALIDATION
    // Why: Fail fast on invalid input before any cryptographic operations
    // ==========================================================================
    
    if (typeof eligible !== 'boolean') {
        throw new Error('eligible must be a boolean');
    }
    
    if (typeof walletPublicKey !== 'string' || walletPublicKey.length === 0) {
        throw new Error('walletPublicKey must be a non-empty string');
    }
    
    // Validate wallet public key format by attempting to import it
    try {
        const importedKey = importPublicKeyRaw(walletPublicKey);
        if (!isValidP256PublicKey(importedKey)) {
            throw new Error('Invalid key type');
        }
    } catch (e) {
        throw new Error(`Invalid walletPublicKey: ${e.message}`);
    }
    
    if (typeof issuerId !== 'string' || issuerId.length === 0) {
        throw new Error('issuerId must be a non-empty string');
    }
    
    if (!isValidP256PrivateKey(issuerPrivateKey)) {
        throw new Error('issuerPrivateKey must be a valid P-256 private key');
    }
    
    // ==========================================================================
    // BUILD TOKEN
    // ==========================================================================
    
    const currentTime = now();
    
    // Header contains algorithm metadata
    const header = {
        alg: ALGORITHM,
        typ: 'ELIGIBILITY',
        ver: TOKEN_VERSION,
    };
    
    // Payload contains eligibility claim bound to wallet
    const payload = {
        // Eligibility status (the core claim)
        elig: eligible,
        
        // Wallet binding: hash of public key
        // Why hash instead of full key? Smaller payload, still uniquely identifies wallet
        wbind: sha256Base64Url(walletPublicKey),
        
        // Full wallet public key (needed for proof verification)
        wpub: walletPublicKey,
        
        // Issuer identifier
        iss: issuerId,
        
        // Issued at timestamp
        iat: currentTime,
        
        // Expiration timestamp
        // Why expiry? Forces periodic re-verification of eligibility
        exp: currentTime + validitySeconds,
        
        // Unique token ID (for revocation checking)
        jti: tokenId || crypto.randomUUID(),
    };
    
    // ==========================================================================
    // SIGN TOKEN
    // ==========================================================================
    
    const headerB64 = base64UrlEncodeJson(header);
    const payloadB64 = base64UrlEncodeJson(payload);
    
    // The signed message is header.payload (same as JWS)
    const signingInput = `${headerB64}.${payloadB64}`;
    
    // Sign with ECDSA P-256 (SHA-256 hash is implicit)
    const signature = crypto.sign(
        'sha256',
        Buffer.from(signingInput, 'utf8'),
        issuerPrivateKey
    );
    
    // Convert DER signature to raw format (64 bytes: r || s)
    // Why raw format? Smaller, simpler, matches Web Crypto output
    const rawSignature = derToRawSignature(signature);
    const signatureB64 = base64UrlEncode(rawSignature);
    
    // Final token format: header.payload.signature
    const token = `${headerB64}.${payloadB64}.${signatureB64}`;
    
    return {
        token,
        header,
        payload,
        tokenHash: sha256Base64Url(token),
    };
}

/**
 * Convert DER-encoded ECDSA signature to raw format.
 * 
 * DER format: SEQUENCE { INTEGER r, INTEGER s }
 * Raw format: r (32 bytes) || s (32 bytes)
 * 
 * Why convert?
 * - Node.js crypto outputs DER format
 * - Web Crypto API uses raw format
 * - Raw is more compact (64 bytes vs 70-72 for DER)
 * 
 * @param {Buffer} derSignature - DER encoded signature
 * @returns {Buffer} Raw signature (64 bytes)
 */
function derToRawSignature(derSignature) {
    // Parse DER structure
    if (derSignature[0] !== 0x30) {
        throw new Error('Invalid DER signature: missing SEQUENCE tag');
    }
    
    let offset = 2; // Skip SEQUENCE tag and length
    
    // Parse r
    if (derSignature[offset] !== 0x02) {
        throw new Error('Invalid DER signature: missing INTEGER tag for r');
    }
    offset++;
    const rLength = derSignature[offset++];
    let r = derSignature.slice(offset, offset + rLength);
    offset += rLength;
    
    // Parse s
    if (derSignature[offset] !== 0x02) {
        throw new Error('Invalid DER signature: missing INTEGER tag for s');
    }
    offset++;
    const sLength = derSignature[offset++];
    let s = derSignature.slice(offset, offset + sLength);
    
    // Normalize r and s to exactly 32 bytes each
    // Why? Integers may have leading zeros or be shorter than 32 bytes
    r = normalizeInteger(r, 32);
    s = normalizeInteger(s, 32);
    
    return Buffer.concat([r, s]);
}

/**
 * Convert raw signature to DER format.
 * 
 * @param {Buffer} rawSignature - Raw signature (64 bytes)
 * @returns {Buffer} DER encoded signature
 */
function rawToDerSignature(rawSignature) {
    if (rawSignature.length !== 64) {
        throw new Error(`Invalid raw signature length: expected 64, got ${rawSignature.length}`);
    }
    
    let r = rawSignature.slice(0, 32);
    let s = rawSignature.slice(32, 64);
    
    // Remove leading zeros but ensure positive (add 0x00 if high bit set)
    r = encodeInteger(r);
    s = encodeInteger(s);
    
    // Build DER structure
    const sequence = Buffer.concat([
        Buffer.from([0x02, r.length]),
        r,
        Buffer.from([0x02, s.length]),
        s,
    ]);
    
    return Buffer.concat([
        Buffer.from([0x30, sequence.length]),
        sequence,
    ]);
}

/**
 * Normalize an integer to exactly the specified length.
 * 
 * @param {Buffer} buf - Integer buffer
 * @param {number} length - Target length
 * @returns {Buffer} Normalized buffer
 */
function normalizeInteger(buf, length) {
    // Remove leading zeros (except one if high bit is set in first non-zero byte)
    while (buf.length > length && buf[0] === 0x00) {
        buf = buf.slice(1);
    }
    
    // Pad with zeros if too short
    if (buf.length < length) {
        buf = Buffer.concat([Buffer.alloc(length - buf.length), buf]);
    }
    
    return buf;
}

/**
 * Encode an integer for DER format.
 * 
 * @param {Buffer} buf - Integer buffer
 * @returns {Buffer} DER-encoded integer
 */
function encodeInteger(buf) {
    // Remove leading zeros
    let start = 0;
    while (start < buf.length - 1 && buf[start] === 0x00) {
        start++;
    }
    buf = buf.slice(start);
    
    // Add leading zero if high bit is set (to keep number positive)
    if (buf[0] & 0x80) {
        buf = Buffer.concat([Buffer.from([0x00]), buf]);
    }
    
    return buf;
}

// =============================================================================
// TOKEN VERIFICATION
// =============================================================================

/**
 * Verify a token's signature and validity.
 * 
 * This function performs ALL security checks:
 * 1. Structure validation
 * 2. Algorithm validation (prevent algorithm confusion)
 * 3. Signature verification
 * 4. Expiry check
 * 5. Wallet binding check (optional, if wallet key provided)
 * 
 * FAIL CLOSED: Any check failure results in rejection.
 * 
 * @param {string} token - The serialized token
 * @param {crypto.KeyObject} issuerPublicKey - Issuer's public key
 * @param {Object} [options] - Verification options
 * @param {string} [options.expectedWalletPublicKey] - Expected wallet public key
 * @param {boolean} [options.checkExpiry=true] - Whether to check expiry
 * @returns {Object} Verification result with parsed payload
 */
function verifyToken(token, issuerPublicKey, options = {}) {
    const { expectedWalletPublicKey = null, checkExpiry = true } = options;
    
    // ==========================================================================
    // STRUCTURE VALIDATION
    // Why: Reject malformed tokens before any crypto operations
    // ==========================================================================
    
    if (typeof token !== 'string') {
        return { valid: false, error: 'Token must be a string' };
    }
    
    const parts = token.split('.');
    if (parts.length !== 3) {
        return { valid: false, error: 'Token must have exactly 3 parts' };
    }
    
    const [headerB64, payloadB64, signatureB64] = parts;
    
    // ==========================================================================
    // DECODE HEADER AND PAYLOAD
    // ==========================================================================
    
    let header, payload;
    try {
        header = base64UrlDecodeJson(headerB64);
    } catch (e) {
        return { valid: false, error: 'Invalid header encoding' };
    }
    
    try {
        payload = base64UrlDecodeJson(payloadB64);
    } catch (e) {
        return { valid: false, error: 'Invalid payload encoding' };
    }
    
    // ==========================================================================
    // ALGORITHM VALIDATION
    // Why: Prevent algorithm confusion attacks (e.g., "none" algorithm)
    // This is a CRITICAL security check
    // ==========================================================================
    
    if (header.alg !== ALGORITHM) {
        return { 
            valid: false, 
            error: `Invalid algorithm: expected ${ALGORITHM}, got ${header.alg}` 
        };
    }
    
    if (header.typ !== 'ELIGIBILITY') {
        return { valid: false, error: 'Invalid token type' };
    }
    
    // ==========================================================================
    // SIGNATURE VERIFICATION
    // Why: Ensures token was signed by the issuer
    // This is the PRIMARY security check
    // ==========================================================================
    
    if (!isValidP256PublicKey(issuerPublicKey)) {
        return { valid: false, error: 'Invalid issuer public key' };
    }
    
    let rawSignature;
    try {
        rawSignature = base64UrlDecode(signatureB64);
    } catch (e) {
        return { valid: false, error: 'Invalid signature encoding' };
    }
    
    if (rawSignature.length !== 64) {
        return { valid: false, error: 'Invalid signature length' };
    }
    
    // Convert raw signature to DER for Node.js crypto
    const derSignature = rawToDerSignature(rawSignature);
    
    const signingInput = `${headerB64}.${payloadB64}`;
    const signatureValid = crypto.verify(
        'sha256',
        Buffer.from(signingInput, 'utf8'),
        issuerPublicKey,
        derSignature
    );
    
    if (!signatureValid) {
        return { valid: false, error: 'Signature verification failed' };
    }
    
    // ==========================================================================
    // EXPIRY CHECK
    // Why: Tokens should not be valid forever
    // Forces periodic re-verification of eligibility status
    // ==========================================================================
    
    if (checkExpiry) {
        if (typeof payload.exp !== 'number') {
            return { valid: false, error: 'Token missing expiry' };
        }
        
        if (isExpired(payload.exp)) {
            return { valid: false, error: 'Token has expired' };
        }
    }
    
    // ==========================================================================
    // WALLET BINDING CHECK (Optional)
    // Why: Ensures token belongs to the expected wallet
    // Prevents stolen token usage
    // ==========================================================================
    
    if (expectedWalletPublicKey !== null) {
        const expectedBinding = sha256Base64Url(expectedWalletPublicKey);
        if (payload.wbind !== expectedBinding) {
            return { valid: false, error: 'Token not bound to expected wallet' };
        }
    }
    
    // ==========================================================================
    // SUCCESS
    // ==========================================================================
    
    return {
        valid: true,
        header,
        payload,
        tokenHash: sha256Base64Url(token),
    };
}

/**
 * Parse a token without verification.
 * 
 * WARNING: This does NOT verify the signature!
 * Use only for inspection purposes, never for authorization.
 * 
 * @param {string} token - The serialized token
 * @returns {Object} Parsed token parts
 */
function parseToken(token) {
    if (typeof token !== 'string') {
        throw new Error('Token must be a string');
    }
    
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('Token must have exactly 3 parts');
    }
    
    const [headerB64, payloadB64, signatureB64] = parts;
    
    return {
        header: base64UrlDecodeJson(headerB64),
        payload: base64UrlDecodeJson(payloadB64),
        signatureB64,
        tokenHash: sha256Base64Url(token),
        // Warning flag to remind developers this is unverified
        _unverified: true,
    };
}

/**
 * Compute the hash of a token.
 * 
 * Used for audit logs and revocation checking.
 * The hash uniquely identifies the token without revealing its contents.
 * 
 * @param {string} token - The serialized token
 * @returns {string} Base64URL encoded SHA-256 hash
 */
function hashToken(token) {
    return sha256Base64Url(token);
}

// =============================================================================
// EXPORTS
// =============================================================================

module.exports = {
    // Creation
    createToken,
    
    // Verification
    verifyToken,
    parseToken,
    hashToken,
    
    // Signature conversion (exported for frontend compatibility)
    derToRawSignature,
    rawToDerSignature,
    
    // Constants
    TOKEN_VERSION,
    ALGORITHM,
    DEFAULT_TOKEN_VALIDITY_SECONDS,
};
