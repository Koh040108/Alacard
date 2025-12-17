/**
 * AlaCard Cryptographic Utilities
 * 
 * Base64URL encoding and hashing utilities used throughout the system.
 * These are the foundational primitives that all other modules depend on.
 * 
 * Security Note: We use Base64URL (not Base64) because it's URL-safe and
 * avoids ambiguity in token transmission.
 */

const crypto = require('crypto');

// =============================================================================
// BASE64URL ENCODING
// =============================================================================

/**
 * Encode a Buffer to Base64URL string.
 * 
 * Why Base64URL instead of Base64?
 * - No '+' or '/' characters that could be misinterpreted in URLs
 * - No padding '=' characters that could cause issues in query strings
 * - Standard for JWS/JWT tokens (RFC 7515)
 * 
 * @param {Buffer} buffer - The buffer to encode
 * @returns {string} Base64URL encoded string
 */
function base64UrlEncode(buffer) {
    if (!Buffer.isBuffer(buffer)) {
        throw new Error('Input must be a Buffer');
    }
    return buffer
        .toString('base64')
        .replace(/\+/g, '-')    // Replace + with -
        .replace(/\//g, '_')    // Replace / with _
        .replace(/=+$/, '');    // Remove trailing =
}

/**
 * Decode a Base64URL string to Buffer.
 * 
 * @param {string} str - The Base64URL string to decode
 * @returns {Buffer} Decoded buffer
 */
function base64UrlDecode(str) {
    if (typeof str !== 'string') {
        throw new Error('Input must be a string');
    }
    
    // Restore standard Base64 characters
    let base64 = str
        .replace(/-/g, '+')
        .replace(/_/g, '/');
    
    // Add padding if necessary (Base64 requires length to be multiple of 4)
    const padding = (4 - (base64.length % 4)) % 4;
    base64 += '='.repeat(padding);
    
    return Buffer.from(base64, 'base64');
}

/**
 * Encode a JavaScript object to Base64URL JSON string.
 * 
 * @param {Object} obj - The object to encode
 * @returns {string} Base64URL encoded JSON string
 */
function base64UrlEncodeJson(obj) {
    const jsonString = JSON.stringify(obj);
    return base64UrlEncode(Buffer.from(jsonString, 'utf8'));
}

/**
 * Decode a Base64URL JSON string to JavaScript object.
 * 
 * @param {string} str - The Base64URL encoded JSON string
 * @returns {Object} Decoded object
 */
function base64UrlDecodeJson(str) {
    const buffer = base64UrlDecode(str);
    return JSON.parse(buffer.toString('utf8'));
}

// =============================================================================
// HASHING
// =============================================================================

/**
 * Compute SHA-256 hash of data.
 * 
 * Why SHA-256?
 * - Industry standard, widely audited
 * - 256-bit output provides 128-bit collision resistance
 * - Required by ECDSA P-256 (ES256) specification
 * 
 * @param {string|Buffer} data - Data to hash
 * @returns {Buffer} 32-byte hash
 */
function sha256(data) {
    return crypto.createHash('sha256').update(data).digest();
}

/**
 * Compute SHA-256 hash and return as Base64URL string.
 * 
 * @param {string|Buffer} data - Data to hash
 * @returns {string} Base64URL encoded hash
 */
function sha256Base64Url(data) {
    return base64UrlEncode(sha256(data));
}

/**
 * Compute SHA-256 hash and return as hex string.
 * Useful for audit logs and debugging.
 * 
 * @param {string|Buffer} data - Data to hash
 * @returns {string} Hex encoded hash
 */
function sha256Hex(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

// =============================================================================
// RANDOM GENERATION
// =============================================================================

/**
 * Generate cryptographically secure random bytes.
 * 
 * Why crypto.randomBytes?
 * - Uses OS CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
 * - Unpredictable output suitable for nonces and keys
 * - Math.random() is NOT suitable for security purposes
 * 
 * @param {number} length - Number of bytes to generate
 * @returns {Buffer} Random bytes
 */
function randomBytes(length) {
    if (!Number.isInteger(length) || length <= 0) {
        throw new Error('Length must be a positive integer');
    }
    return crypto.randomBytes(length);
}

/**
 * Generate a random nonce as Base64URL string.
 * 
 * Why 32 bytes?
 * - Provides 256 bits of entropy
 * - Statistically impossible to guess or collide
 * - Matches security level of SHA-256 and ECDSA P-256
 * 
 * @param {number} [length=32] - Number of random bytes
 * @returns {string} Base64URL encoded nonce
 */
function generateNonce(length = 32) {
    return base64UrlEncode(randomBytes(length));
}

// =============================================================================
// TIMESTAMP UTILITIES
// =============================================================================

/**
 * Get current Unix timestamp in seconds.
 * 
 * Why seconds instead of milliseconds?
 * - Standard for JWT/JWS tokens
 * - Reduces token size
 * - Sufficient precision for expiry checks
 * 
 * @returns {number} Current Unix timestamp in seconds
 */
function now() {
    return Math.floor(Date.now() / 1000);
}

/**
 * Check if a timestamp has expired.
 * 
 * @param {number} expiry - Unix timestamp in seconds
 * @returns {boolean} True if expired
 */
function isExpired(expiry) {
    return now() > expiry;
}

// =============================================================================
// CONSTANT-TIME COMPARISON
// =============================================================================

/**
 * Compare two buffers in constant time.
 * 
 * CRITICAL SECURITY: This prevents timing attacks.
 * 
 * Why constant-time comparison?
 * - Regular string comparison exits early on first mismatch
 * - An attacker can measure response time to guess correct bytes
 * - Constant-time comparison always takes the same time regardless of input
 * 
 * @param {Buffer} a - First buffer
 * @param {Buffer} b - Second buffer
 * @returns {boolean} True if buffers are equal
 */
function constantTimeEqual(a, b) {
    if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
        return false;
    }
    if (a.length !== b.length) {
        return false;
    }
    return crypto.timingSafeEqual(a, b);
}

/**
 * Compare two Base64URL strings in constant time.
 * 
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {boolean} True if strings represent equal data
 */
function constantTimeEqualBase64Url(a, b) {
    try {
        return constantTimeEqual(base64UrlDecode(a), base64UrlDecode(b));
    } catch {
        return false;
    }
}

// =============================================================================
// EXPORTS
// =============================================================================

module.exports = {
    // Base64URL
    base64UrlEncode,
    base64UrlDecode,
    base64UrlEncodeJson,
    base64UrlDecodeJson,
    
    // Hashing
    sha256,
    sha256Base64Url,
    sha256Hex,
    
    // Random
    randomBytes,
    generateNonce,
    
    // Time
    now,
    isExpired,
    
    // Comparison
    constantTimeEqual,
    constantTimeEqualBase64Url,
};
