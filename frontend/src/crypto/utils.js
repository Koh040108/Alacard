/**
 * AlaCard Frontend Crypto Utilities
 * 
 * Browser-compatible cryptographic utilities using Web Crypto API.
 * Mirrors the backend utils.js but for browser environment.
 */

// =============================================================================
// BASE64URL ENCODING
// =============================================================================

/**
 * Encode an ArrayBuffer to Base64URL string.
 * 
 * @param {ArrayBuffer|Uint8Array} buffer - The buffer to encode
 * @returns {string} Base64URL encoded string
 */
export function base64UrlEncode(buffer) {
    const bytes = buffer instanceof ArrayBuffer 
        ? new Uint8Array(buffer) 
        : buffer;
    
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    
    return btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

/**
 * Decode a Base64URL string to Uint8Array.
 * 
 * @param {string} str - The Base64URL string to decode
 * @returns {Uint8Array} Decoded bytes
 */
export function base64UrlDecode(str) {
    let base64 = str
        .replace(/-/g, '+')
        .replace(/_/g, '/');
    
    const padding = (4 - (base64.length % 4)) % 4;
    base64 += '='.repeat(padding);
    
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    
    return bytes;
}

/**
 * Encode a JavaScript object to Base64URL JSON string.
 * 
 * @param {Object} obj - The object to encode
 * @returns {string} Base64URL encoded JSON string
 */
export function base64UrlEncodeJson(obj) {
    const jsonString = JSON.stringify(obj);
    const bytes = new TextEncoder().encode(jsonString);
    return base64UrlEncode(bytes);
}

/**
 * Decode a Base64URL JSON string to JavaScript object.
 * 
 * @param {string} str - The Base64URL encoded JSON string
 * @returns {Object} Decoded object
 */
export function base64UrlDecodeJson(str) {
    const bytes = base64UrlDecode(str);
    const jsonString = new TextDecoder().decode(bytes);
    return JSON.parse(jsonString);
}

// =============================================================================
// HASHING
// =============================================================================

/**
 * Compute SHA-256 hash of data.
 * 
 * @param {string|Uint8Array} data - Data to hash
 * @returns {Promise<Uint8Array>} 32-byte hash
 */
export async function sha256(data) {
    const bytes = typeof data === 'string' 
        ? new TextEncoder().encode(data)
        : data;
    
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
    return new Uint8Array(hashBuffer);
}

/**
 * Compute SHA-256 hash and return as Base64URL string.
 * 
 * @param {string|Uint8Array} data - Data to hash
 * @returns {Promise<string>} Base64URL encoded hash
 */
export async function sha256Base64Url(data) {
    const hash = await sha256(data);
    return base64UrlEncode(hash);
}

// =============================================================================
// RANDOM GENERATION
// =============================================================================

/**
 * Generate cryptographically secure random bytes.
 * 
 * @param {number} length - Number of bytes to generate
 * @returns {Uint8Array} Random bytes
 */
export function randomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
}

/**
 * Generate a random nonce as Base64URL string.
 * 
 * @param {number} [length=32] - Number of random bytes
 * @returns {string} Base64URL encoded nonce
 */
export function generateNonce(length = 32) {
    return base64UrlEncode(randomBytes(length));
}

// =============================================================================
// TIMESTAMP UTILITIES
// =============================================================================

/**
 * Get current Unix timestamp in seconds.
 * 
 * @returns {number} Current Unix timestamp in seconds
 */
export function now() {
    return Math.floor(Date.now() / 1000);
}

/**
 * Check if a timestamp has expired.
 * 
 * @param {number} expiry - Unix timestamp in seconds
 * @returns {boolean} True if expired
 */
export function isExpired(expiry) {
    return now() > expiry;
}
