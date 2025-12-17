/**
 * AlaCard Frontend Crypto - Main Entry Point
 * 
 * Re-exports all crypto functionality for easy import.
 */

// Utilities
export {
    base64UrlEncode,
    base64UrlDecode,
    base64UrlEncodeJson,
    base64UrlDecodeJson,
    sha256,
    sha256Base64Url,
    randomBytes,
    generateNonce,
    now,
    isExpired,
} from './utils.js';

// Key Management
export {
    generateWalletKeyPair,
    exportPublicKeyRaw,
    exportKeyPairForStorage,
    importPublicKeyRaw,
    importPrivateKeyJwk,
    importPublicKeyJwk,
    importStoredKeyPair,
    saveWalletKeys,
    loadWalletKeys,
    clearWalletKeys,
    hasWalletKeys,
} from './keys.js';

// Proof Generation
export {
    parseToken,
    hashToken,
    generateProof,
    serializeProof,
    serializeProofCompact,
    deserializeProof,
    isTokenExpired,
    getTokenExpiry,
    isTokenBoundToWallet,
    getTokenEligibility,
} from './proof.js';
