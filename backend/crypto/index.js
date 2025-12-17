/**
 * AlaCard Cryptographic Core - Main Entry Point
 * 
 * This module provides the complete cryptographic foundation for the
 * AlaCard privacy-preserving eligibility verification system.
 * 
 * ARCHITECTURE OVERVIEW:
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                    GOVERNMENT ISSUER                            │
 * │  ┌───────────────┐     ┌───────────────┐                       │
 * │  │ Issuer Keys   │────▶│ Sign Token    │                       │
 * │  │ (P-256)       │     │ (ECDSA)       │                       │
 * │  └───────────────┘     └───────┬───────┘                       │
 * └────────────────────────────────┼────────────────────────────────┘
 *                                  │ Token (signed)
 *                                  ▼
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                    CITIZEN WALLET                               │
 * │  ┌───────────────┐     ┌───────────────┐     ┌───────────────┐ │
 * │  │ Wallet Keys   │     │ Store Token   │     │ Generate      │ │
 * │  │ (P-256)       │────▶│ (bound to     │────▶│ Proof         │ │
 * │  └───────────────┘     │ wallet key)   │     │ (signs nonce) │ │
 * │                        └───────────────┘     └───────┬───────┘ │
 * └──────────────────────────────────────────────────────┼──────────┘
 *                                                        │ Proof
 *                                                        ▼
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                    VERIFICATION TERMINAL                        │
 * │  ┌───────────────┐     ┌───────────────┐     ┌───────────────┐ │
 * │  │ Generate      │     │ Verify        │     │ Verify        │ │
 * │  │ Nonce         │────▶│ Token Sig     │────▶│ Proof Sig     │ │
 * │  │ (challenge)   │     │ (issuer key)  │     │ (wallet key)  │ │
 * │  └───────────────┘     └───────────────┘     └───────┬───────┘ │
 * │                                                      │         │
 * │                                              ┌───────▼───────┐ │
 * │                                              │ ELIGIBLE/NOT  │ │
 * │                                              └───────────────┘ │
 * └─────────────────────────────────────────────────────────────────┘
 * 
 * SECURITY PROPERTIES:
 * 
 * 1. AUTHENTICITY: Tokens are signed by the government issuer
 *    - Only the government can create valid tokens
 *    - Terminals verify signature using issuer's public key
 * 
 * 2. BINDING: Tokens are bound to a specific wallet
 *    - Token contains hash of wallet public key
 *    - Prevents token transfer to other wallets
 * 
 * 3. OWNERSHIP PROOF: Wallet proves ownership via challenge-response
 *    - Terminal generates random nonce (challenge)
 *    - Wallet signs nonce with private key
 *    - Terminal verifies signature with public key from token
 * 
 * 4. REPLAY PROTECTION: Nonces are single-use
 *    - Each nonce can only be used once
 *    - Nonces expire after 5 minutes
 * 
 * 5. PRIVACY: No personal data is revealed
 *    - Token contains only eligibility status
 *    - No IC, name, income, or other PII
 *    - Terminal learns only: eligible or not
 * 
 * CRYPTOGRAPHIC PRIMITIVES:
 * - ECDSA P-256 (ES256) for signatures
 * - SHA-256 for hashing
 * - CSPRNG for nonce generation
 * - Base64URL for encoding
 */

// =============================================================================
// UTILITIES
// =============================================================================

const utils = require('./utils');

// =============================================================================
// KEY MANAGEMENT
// =============================================================================

const keys = require('./keys');

// =============================================================================
// TOKEN OPERATIONS
// =============================================================================

const token = require('./token');

// =============================================================================
// PROOF OPERATIONS
// =============================================================================

const proof = require('./proof');

// =============================================================================
// CONVENIENCE EXPORTS
// =============================================================================

module.exports = {
    // =========================================================================
    // UTILITIES
    // =========================================================================
    
    // Base64URL encoding
    base64UrlEncode: utils.base64UrlEncode,
    base64UrlDecode: utils.base64UrlDecode,
    base64UrlEncodeJson: utils.base64UrlEncodeJson,
    base64UrlDecodeJson: utils.base64UrlDecodeJson,
    
    // Hashing
    sha256: utils.sha256,
    sha256Base64Url: utils.sha256Base64Url,
    sha256Hex: utils.sha256Hex,
    
    // Random
    randomBytes: utils.randomBytes,
    generateNonce: utils.generateNonce,
    
    // Time
    now: utils.now,
    isExpired: utils.isExpired,
    
    // Comparison
    constantTimeEqual: utils.constantTimeEqual,
    constantTimeEqualBase64Url: utils.constantTimeEqualBase64Url,
    
    // =========================================================================
    // KEY MANAGEMENT
    // =========================================================================
    
    // Generation
    generateKeyPair: keys.generateKeyPair,
    generateIssuerKeyPair: keys.generateIssuerKeyPair,
    generateWalletKeyPair: keys.generateWalletKeyPair,
    
    // Import
    importPublicKeyPem: keys.importPublicKeyPem,
    importPrivateKeyPem: keys.importPrivateKeyPem,
    importPublicKeyJwk: keys.importPublicKeyJwk,
    importPrivateKeyJwk: keys.importPrivateKeyJwk,
    importPublicKeyRaw: keys.importPublicKeyRaw,
    
    // Export
    exportPublicKeyRaw: keys.exportPublicKeyRaw,
    getPublicKeyFromPrivate: keys.getPublicKeyFromPrivate,
    
    // Validation
    isValidP256PublicKey: keys.isValidP256PublicKey,
    isValidP256PrivateKey: keys.isValidP256PrivateKey,
    
    // =========================================================================
    // TOKEN OPERATIONS
    // =========================================================================
    
    // Creation
    createToken: token.createToken,
    
    // Verification
    verifyToken: token.verifyToken,
    parseToken: token.parseToken,
    hashToken: token.hashToken,
    
    // Signature conversion
    derToRawSignature: token.derToRawSignature,
    rawToDerSignature: token.rawToDerSignature,
    
    // Constants
    TOKEN_VERSION: token.TOKEN_VERSION,
    TOKEN_ALGORITHM: token.ALGORITHM,
    DEFAULT_TOKEN_VALIDITY_SECONDS: token.DEFAULT_TOKEN_VALIDITY_SECONDS,
    
    // =========================================================================
    // PROOF OPERATIONS
    // =========================================================================
    
    // Challenge
    generateChallenge: proof.generateChallenge,
    isChallengeValid: proof.isChallengeValid,
    
    // Proof
    generateProof: proof.generateProof,
    serializeProof: proof.serializeProof,
    deserializeProof: proof.deserializeProof,
    verifyProof: proof.verifyProof,
    
    // Nonce management
    NonceStore: proof.NonceStore,
    
    // Constants
    NONCE_VALIDITY_SECONDS: proof.NONCE_VALIDITY_SECONDS,
    PROOF_VERSION: proof.PROOF_VERSION,
    
    // =========================================================================
    // MODULE REFERENCES (for advanced usage)
    // =========================================================================
    
    utils,
    keys,
    token,
    proof,
};
