# AlaCard - Privacy-Preserving Eligibility Verification (MVP)

AlaCard is a hackathon-ready solution for verifying citizen subsidy eligibility without revealing personal data. It uses cryptographic signatures (PKI), ZKP-style challenge-response authentication, and an append-only audit trail.

## 🚀 Features

- **Privacy**: No personal data (IC, Name, Income) is stored in the token or shared with the terminal. 
- **Security**: 
  - **PKI**: Tokens are signed by the Government Issuer.
  - **Wallet Binding**: Tokens are bound to the user's wallet private key.
  - **Replay Protection**: Verifications use a random nonce.
- **Transparency**: All verifications are logged in a hashed, append-only audit log.
- **Offline Capable**: Terminals can verify cryptographic proofs locally (simulated in this web MVP).

## 🛠 Tech Stack

- **Backend**: Node.js, Express, SQLite, Native Crypto
- **Frontend**: React (Vite), Tailwind CSS, Lucide Icons, Node-Forge (Crypto)

## 📂 Project Structure

- `backend/`: Issuer API, Verification Logic, SQLite Database.
  - `server.js`: Main API.
  - `cryptoUtils.js`: Signing and Hashing logic.
  - `database.js`: DB Schema.
- `frontend/`: Citizen Wallet and Verification Terminal.
  - `src/pages/Wallet.jsx`: Secure storage & ZKP generation.
  - `src/pages/Terminal.jsx`: Verification logic.
  - `src/pages/Audit.jsx`: Blockchain-style log viewer.

## 🏁 Getting Started

### Prerequisites
- Node.js (v18+)

### 1. Installation

Run this from the root directory:

```bash
npm run install:all
```

(Or manually `npm install` in both `backend` and `frontend` folders).

### 2. Run the Backend

Open a terminal:

```bash
npm run backend
```

(Server runs on http://localhost:3000)

### 3. Seed Mock Data

In a new terminal (or use the script provided):

```bash
npm run seed
```

This resets the database and creates mock citizens:
- `CITIZEN_001` (Eligible)
- `CITIZEN_002` (Not Eligible - Income too high)
- `CITIZEN_003` (Eligible)

### 4. Run the Frontend

Open another terminal:

```bash
npm run frontend
```

(App runs on http://localhost:5173)

## 📱 How to Demo

1. **Open Wallet** (`/wallet`):
   - Click "Initialize Secure Wallet" to generate keys.
   - Enter `CITIZEN_001` and click "Download Eligibility Token".
   - You now have a signed token.

2. **Open Terminal** (`/terminal`) in a separate tab/window:
   - Click "Start New Verification" to generate a Nonce (e.g., `abc123xym`).

3. **Prove Eligibility**:
   - Go back to **Wallet**.
   - Paste the Nonce into the "Prove Eligibility" input.
   - Click "Generate Zero-Knowledge Proof".
   - Copy the JSON Proof.

4. **Verify**:
   - Go back to **Terminal**.
   - Paste the JSON Proof.
   - Click "Verify Eligibility".
   - Result: **ELIGIBLE** (and logged).

5. **Audit**:
   - Go to **Audit Log** (`/audit`).
   - See the new entry linked to the previous hash.

## 🔐 Security Design

1. **Issuer Signature**: Ensures the token was created by the government.
2. **Wallet Binding**: The token contains the User's Public Key. The Proof must contain a signature of the Nonce by the corresponding Private Key. This prevents token theft/cloning (unless the private key is stolen).
3. **Audit Chain**: `current_hash = SHA256(prev_hash + data)`. modification of logs allows detection.

## 🔑 Cryptographic Core

The system uses **ECDSA P-256 (ES256)** with **SHA-256** for all cryptographic operations.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    GOVERNMENT ISSUER                            │
│  ┌───────────────┐     ┌───────────────┐                       │
│  │ Issuer Keys   │────▶│ Sign Token    │                       │
│  │ (P-256)       │     │ (ECDSA)       │                       │
│  └───────────────┘     └───────┬───────┘                       │
└────────────────────────────────┼────────────────────────────────┘
                                 │ Token (signed)
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    CITIZEN WALLET                               │
│  ┌───────────────┐     ┌───────────────┐     ┌───────────────┐ │
│  │ Wallet Keys   │     │ Store Token   │     │ Generate      │ │
│  │ (P-256)       │────▶│ (bound to     │────▶│ Proof         │ │
│  └───────────────┘     │ wallet key)   │     │ (signs nonce) │ │
│                        └───────────────┘     └───────┬───────┘ │
└──────────────────────────────────────────────────────┼──────────┘
                                                       │ Proof
                                                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    VERIFICATION TERMINAL                        │
│  ┌───────────────┐     ┌───────────────┐     ┌───────────────┐ │
│  │ Generate      │     │ Verify        │     │ Verify        │ │
│  │ Nonce         │────▶│ Token Sig     │────▶│ Proof Sig     │ │
│  │ (challenge)   │     │ (issuer key)  │     │ (wallet key)  │ │
│  └───────────────┘     └───────────────┘     └───────┬───────┘ │
│                                                      │         │
│                                              ┌───────▼───────┐ │
│                                              │ ELIGIBLE/NOT  │ │
│                                              └───────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Crypto Modules

| Module | Location | Purpose |
|--------|----------|---------|
| `utils.js` | `backend/crypto/` | Base64URL, SHA-256, nonces, constant-time comparison |
| `keys.js` | `backend/crypto/` | P-256 key generation, import/export (PEM, JWK, raw) |
| `token.js` | `backend/crypto/` | Token creation, signing, verification |
| `proof.js` | `backend/crypto/` | Challenge-response, nonce management |
| `tests.js` | `backend/crypto/` | Security test suite |

### 🧪 Run Crypto Tests

To verify the cryptographic implementation:

```bash
cd backend
node crypto/tests.js
```

**Expected output:**
```
============================================================
AlaCard Security Tests
============================================================

🔑 Generated test keys...

--- Basic Functionality ---
✅ PASS: Token creation succeeds with valid inputs
✅ PASS: Token verification succeeds with valid token
✅ PASS: Challenge generation produces unique nonces
✅ PASS: Proof generation and verification succeeds

--- Attack Prevention Tests ---
✅ PASS: ATTACK: Token tampering is detected
✅ PASS: ATTACK: Proof replay is detected (same nonce)
✅ PASS: ATTACK: Proof with wrong nonce is rejected
✅ PASS: ATTACK: Stolen token cannot be used without wallet key
✅ PASS: ATTACK: Forged token with wrong issuer key is rejected
✅ PASS: ATTACK: Expired token is rejected
✅ PASS: ATTACK: Algorithm confusion is prevented
✅ PASS: ATTACK: Wallet binding is enforced
✅ PASS: ATTACK: Invalid signature length is rejected

--- Privacy Tests ---
✅ PASS: Token does not contain IC number
✅ PASS: Proof does not reveal token contents to eavesdropper

--- Cryptographic Properties ---
✅ PASS: Key generation produces unique keys
✅ PASS: Nonces have sufficient entropy
✅ PASS: Token hashes are deterministic
✅ PASS: Different tokens produce different hashes
✅ PASS: Constant-time comparison prevents timing attacks

============================================================
Tests Complete: 20 passed, 0 failed
============================================================
```

### Security Properties Tested

| Attack | Protection |
|--------|------------|
| Token Tampering | Signature verification fails |
| Replay Attack | Single-use nonces with expiry |
| Stolen Token | Requires wallet private key |
| Forged Token | Only issuer can sign |
| Expired Token | Expiry timestamp enforced |
| Algorithm Confusion | Only ES256 accepted |

### Token Format

```
BASE64URL(header).BASE64URL(payload).BASE64URL(signature)
```

**Header:**
```json
{ "alg": "ES256", "typ": "ELIGIBILITY", "ver": "1" }
```

**Payload (NO PII):**
```json
{
  "elig": true,           // Eligibility status
  "wbind": "abc123...",   // SHA-256 hash of wallet public key
  "wpub": "BExy...",      // Wallet public key (raw, Base64URL)
  "iss": "GOV_ISSUER",    // Issuer ID
  "iat": 1702800000,      // Issued at (Unix timestamp)
  "exp": 1705392000,      // Expires at (Unix timestamp)
  "jti": "uuid-..."       // Unique token ID
}
```

---
*Built for Hackathon 2025*
