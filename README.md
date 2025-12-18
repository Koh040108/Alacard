# Alacard: Privacy-Preserving Subsidy Verification

Alacard is a **Zero-Knowledge Proof (ZKP)** based system for verifying citizen eligibility for subsidies without revealing personal identity information (PII).

## 🚀 Key Features

- **Privacy-First**: Verifiers (Terminals) only learn "Eligible" or "Not Eligible". They never see the user's name, ID, or income.
- **Crypto-Binding**: Tokens are cryptographically updated to a specific user's wallet (ECDSA P-256).
- **Replay Protection**: Uses server-generated nonces to prevent attackers from reusing stolen proofs.
- **Auditability**: Every verification event is cryptographically logged on the server.

## 🏗 Architecture

The system consists of three main components:

1.  **Backend (Issuer & Verifier)**
    - **Issuer**: Signs eligibility tokens using a private ECDSA key.
    - **Verifier**: Validates ZK proofs submitted by terminals.
    - **Tech**: Node.js, Express, SQLite, Native Crypto Module (ECDSA P-256).

2.  **Wallet (Frontend)**
    - **Role**: Stores the user's `private key` securely in the browser (Web Crypto API).
    - **Function**: Generates a signature over `(Token + Nonce)` to prove ownership.
    - **Tech**: React, Vite, Web Crypto API.

3.  **Terminal (Frontend)**
    - **Role**: The point-of-sale device used by merchants.
    - **Function**: Requests a challenge (nonce) and verifies the user's proof.
    - **Tech**: React, Vite.

## 🛠️ Setup & Installation

### Prerequisites
- Node.js (v18+)
- NPM

### 1. Start the Backend
```bash
cd backend
npm install
npm start
```
*Runs on port 3000. Setup includes automatic key generation (`keys/`) and DB initialization (`database.sqlite`).*

### 2. Start the Frontend
```bash
cd frontend
npm install
npm run dev
```
*Runs on port 5173. Access via browser.*

## � Usage Guide

### Step 1: Issue Credentials
1.  Open **Wallet** (`/`).
2.  Click **"Link Identity"**.
3.  Enter Citizen ID: `CITIZEN_001` (Pre-seeded eligible user).
4.  The system issues a signed token bound to your browser's local key.

### Step 2: Verification (The ZKP Flow)
1.  Open **Terminal** page (separate tab/device).
2.  Click **"Start New Verification"**. The terminal requests a **Nonce** from the backend.
3.  **Copy** the Nonce.
4.  Go to **Wallet** -> **"Present ID / Verify"**.
5.  **Paste** the Nonce.
6.  Click **"Generate Proof"**.
    - *The wallet signs `hash(Token + Nonce)` with its private key.*
7.  **Copy** the JSON Proof.
8.  Go back to **Terminal** and **Paste** the Proof.
9.  Click **"Verify"**.
    - *The backend verifies the signature, nonce freshness, and token validity.*

## 🔒 Security Model

| Component | Protection Mechanism |
|Data Integrity| ECDSA P-256 Signatures (Issuer Key)|
|Wallet Ownership| ECDSA P-256 Signatures (Wallet Key)|
|Replay Attacks| Nonce-based Challenge/Response (5 min expiry)|
|Privacy| Token contents hidden from Terminal; only validity status returned|

## 📂 Project Structure

- `backend/crypto/`: The core cryptographic library (Keys, Tokens, Proofs).
- `backend/server.js`: API endpoints for issuance and verification.
- `frontend/src/crypto/`: Mirror of the crypto library for the browser.
- `frontend/src/pages/`: React components for Wallet and Terminal.
