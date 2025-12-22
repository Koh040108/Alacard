# 🔐 AlaCard: Privacy-Preserving Subsidy Verification System

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-ISC-green.svg)
![Node](https://img.shields.io/badge/node-v18%2B-brightgreen.svg)
![React](https://img.shields.io/badge/react-18-61dafb.svg)

**A cryptographic system for verifying citizen eligibility for government subsidies without revealing personal identity information.**

[Features](#-key-features) • [Architecture](#-system-architecture) • [Quick Start](#-quick-start) • [Usage](#-usage-guide) • [Security](#-security-model) • [API](#-api-reference)

</div>

---

## 🌟 Key Features

### Privacy & Security
- **Zero-Knowledge Verification**: Terminals only learn "Eligible" or "Not Eligible" — never seeing names, IC numbers, or income data
- **Cryptographic Token Binding**: Tokens are ECDSA P-256 signed and bound to specific wallet keys
- **Replay Protection**: Server-generated nonces with time-based expiry prevent proof reuse

### Fraud Detection
- **AI Risk Engine**: Real-time fraud analysis with multiple detection vectors:
  - 📍 **Proximity Check**: GPS-based relay attack prevention (wallet-to-terminal distance)
  - ✈️ **Impossible Travel**: Velocity-based detection of physically impossible movements
  - 📊 **Frequency Analysis**: Detection of suspicious high-frequency transactions
  - 🎯 **Location Anomaly**: Behavioral clustering to identify unusual usage patterns

### User Experience
- **Mobile-First Citizen App**: Modern React UI with subsidy wallet, transaction history, and QR code generation
- **Terminal Simulation**: QR scanning, location selection, and real-time verification status
- **Issuer Admin Panel**: Citizen management, token freeze/unfreeze, and audit log viewer

---

## 🏗 System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ALACARD ARCHITECTURE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐         ┌─────────────────┐         ┌────────────────┐ │
│  │   CITIZEN APP   │         │     BACKEND     │         │    TERMINAL    │ │
│  │   (Wallet)      │         │   (Issuer/API)  │         │   (Verifier)   │ │
│  ├─────────────────┤         ├─────────────────┤         ├────────────────┤ │
│  │ • Key Generation│ ──────► │ • Token Issuance│ ◄────── │ • QR Scanning  │ │
│  │ • Proof Gen     │         │ • Verification  │         │ • Nonce Request│ │
│  │ • QR Display    │         │ • Fraud Engine  │ ──────► │ • Status View  │ │
│  │ • GPS Location  │         │ • Audit Logging │         │ • Claim Flow   │ │
│  │ • History View  │         │ • Citizen CRUD  │         │ • Location Set │ │
│  └─────────────────┘         └─────────────────┘         └────────────────┘ │
│         │                           │                           │           │
│         │      ECDSA P-256          │       SQLite DB           │           │
│         │      Web Crypto API       │       Fraud Engine        │           │
│         └───────────────────────────┴───────────────────────────┘           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Backend** | Node.js, Express, SQLite | Token issuance, verification, fraud detection, audit logging |
| **Frontend** | React 18, Vite, Web Crypto API | Citizen wallet, terminal simulator, issuer admin |
| **Crypto Core** | ECDSA P-256, SHA-256 | Token signing, proof generation, key management |
| **Fraud Engine** | Geolib, Custom Heuristics | Real-time risk scoring with location/velocity checks |

---

## 🚀 Quick Start

### Prerequisites
- Node.js v18+
- NPM

### Installation

```bash
# Clone the repository
git clone https://github.com/Koh040108/Alacard.git
cd Alacard

# Install all dependencies
npm run install:all

# Start backend (Port 3000)
npm run backend

# Start frontend (Port 5173) - in a new terminal
npm run frontend
```

### First Run
The system auto-initializes:
- 🔑 **Keys**: ECDSA P-256 keypair generated in `backend/keys/`
- 🗄️ **Database**: SQLite initialized with schema and migrations
- 👤 **Seed Data**: Demo citizens pre-loaded (CITIZEN_001, etc.)

---

## 📖 Usage Guide

### 1️⃣ Citizen Onboarding (Wallet App)

1. Open browser to `http://localhost:5173`
2. Click **"Initialize Secure Identity"** to generate wallet keys
3. Enter Citizen ID: `CITIZEN_001` (pre-seeded eligible user)
4. System issues a cryptographically-signed token bound to your wallet

### 2️⃣ Verification Flow (Terminal)

1. Open Terminal page (`/terminal`) in a separate tab/device
2. Set **Terminal Location** (simulates kiosk GPS)
3. Scan the QR code from the Citizen's wallet
4. View verification result with AI Risk Score

### 3️⃣ Subsidy Redemption

1. In Wallet, tap on a subsidy card (e.g., "BUDI MADANI RON95")
2. Enter claim amount (up to RM50)
3. Present QR to Terminal
4. Terminal approves and logs the transaction

### 4️⃣ Issuer Administration

1. Navigate to `/issuer`
2. View all citizens and their eligibility status
3. Freeze/Unfreeze tokens as needed
4. Review complete audit trail

---

## 🔒 Security Model

### Cryptographic Guarantees

| Property | Mechanism | Protection |
|----------|-----------|------------|
| **Data Integrity** | ECDSA P-256 Signatures | Tokens cannot be forged or modified |
| **Wallet Binding** | Public Key Hash in Token | Tokens cannot be transferred between wallets |
| **Replay Prevention** | Nonce + Signature Cache | Each proof can only be verified once |
| **Time Binding** | 5-minute challenge expiry | Old proofs automatically expire |
| **Privacy** | Zero-Knowledge Response | Terminal learns only eligibility status |

### Fraud Detection Thresholds

| Check | Trigger | Risk Score Impact |
|-------|---------|-------------------|
| Relay Attack | Wallet >100km from Terminal | +90 points |
| Proximity Warning | Wallet >5km from Terminal | +50 points |
| Impossible Travel | >800 km/h between transactions | +80 points |
| Location Anomaly | >300km from usual zone | +30 points |
| High Frequency | <1 minute between transactions | +20 points |
| GPS Missing | No wallet location provided | +10 points |

---

## 📁 Project Structure

```
Alacard/
├── backend/
│   ├── crypto/           # Cryptographic library (keys, tokens, proofs)
│   │   ├── index.js      # Main exports
│   │   ├── keys.js       # ECDSA key management
│   │   ├── token.js      # Token creation/verification
│   │   └── proof.js      # Proof generation/verification
│   ├── server.js         # Express API (612 lines)
│   ├── fraudEngine.js    # AI Risk Analysis (173 lines)
│   ├── database.js       # SQLite initialization & migrations
│   └── keys/             # Persisted issuer keypair (PEM)
│
├── frontend/
│   ├── src/
│   │   ├── crypto/       # Browser-compatible crypto (Web Crypto API)
│   │   ├── pages/
│   │   │   ├── Wallet.jsx        # Citizen wallet + QR generation
│   │   │   ├── Terminal.jsx      # Verification terminal + scanning
│   │   │   ├── Issuer.jsx        # Admin panel
│   │   │   └── citizen/          # Sub-pages (Home, History, Profile)
│   │   └── utils/api.js  # Axios instance with base URL
│   └── vite.config.js
│
├── vercel.json           # Deployment configuration
└── package.json          # Root workspace scripts
```

---

## 🔌 API Reference

### Token Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/public-key` | GET | Retrieve issuer's public key (raw Base64URL) |
| `/issue-token` | POST | Issue signed token for eligible citizen |
| `/verify-token` | POST | Verify proof and return eligibility + risk score |
| `/request-nonce` | GET | Generate time-limited verification challenge |

### Admin Operations

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/citizens` | GET | List all citizens with eligibility status |
| `/issued-tokens` | GET | List all issued tokens |
| `/freeze-token` | POST | Freeze a citizen's token |
| `/unfreeze-token` | POST | Unfreeze a previously frozen token |
| `/audit-logs` | GET | Retrieve verification history |

### Citizen Operations

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/my-activity` | POST | Retrieve user's transaction history |
| `/claim` | POST | Process subsidy claim transaction |

---

## 🛠️ Development

### Environment Variables

```env
# Frontend (.env)
VITE_API_URL=http://localhost:3000   # Backend API URL

# Production (Vercel)
VITE_API_URL=https://your-api.vercel.app/api
```

### Database Schema

```sql
-- Core Tables
citizens (citizen_id, income, eligibility_status, subsidy_quota)
issued_tokens (token_id, token_hash, expiry, issuer_signature, status, citizen_id)
audit_logs (audit_id, token_hash, terminal_id, location, risk_data, timestamp, result, wallet_binding)
verification_terminals (terminal_id, location)
```

---

## 📄 License

ISC License - See [LICENSE](LICENSE) for details.

---

## 👥 Contributors

- **Koh** - Initial development and architecture

---

<div align="center">

**Built with ❤️ for privacy-preserving government services**

</div>
