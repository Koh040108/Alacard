import React, { useState, useEffect } from 'react';
import { generateWalletKeyPair, generateProof, importPrivateKeyJwk, parseToken } from '../crypto';
import api from '../utils/api';
import { QRCodeCanvas } from 'qrcode.react';
import { Shield, Check, Copy, Scan, X, Fingerprint, AlertTriangle } from 'lucide-react';

// Sub-pages
import CitizenHome from './citizen/Home';
import SubsidyWallet from './citizen/SubsidyWallet';
import CitizenHistory from './citizen/History';
import Profile from './citizen/Profile';
import BottomNav from './citizen/BottomNav';

const LOCATION_MAP = {
    'Selangor': { latitude: 3.107, longitude: 101.606 },
    'Perak': { latitude: 4.597, longitude: 101.090 },
    'Penang': { latitude: 5.414, longitude: 100.311 },
    'Johor': { latitude: 1.485, longitude: 103.761 },
    'Sabah': { latitude: 5.980, longitude: 116.073 },
    'Sarawak': { latitude: 1.553, longitude: 110.359 }
};

const Wallet = () => {
    // Global State
    const [keys, setKeys] = useState(null);
    const [token, setToken] = useState(null);
    const [loading, setLoading] = useState(false);

    // UI State
    const [activeTab, setActiveTab] = useState('home'); // home, scan, notification, profile
    const [viewMode, setViewMode] = useState('default'); // default, scanning (QR overlay)
    const [citizenId, setCitizenId] = useState('');

    // QR State
    const [proofStr, setProofStr] = useState('');
    const [timeLeft, setTimeLeft] = useState(30);
    const [scanMode, setScanMode] = useState('auto'); // 'auto' | 'manual'
    const [inputNonce, setInputNonce] = useState('');
    const [claimAmount, setClaimAmount] = useState(null);
    const [locationStatus, setLocationStatus] = useState('idle'); // idle, seeking, found, error
    const [locationError, setLocationError] = useState(null);
    const [manualLocation, setManualLocation] = useState('');

    // Approval Flow State
    const [pendingVerification, setPendingVerification] = useState(null);
    const [showApprovalModal, setShowApprovalModal] = useState(false);
    const [approvalLoading, setApprovalLoading] = useState(false);
    const [showSecurityActionB, setShowSecurityActionB] = useState(false); // New State for High Risk Reject

    useEffect(() => {
        const savedKeys = JSON.parse(localStorage.getItem('alacard_keys'));
        const savedToken = JSON.parse(localStorage.getItem('alacard_token'));
        const savedCitizenId = localStorage.getItem('alacard_citizen_id');

        if (savedKeys) setKeys(savedKeys);
        if (savedToken) setToken(savedToken);
        if (savedCitizenId) setCitizenId(savedCitizenId);
    }, []);

    // Poll for pending verification requests
    useEffect(() => {
        if (!token) return;

        const pollInterval = setInterval(async () => {
            try {
                const res = await api.post('/my-pending-verification', { token });
                if (res.data.pending) {
                    setPendingVerification(res.data);
                    setShowApprovalModal(true);
                } else {
                    // If no pending and modal was open, close it
                    // BUT only if we are not in the middle of Security Action B
                    if (pendingVerification && showApprovalModal && !showSecurityActionB) {
                        setPendingVerification(null);
                        setShowApprovalModal(false);
                    }
                }
            } catch (err) {
                console.error('Pending verification poll error:', err);
            }
        }, 2000); // Poll every 2 seconds

        return () => clearInterval(pollInterval);
    }, [token, pendingVerification, showApprovalModal, showSecurityActionB]);

    // Handle approval response
    const handleApprovalResponse = async (approved) => {
        if (!pendingVerification) return;
        setApprovalLoading(true);
        try {
            await api.post('/respond-verification', {
                verification_id: pendingVerification.verification_id,
                token: token,
                approved: approved
            });
            setShowApprovalModal(false);
            setPendingVerification(null);
        } catch (err) {
            alert('Failed to respond: ' + (err.response?.data?.error || err.message));
        } finally {
            setApprovalLoading(false);
        }
    };



    const handleRejectClick = () => {
        // High Risk check (Score > 20 is the warning threshold in existing code)
        if (pendingVerification?.risk_score > 20) {
            setShowSecurityActionB(true);
        } else {
            handleApprovalResponse(false);
        }
    };

    const handleSecurityActionBSuccess = async () => {
        if (!pendingVerification) {
            alert("Transaction session expired or invalid.");
            setShowSecurityActionB(false);
            setShowApprovalModal(false);
            return;
        }

        setShowSecurityActionB(false);
        setApprovalLoading(true);
        try {
            // 1. Freeze Token
            await api.post('/freeze-token', { token });
            // 2. Reject Transaction
            await api.post('/respond-verification', {
                verification_id: pendingVerification.verification_id,
                token: token,
                approved: false
            });
            setShowApprovalModal(false);
            setPendingVerification(null);
            alert("Security Alert: Token has been frozen for your protection.");
        } catch (err) {
            alert('Failed to execute Security Action: ' + (err.response?.data?.error || err.message));
        } finally {
            setApprovalLoading(false);
        }
    };

    // -------------------------------------------------------------------------
    // IDENTITY MANAGEMENT (Onboarding)
    // -------------------------------------------------------------------------
    const handleGenerateKeys = async () => {
        setLoading(true);
        try {
            const newKeys = await generateWalletKeyPair();
            const keyData = {
                publicKeyJwk: newKeys.publicKey.jwk,
                privateKeyJwk: newKeys.privateKey.jwk,
                publicKeyRaw: newKeys.publicKey.raw
            };
            setKeys(keyData);
            localStorage.setItem('alacard_keys', JSON.stringify(keyData));
        } catch (e) {
            alert("Key generation failed: " + e.message);
        } finally {
            setLoading(false);
        }
    };

    const handleIssueToken = async () => {
        if (!citizenId) return;
        setLoading(true);
        try {
            const res = await api.post('/issue-token', {
                citizen_id: citizenId,
                wallet_public_key: keys.publicKeyRaw
            });
            const { token } = res.data;
            setToken(token);
            localStorage.setItem('alacard_token', JSON.stringify(token));
            localStorage.setItem('alacard_citizen_id', citizenId);
            setActiveTab('home'); // Go to dashboard
        } catch (err) {
            alert('Error: ' + (err.response?.data?.error || err.message));
        }
        setLoading(false);
    };

    // -------------------------------------------------------------------------
    // PROOF GENERATION (QR Engine)
    // -------------------------------------------------------------------------
    const handleManualGenerate = async () => {
        if (!inputNonce || !token || !keys) return;
        try {
            const pk = await importPrivateKeyJwk(keys.privateKeyJwk);
            const p = await generateProof({
                token,
                nonce: inputNonce, // Use the manual input
                walletPrivateKey: pk
            });

            if (manualLocation && LOCATION_MAP[manualLocation]) {
                const coords = LOCATION_MAP[manualLocation];
                const payload = {
                    proof: p,
                    loc: { lat: coords.latitude, lng: coords.longitude },
                    claim_amount: claimAmount
                };
                setProofStr(JSON.stringify(payload));
                return;
            }

            // Get Location (Best Effort)
            navigator.geolocation.getCurrentPosition(
                (pos) => {
                    const payload = {
                        proof: p,
                        loc: { lat: pos.coords.latitude, lng: pos.coords.longitude },
                        claim_amount: claimAmount
                    };
                    setProofStr(JSON.stringify(payload));
                },
                (err) => {
                    console.warn("Location denied:", err);
                    // Fallback without location
                    const payload = { proof: p, loc: null, claim_amount: claimAmount };
                    setProofStr(JSON.stringify(payload));
                }
            );
        } catch (e) {
            alert("Proof Generation Failed: " + e.message);
        }
    };

    useEffect(() => {
        let interval;
        let timer;

        if (viewMode === 'scanning' && token && keys) {

            const generate = async () => {
                setProofStr(''); // Clear old QR to prevents scanning stale/loading states
                try {
                    const pk = await importPrivateKeyJwk(keys.privateKeyJwk);
                    // Use seconds for consistency with backend expectation if needed
                    // But backend check allows 60s skew.
                    const p = await generateProof({
                        token,
                        nonce: Math.floor(Date.now() / 1000).toString(),
                        walletPrivateKey: pk
                    });

                    // Manual Override Logic
                    if (manualLocation && LOCATION_MAP[manualLocation]) {
                        setLocationStatus('found');
                        setLocationError(null);
                        const coords = LOCATION_MAP[manualLocation];
                        const payload = {
                            proof: p,
                            loc: { lat: coords.latitude, lng: coords.longitude },
                            claim_amount: claimAmount
                        };
                        setProofStr(JSON.stringify(payload));
                        return; // Skip GPS
                    }

                    setLocationStatus('seeking');
                    // Get Location for Proximity Check
                    navigator.geolocation.getCurrentPosition(
                        (pos) => {
                            setLocationStatus('found');
                            setLocationError(null);
                            const payload = {
                                proof: p,
                                loc: { lat: pos.coords.latitude, lng: pos.coords.longitude },
                                claim_amount: claimAmount
                            };
                            setProofStr(JSON.stringify(payload));
                        },
                        (err) => {
                            console.warn("Location denied/unavailable");
                            setLocationStatus('error');
                            setLocationError(err.message + (window.isSecureContext ? '' : ' (Not HTTPS)'));
                            setProofStr(JSON.stringify({ proof: p, loc: null, claim_amount: claimAmount }));
                        },
                        { timeout: 10000 } // Increased to 10s for better GPS fix
                    );
                } catch (e) {
                    console.error(e);
                }
            };

            generate();

            interval = setInterval(() => {
                generate();
                setTimeLeft(30);
            }, 30000);

            timer = setInterval(() => {
                setTimeLeft(prev => prev > 0 ? prev - 1 : 0);
            }, 1000);
        }

        return () => {
            clearInterval(interval);
            clearInterval(timer);
        };
    }, [viewMode, token, keys, claimAmount, manualLocation]);

    // -------------------------------------------------------------------------
    // ROUTER
    // -------------------------------------------------------------------------

    // 1. Onboarding Screen
    if (!keys) {
        return <Onboarding onGenerate={handleGenerateKeys} loading={loading} />;
    }

    // 2. Link ID Screen (If keys exist but no token)
    if (!token) {
        return (
            <LinkIdentity
                citizenId={citizenId}
                setCitizenId={setCitizenId}
                onSubmit={handleIssueToken}
                loading={loading}
            />
        );
    }

    // 3. Main App Layout
    return (
        <div className="relative min-h-screen bg-slate-50">

            {/* Page Content */}
            <div className={`transition-all ${viewMode === 'scanning' ? 'scale-95 opacity-50 blur-sm overflow-hidden h-screen' : ''}`}>
                {activeTab === 'home' && (
                    <CitizenHome onNavigate={(tab) => setActiveTab(tab)} />
                )}

                {(activeTab === 'scan' || activeTab === 'subsidy') && (
                    <SubsidyWallet
                        onNavigate={(tab) => setActiveTab(tab)}
                        onScan={(amount) => {
                            setClaimAmount(amount || null);
                            setViewMode('scanning');
                        }}
                        token={token}
                        citizenId={citizenId}
                    />
                )}

                {/* Notifications -> History */}
                {activeTab === 'notification' && (
                    <CitizenHistory
                        onNavigate={(tab) => setActiveTab(tab)}
                        token={token}
                    />
                )}

                {/* Profile -> New Profile Screen */}
                {activeTab === 'profile' && (
                    <Profile
                        onNavigate={(tab) => setActiveTab(tab)}
                        token={token}
                        citizenId={citizenId}
                    />
                )}
            </div>

            {/* Bottom Nav */}
            <BottomNav activeTab={activeTab} onTabChange={setActiveTab} />

            {/* QR Overlay (Proof Generator) */}
            {viewMode === 'scanning' && (
                <div className="fixed inset-0 z-50 flex flex-col items-center justify-end sm:justify-center bg-black/90 animate-in fade-in duration-200 backdrop-blur-sm">
                    {/* Close Area */}
                    <div className="absolute inset-0" onClick={() => { setViewMode('default'); setClaimAmount(null); }}></div>

                    <div className="relative w-full max-w-md bg-white rounded-t-3xl sm:rounded-3xl p-6 pb-10 sm:pb-6 shadow-2xl animate-in slide-in-from-bottom-10">
                        <div className="w-12 h-1 bg-slate-200 rounded-full mx-auto mb-6"></div>

                        <div className="flex justify-between items-center mb-6">
                            <div>
                                <h3 className="text-xl font-bold text-slate-900">Scan to Verify</h3>
                                <p className="text-sm text-slate-500 mb-1">Present this QR code to the terminal</p>
                                <p className="text-[10px] text-slate-400 font-mono">v1.2 Patched</p>
                                {claimAmount && <p className="text-xs font-bold text-blue-600 bg-blue-50 px-2 py-1 rounded w-fit">Redeem Request: RM {claimAmount}</p>}
                            </div>
                            <button onClick={() => { setViewMode('default'); setClaimAmount(null); }} className="p-2 bg-slate-100 rounded-full">
                                <X size={20} className="text-slate-500" />
                            </button>
                        </div>

                        {/* Mode Toggle */}
                        <div className="flex justify-center mb-6 bg-slate-100 p-1 rounded-xl w-fit mx-auto">
                            <button
                                onClick={() => { setScanMode('auto'); setProofStr(''); }}
                                className={`px-4 py-2 rounded-lg text-sm font-bold transition-all ${scanMode === 'auto' ? 'bg-white text-blue-600 shadow-sm' : 'text-slate-500'}`}
                            >
                                Auto (Passive)
                            </button>
                            <button
                                onClick={() => { setScanMode('manual'); setProofStr(''); setInputNonce(''); }}
                                className={`px-4 py-2 rounded-lg text-sm font-bold transition-all ${scanMode === 'manual' ? 'bg-white text-blue-600 shadow-sm' : 'text-slate-500'}`}
                            >
                                Manual Input
                            </button>
                        </div>

                        {/* CONTENT AREA */}
                        {scanMode === 'auto' ? (
                            <>
                                {/* Manual Location Override */}
                                <div className="mb-4">
                                    <select
                                        value={manualLocation}
                                        onChange={(e) => setManualLocation(e.target.value)}
                                        className="w-full bg-white border border-slate-300 rounded-lg p-2 text-xs font-bold text-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    >
                                        <option value="">📡 Mode: Auto-GPS (Real)</option>
                                        <option disabled>--- Manual Override ---</option>
                                        {Object.keys(LOCATION_MAP).map(state => (
                                            <option key={state} value={state}>📍 Force: {state}</option>
                                        ))}
                                    </select>
                                </div>

                                {/* QR Box (Auto) */}
                                <div className="bg-slate-50 p-6 rounded-2xl flex flex-col items-center justify-center border border-slate-100 mb-6">
                                    {proofStr ? (
                                        <QRCodeCanvas value={proofStr} size={250} />
                                    ) : (
                                        <div className="w-[250px] h-[250px] flex items-center justify-center text-slate-400 font-medium animate-pulse">
                                            Generating Secure Proof...
                                        </div>
                                    )}
                                </div>

                                {/* Timer */}
                                <div className="flex items-center justify-between bg-blue-50 p-4 rounded-xl text-blue-700">
                                    <div className="flex items-center gap-2">
                                        <div className="w-2 h-2 bg-blue-500 rounded-full animate-ping"></div>
                                        <span className="font-bold text-sm">Live Token</span>
                                    </div>
                                    <span className="font-mono font-bold">{timeLeft}s</span>
                                </div>

                                {/* Debug Location Status */}
                                <div className="mt-4 p-3 rounded-xl bg-slate-100 text-xs text-center border border-slate-200">
                                    <p className="font-bold text-slate-500 mb-1">GPS Status</p>
                                    <div className={`font-mono font-bold mb-1 ${locationStatus === 'found' ? 'text-green-600' : locationStatus === 'error' ? 'text-red-500' : 'text-blue-500 animate-pulse'}`}>
                                        {locationStatus === 'found' && (manualLocation ? 'FORCED (MANUAL)' : 'CONNECTED')}
                                        {locationStatus === 'error' && 'FAILED'}
                                        {(locationStatus === 'seeking' || locationStatus === 'idle') && 'SEARCHING...'}
                                    </div>
                                    {locationStatus === 'error' && (
                                        <p className="text-red-500 text-[10px]">{locationError}</p>
                                    )}
                                    <p className="text-[9px] text-slate-400 mt-2">
                                        (Requires HTTPS/Localhost + Permission)
                                    </p>
                                </div>
                            </>
                        ) : (

                            <>
                                {/* Manual Input Form */}
                                <div className="space-y-4 mb-6">
                                    {!proofStr ? (
                                        <>
                                            <div className="bg-slate-50 p-6 rounded-2xl border border-dashed border-slate-300 flex flex-col items-center justify-center text-center">
                                                <Scan size={32} className="text-slate-400 mb-2" />
                                                <p className="text-sm text-slate-500 mb-4">Enter the Challenge Code displayed on the Verification Terminal</p>
                                                <input
                                                    className="w-full bg-white border border-slate-300 rounded-xl py-3 px-4 text-center font-mono font-bold text-xl tracking-widest focus:outline-none focus:ring-2 focus:ring-blue-500 uppercase"
                                                    placeholder="CODE"
                                                    value={inputNonce}
                                                    onChange={e => setInputNonce(e.target.value)}
                                                />
                                            </div>
                                            <button
                                                onClick={handleManualGenerate}
                                                disabled={!inputNonce}
                                                className="w-full bg-blue-600 text-white font-bold py-4 rounded-xl shadow-lg active:scale-95 transition-all"
                                            >
                                                Generate Proof
                                            </button>
                                        </>
                                    ) : (
                                        // Resulting QR for Manual
                                        <div className="bg-slate-50 p-6 rounded-2xl flex flex-col items-center justify-center border border-slate-100 mb-4">
                                            <QRCodeCanvas value={proofStr} size={200} />

                                            <div className="w-full mt-4">
                                                <p className="text-xs font-bold text-slate-500 mb-1">Proof JSON (for manual testing):</p>
                                                <textarea
                                                    readOnly
                                                    className="w-full h-24 text-[10px] bg-slate-200 rounded p-2 font-mono text-slate-700"
                                                    value={proofStr}
                                                />
                                                <button
                                                    onClick={() => navigator.clipboard.writeText(proofStr)}
                                                    className="flex items-center justify-center gap-2 w-full mt-2 bg-slate-200 hover:bg-slate-300 text-slate-700 font-bold py-2 rounded-lg text-xs"
                                                >
                                                    <Copy size={12} /> Copy Proof JSON
                                                </button>
                                            </div>

                                            <button onClick={() => setProofStr('')} className="mt-6 text-sm text-blue-600 font-bold">
                                                Enter Different Code
                                            </button>
                                        </div>
                                    )}
                                </div>
                            </>
                        )}
                    </div>
                </div>
            )}

            {/* Approval Request Modal */}
            {showApprovalModal && pendingVerification && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/90 backdrop-blur-sm animate-in fade-in duration-200">
                    <div className="w-full max-w-sm mx-4 bg-slate-900 rounded-3xl p-6 shadow-2xl border border-slate-700 animate-in zoom-in-95">

                        {/* Header */}
                        <div className="text-center mb-6">
                            <div className="w-16 h-16 bg-orange-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                                <Shield className="w-8 h-8 text-orange-400" />
                            </div>
                            <h2 className="text-xl font-bold text-white mb-1">Transaction Request</h2>
                            <p className="text-slate-400 text-sm">A terminal wants to verify your subsidy</p>
                        </div>

                        {/* Details */}
                        <div className="bg-slate-800 rounded-xl p-4 mb-6 space-y-3">
                            <div className="flex justify-between items-center">
                                <span className="text-slate-400 text-sm">Terminal</span>
                                <span className="text-white font-mono text-sm">{pendingVerification.terminal_id}</span>
                            </div>
                            <div className="flex justify-between items-center">
                                <span className="text-slate-400 text-sm">Location</span>
                                <span className="text-white text-sm">{pendingVerification.terminal_location?.city || pendingVerification.terminal_location?.state || 'Unknown'}</span>
                            </div>
                            {pendingVerification.claim_amount > 0 && (
                                <div className="flex justify-between items-center">
                                    <span className="text-slate-400 text-sm">Amount</span>
                                    <span className="text-green-400 font-bold">RM {pendingVerification.claim_amount}</span>
                                </div>
                            )}
                            <div className="flex justify-between items-center">
                                <span className="text-slate-400 text-sm">Expires In</span>
                                <span className={`font-mono font-bold ${pendingVerification.expires_in < 15 ? 'text-red-400 animate-pulse' : 'text-blue-400'}`}>
                                    {Math.floor(pendingVerification.expires_in)}s
                                </span>
                            </div>
                        </div>

                        {/* Risk Warning */}
                        {pendingVerification.risk_score > 20 && (
                            <div className="bg-orange-500/10 border border-orange-500/30 rounded-xl p-3 mb-6">
                                <p className="text-orange-400 text-xs font-bold mb-1">⚠️ Risk Warning</p>
                                <p className="text-orange-200 text-xs">{pendingVerification.risk_reasons?.[0] || 'Unusual activity detected'}</p>
                            </div>
                        )}

                        {/* Buttons */}
                        <div className="flex gap-3">
                            <button
                                onClick={handleRejectClick}
                                disabled={approvalLoading}
                                className="flex-1 bg-red-600 hover:bg-red-500 text-white font-bold py-4 rounded-xl transition-all active:scale-95 disabled:opacity-50"
                            >
                                {approvalLoading ? '...' : (pendingVerification.risk_score > 20 ? 'Reject & Secure' : 'Reject')}
                            </button>
                            <button
                                onClick={() => handleApprovalResponse(true)}
                                disabled={approvalLoading}
                                className="flex-1 bg-green-600 hover:bg-green-500 text-white font-bold py-4 rounded-xl transition-all active:scale-95 disabled:opacity-50"
                            >
                                {approvalLoading ? '...' : 'Approve'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Security Action B Modal (Biometric Freeze) */}
            {showSecurityActionB && (
                <div className="fixed inset-0 z-[110] flex items-center justify-center bg-red-900/90 backdrop-blur-md animate-in fade-in duration-200">
                    <div className="w-full max-w-xs mx-4 bg-white rounded-3xl p-8 mb-20 text-center shadow-2xl animate-in zoom-in-95" onClick={handleSecurityActionBSuccess}>
                        <div className="w-20 h-20 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-6 ring-8 ring-red-500/20 animate-pulse cursor-pointer">
                            <Fingerprint size={48} className="text-red-600" />
                        </div>

                        <h3 className="text-xl font-bold text-red-600 mb-2">High Risk Detected</h3>
                        <p className="text-slate-600 text-sm mb-6">
                            Authorized biometric scan required to <span className="font-bold">Freeze Token</span> and block this transaction.
                        </p>

                        <div className="text-[10px] uppercase font-bold text-slate-400 tracking-widest">
                            Touch ID / Face ID
                        </div>
                        <p className="text-[10px] text-slate-300 mt-2">(Click icon to simulate scan)</p>

                        <button
                            onClick={(e) => { e.stopPropagation(); setShowSecurityActionB(false); }}
                            className="mt-8 text-slate-400 text-sm font-bold underline"
                        >
                            Cancel
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

// -------------------------------------------------------------------------
// SUB-COMPONENTS (Legacy Onboarding)
// -------------------------------------------------------------------------

const Onboarding = ({ onGenerate, loading }) => (
    <div className="min-h-screen bg-slate-900 flex flex-col items-center justify-center p-6 text-center text-white">
        <div className="w-24 h-24 bg-blue-600 rounded-3xl flex items-center justify-center mb-8 shadow-2xl shadow-blue-500/30 ring-4 ring-blue-500/20">
            <Shield className="w-12 h-12 text-white" />
        </div>
        <h1 className="text-3xl font-bold mb-3">Secure Identity</h1>
        <p className="text-slate-400 mb-12 leading-relaxed max-w-xs">
            Create your private digital wallet to store government credentials securely on your device.
        </p>
        <button
            onClick={onGenerate}
            disabled={loading}
            className="w-full max-w-xs bg-white text-blue-900 font-bold py-4 rounded-2xl shadow-xl active:scale-95 transition-all text-lg"
        >
            {loading ? 'Creating Secure Enclave...' : 'Create Wallet'}
        </button>
    </div>
);

const LinkIdentity = ({ citizenId, setCitizenId, onSubmit, loading }) => (
    <div className="min-h-screen bg-slate-900 flex flex-col items-center justify-center p-6 text-white text-center">
        <h2 className="text-2xl font-bold mb-2">Link National ID</h2>
        <p className="text-slate-400 mb-8 text-sm">Enter your Citizen ID (e.g., CITIZEN_001) to fetch your entitlements.</p>

        <div className="w-full max-w-xs space-y-4">
            <input
                className="w-full bg-slate-800 border border-slate-700 rounded-xl py-4 px-4 text-center text-xl font-bold focus:outline-none focus:border-blue-500 transition-colors placeholder-slate-600"
                placeholder="CITIZEN_001"
                value={citizenId}
                onChange={e => setCitizenId(e.target.value)}
                autoFocus
            />
            <button
                onClick={onSubmit}
                disabled={loading}
                className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-4 rounded-xl shadow-lg shadow-blue-900/50 active:scale-95 transition-all"
            >
                {loading ? 'Verifying...' : 'Link Identity'}
            </button>
        </div>
    </div>
);

export default Wallet;

