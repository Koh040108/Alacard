import React, { useState, useEffect } from 'react';
import { generateWalletKeyPair, generateProof, importPrivateKeyJwk, parseToken } from '../crypto';
import api from '../utils/api';
import { QRCodeCanvas } from 'qrcode.react';
import { Shield, Check, Copy, Scan, X } from 'lucide-react';

// Sub-pages
import CitizenHome from './citizen/Home';
import SubsidyWallet from './citizen/SubsidyWallet';
import CitizenHistory from './citizen/History';
import Profile from './citizen/Profile';
import BottomNav from './citizen/BottomNav';

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

    useEffect(() => {
        const savedKeys = JSON.parse(localStorage.getItem('alacard_keys'));
        const savedToken = JSON.parse(localStorage.getItem('alacard_token'));
        const savedCitizenId = localStorage.getItem('alacard_citizen_id');

        if (savedKeys) setKeys(savedKeys);
        if (savedToken) setToken(savedToken);
        if (savedCitizenId) setCitizenId(savedCitizenId);
    }, []);

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
                try {
                    const pk = await importPrivateKeyJwk(keys.privateKeyJwk);
                    // Use seconds for consistency with backend expectation if needed
                    // But backend check allows 60s skew.
                    const p = await generateProof({
                        token,
                        nonce: Math.floor(Date.now() / 1000).toString(),
                        walletPrivateKey: pk
                    });

                    // Get Location for Proximity Check
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
                            console.warn("Location denied/unavailable");
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
    }, [viewMode, token, keys, claimAmount]);

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
                    <Profile onNavigate={(tab) => setActiveTab(tab)} />
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

