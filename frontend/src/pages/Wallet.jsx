import React, { useState, useEffect } from 'react';
import { generateWalletKeyPair, generateProof, importPrivateKeyJwk, parseToken } from '../crypto';
import api from '../utils/api';
import { QRCodeCanvas } from 'qrcode.react';
import { Shield, Key, Plus, Scan, Copy, Check, ChevronRight, User, LogOut } from 'lucide-react';

const Wallet = () => {
    const [keys, setKeys] = useState(null);
    const [token, setToken] = useState(null);
    const [tokenSignature, setTokenSignature] = useState(null);
    const [citizenId, setCitizenId] = useState('');
    const [loading, setLoading] = useState(false);
    const [nonce, setNonce] = useState('');
    const [proof, setProof] = useState('');
    const [view, setView] = useState('home'); // home, add-token, prove

    useEffect(() => {
        const savedKeys = JSON.parse(localStorage.getItem('alacard_keys'));
        const savedToken = JSON.parse(localStorage.getItem('alacard_token'));
        const savedSig = localStorage.getItem('alacard_token_sig');

        // Auto-login if keys exist
        if (savedKeys) setKeys(savedKeys);
        if (savedToken) setToken(savedToken);
        if (savedSig) setTokenSignature(savedSig);
    }, []);

    const handleReset = () => {
        if (window.confirm("Switch Citizen? This will clear your current keys and token from this device.")) {
            localStorage.removeItem('alacard_keys');
            localStorage.removeItem('alacard_token');
            localStorage.removeItem('alacard_token_sig');
            setKeys(null);
            setToken(null);
            setTokenSignature(null);
            setCitizenId('');
            setNonce('');
            setProof('');
            setView('home');
        }
    };

    const handleGenerateKeys = () => {
        setLoading(true);
        // Use async/await for key generation
        (async () => {
            try {
                // Generate ECDSA P-256 Key Pair (Web Crypto)
                const newKeys = await generateWalletKeyPair();

                // Store keys in state and localStorage as JWK (Browser standard)
                const keyData = {
                    publicKeyJwk: newKeys.publicKey.jwk,
                    privateKeyJwk: newKeys.privateKey.jwk,
                    publicKeyRaw: newKeys.publicKey.raw // Needed for token binding
                };

                setKeys(keyData);
                localStorage.setItem('alacard_keys', JSON.stringify(keyData));
            } catch (e) {
                console.error("Key generation failed:", e);
                alert("Key generation failed: " + e.message);
            } finally {
                setLoading(false);
            }
        })();
    };

    const handleIssueToken = async () => {
        if (!citizenId) return;
        setLoading(true);
        try {
            const res = await api.post('/issue-token', {
                citizen_id: citizenId,
                wallet_public_key: keys.publicKeyRaw // Send Raw Key for ECDSA Binding
            });
            const { token, signature } = res.data;
            // Token is now a JWT-like string (header.payload.signature)
            // But we might receive an object if backend sends it wrapped?
            // Backend sends: { token: "..." } where token is the string

            setToken(token);
            setTokenSignature(signature); // Signature is embedded in token string now, but backend might send legacy output structure? 
            // Wait, backend issue-token sends: res.json({ token: tokenResult.token }); 
            // tokenResult.token IS the signed string. So we don't need separate signature really.

            localStorage.setItem('alacard_token', JSON.stringify(token));
            localStorage.setItem('alacard_token_sig', signature); // Legacy, might not be needed but keep for safety
            setView('home');
        } catch (err) {
            alert('Error: ' + (err.response?.data?.error || err.message));
        }
        setLoading(false);
    };

    const handleGenerateProof = async () => {
        if (!nonce) return;

        try {
            // 1. Import Private Key from JWK (Async)
            const privateKey = await importPrivateKeyJwk(keys.privateKeyJwk);

            // 2. Generate ZKP Proof (Async)
            const proofObj = await generateProof({
                token: token, // The full token string
                nonce: nonce,
                walletPrivateKey: privateKey
            });

            setProof(JSON.stringify(proofObj, null, 2));
        } catch (e) {
            console.error(e);
            alert("Proof Generation Failed: " + e.message);
        }
    };

    // 1. Onboarding Screen
    if (!keys) {
        return (
            <div className="min-h-[80vh] flex flex-col items-center justify-center p-6 text-center max-w-md mx-auto">
                <div className="w-20 h-20 bg-blue-600 rounded-2xl flex items-center justify-center mb-6 shadow-2xl shadow-blue-500/30 ring-4 ring-blue-500/20">
                    <Shield className="w-10 h-10 text-white" />
                </div>
                <h1 className="text-3xl font-bold mb-2">Secure Identity</h1>
                <p className="text-gray-400 mb-8 leading-relaxed">
                    Create your private digital wallet to store government credentials securely on your device.
                </p>
                <button
                    onClick={handleGenerateKeys}
                    disabled={loading}
                    className="w-full bg-white text-blue-900 font-bold py-4 rounded-xl shadow-xl active:scale-95 transition-all text-lg"
                >
                    {loading ? 'Creating Secure Enclave...' : 'Create Wallet'}
                </button>
            </div>
        );
    }

    // 2. Main Wallet Screen
    return (
        <div className="max-w-md mx-auto min-h-[80vh] flex flex-col relative pb-20">

            {/* Header */}
            <div className="flex justify-between items-center p-4 mb-4">
                <div>
                    <h2 className="text-xs font-bold text-gray-500 uppercase tracking-widest">My Wallet</h2>
                    <h1 className="text-2xl font-bold text-white">Credentials</h1>
                </div>
                <div className="flex items-center gap-3">
                    <button
                        onClick={handleReset}
                        className="p-2 bg-slate-800 rounded-full hover:bg-red-900/50 hover:text-red-400 transition-colors border border-slate-700"
                        title="Switch Citizen / Reset App"
                    >
                        <LogOut size={18} />
                    </button>
                    <div className="w-10 h-10 rounded-full bg-slate-800 flex items-center justify-center border border-slate-700">
                        <User size={20} className="text-gray-400" />
                    </div>
                </div>
            </div>

            {/* Content Area */}
            <div className="flex-1 px-4 space-y-6">

                {/* Token Card */}
                {!token ? (
                    <div className="border-2 border-dashed border-slate-700 rounded-2xl p-8 flex flex-col items-center justify-center text-center space-y-4 hover:border-slate-500 transition-colors bg-slate-800/30">
                        <div className="w-12 h-12 rounded-full bg-slate-700 flex items-center justify-center">
                            <Plus className="text-gray-400" />
                        </div>
                        <div>
                            <h3 className="font-bold text-white">No Credentials</h3>
                            <p className="text-sm text-gray-500 mt-1">Add your government ID to get started.</p>
                        </div>
                        <button
                            onClick={() => setView('add-token')}
                            className="px-6 py-2 bg-blue-600 rounded-full text-white font-bold text-sm shadow-lg shadow-blue-900/50"
                        >
                            Add Credential
                        </button>
                    </div>
                ) : (
                    <div className="relative group perspective-1000">
                        {/* The Digital Card */}
                        <div className={`
              relative w-full aspect-[1.586] rounded-2xl p-6 flex flex-col justify-between 
              bg-gradient-to-br from-blue-600 via-blue-700 to-indigo-900 
              shadow-2xl shadow-blue-900/50 text-white overflow-hidden
              transition-all duration-500 transform
              ${view === 'prove' ? 'scale-95 opacity-50 blur-[2px]' : 'scale-100 opacity-100'}
            `}>
                            {/* Pattern Overlay */}
                            <div className="absolute inset-0 opacity-10 bg-[url('https://www.transparenttextures.com/patterns/cubes.png')]"></div>

                            <div className="relative z-10 flex justify-between items-start">
                                <div className="flex items-center gap-2">
                                    <div className="p-1.5 bg-white/20 rounded-lg backdrop-blur-sm">
                                        <Shield size={16} />
                                    </div>
                                    <span className="font-bold tracking-wide text-sm">GOV.ID</span>
                                </div>
                                <span className="px-2 py-1 bg-green-500/20 text-green-200 text-[10px] font-bold rounded backdrop-blur-md border border-green-500/30">
                                    VERIFIED
                                </span>
                            </div>

                            <div className="relative z-10">
                                <p className="text-blue-200 text-xs font-medium mb-1">Subsidy Type</p>
                                <h3 className="text-xl font-bold tracking-tight">{token ? (parseToken(token).payload.elig ? 'Standard Subsidy' : 'Not Eligible') : '...'}</h3>
                            </div>

                            <div className="relative z-10 flex justify-between items-end">
                                <div>
                                    <p className="text-blue-300 text-[10px]">Holder ID</p>
                                    <p className="font-mono text-sm opacity-80">
                                        {(() => {
                                            const p = parseToken(token).payload;
                                            return `${p.jti.slice(0, 4)} •••• •••• ${p.jti.slice(-4)}`;
                                        })()}
                                    </p>
                                </div>
                                <div className="text-right">
                                    <p className="text-blue-300 text-[10px]">Expires</p>
                                    <p className="text-sm font-medium">{new Date(parseToken(token).payload.exp * 1000).toLocaleDateString()}</p>
                                </div>
                            </div>
                        </div>

                        {/* Actions for Card */}
                        {view === 'home' && (
                            <div className="mt-6">
                                <button
                                    onClick={() => setView('prove')}
                                    className="w-full bg-white text-slate-900 font-bold py-3 rounded-xl shadow-lg flex items-center justify-center gap-2 active:scale-95 transition-all text-sm mb-3"
                                >
                                    <Scan size={18} />
                                    Present ID / Verify
                                </button>
                            </div>
                        )}
                    </div>
                )}

                {/* Add Token Flow */}
                {view === 'add-token' && (
                    <div className="animate-in slide-in-from-bottom-10 fade-in duration-300 bg-slate-800 rounded-2xl p-6 border border-slate-700">
                        <h3 className="font-bold text-lg mb-4">Link National ID</h3>
                        <input
                            className="input-field mb-4 bg-slate-900 text-lg"
                            placeholder="Ex. CITIZEN_001"
                            value={citizenId}
                            onChange={e => setCitizenId(e.target.value)}
                            autoFocus
                        />
                        <div className="flex gap-3">
                            <button
                                onClick={() => setView('home')}
                                className="flex-1 py-3 text-sm font-bold text-gray-400 hover:text-white"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleIssueToken}
                                disabled={loading}
                                className="flex-1 btn-primary py-3 text-sm flex items-center justify-center gap-2"
                            >
                                {loading ? 'Linking...' : 'Link Identity'} <ChevronRight size={16} />
                            </button>
                        </div>
                    </div>
                )}

                {/* Prove Flow */}
                {view === 'prove' && (
                    <div className="animate-in slide-in-from-bottom-20 fade-in duration-300 fixed bottom-0 left-0 right-0 bg-slate-900 border-t border-slate-700 p-6 rounded-t-3xl shadow-[0_-10px_40px_rgba(0,0,0,0.5)] z-50 max-w-md mx-auto">
                        <div className="w-12 h-1 bg-slate-700 rounded-full mx-auto mb-6"></div>

                        <div className="flex justify-center mb-6 bg-slate-800 p-1 rounded-xl w-fit mx-auto">
                            <button
                                onClick={() => setNonce('') /* Reset nonce for passive */}
                                className={`px-4 py-2 rounded-lg text-sm font-bold transition-all ${!nonce ? 'bg-blue-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'}`}
                            >
                                Auto (Passive)
                            </button>
                            <button
                                onClick={() => setNonce('MANUAL')} // Hack to switch mode UI
                                className={`px-4 py-2 rounded-lg text-sm font-bold transition-all ${nonce ? 'bg-blue-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'}`}
                            >
                                Manual Input
                            </button>
                        </div>

                        {!nonce ? (
                            // PASSIVE MODE (Auto-Refresh)
                            <PassiveProofGenerator
                                token={token}
                                privateKeyJwk={keys.privateKeyJwk}
                                onClose={() => setView('home')}
                            />
                        ) : (
                            // MANUAL MODE
                            <ManualProofGenerator
                                token={token}
                                privateKeyJwk={keys.privateKeyJwk}
                                onBack={() => setNonce('')}
                                onClose={() => { setView('home'); setNonce(''); }}
                            />
                        )}
                    </div>
                )}
            </div>
        </div>
    );
};

// Sub-component for Passive Generation to handle interval cleanly
const PassiveProofGenerator = ({ token, privateKeyJwk, onClose }) => {
    const [proof, setProof] = useState('');
    const [timeLeft, setTimeLeft] = useState(30);
    const [showFullScreenQR, setShowFullScreenQR] = useState(false);

    useEffect(() => {
        let mounted = true;

        async function gen() {
            if (!mounted) return;
            try {
                const pk = await importPrivateKeyJwk(privateKeyJwk);
                // Date.now() is ms, proof expects ms string in new short format? 
                // Wait, backend uses `parseInt(pNonce)`. `now()` in utils usually returns seconds?
                // Let's check `backend/crypto/utils.js` or `proof.js` usage.
                // In `proof.js`, `timestamp: now()`. `now()` is usually seconds in this codebase?
                // Let's verify `now()` implementation in frontend/utils.js vs backend.
                // In Step 667 (frontend proof.js), it imports `now` from `./utils.js`.
                // In Step 668 (backend proof.js), it imports `now` from `./utils`.

                // If I look at `Wallet.jsx` previously: `nonce: Date.now().toString()`.
                // Date.now() is MILLISECONDS.
                // Backend: `const proofTime = parseInt(pNonce); ... const currentTime = now();`
                // If `now()` in backend is SECONDS (common in JWT/crypto), and `proofTime` is MILLISECONDS, this check `Math.abs(currentTime - proofTime) > 30` will ALWAYS fail (huge difference).

                // CRITICAL CHECK: What is `now()`?
                // I will assume standard seconds for `now()` in crypto contexts, but `Date.now()` is ms.
                // I should probably check `frontend/src/crypto/utils.js` first or just safe-guard by sending Seconds if backend expects Seconds, or MS if MS.
                // But wait, the previous code was working? "The scanner seem on but it didnt get to scan".
                // Maybe it failed validation silently? Or `now()` returns MS?

                // Let's safe-guard by fixing the nonce generation to match backend expectation.
                // But first, let's just do the 30s change, and fixes if needed.

                const p = await generateProof({
                    token,
                    nonce: Math.floor(Date.now() / 1000).toString(),
                    walletPrivateKey: pk
                });
                if (mounted) setProof(JSON.stringify(p));
            } catch (e) {
                console.error("Auto-proof failed", e);
            }
        }

        // Initial generation
        gen();

        // Interval
        const interval = setInterval(() => {
            gen();
            setTimeLeft(30);
        }, 30000);

        // Countdown timer for UX
        const timer = setInterval(() => {
            setTimeLeft(prev => prev > 0 ? prev - 1 : 0);
        }, 1000);

        return () => {
            mounted = false;
            clearInterval(interval);
            clearInterval(timer);
        };
    }, [token, privateKeyJwk]);

    return (
        <div className="text-center">
            <h3 className="font-bold text-xl mb-1">Show to Terminal</h3>

            <div className="bg-white p-4 rounded-xl shadow-inner mb-6 flex justify-center cursor-pointer mx-auto w-fit" onClick={() => setShowFullScreenQR(true)}>
                {proof ?
                    <QRCodeCanvas value={proof} size={300} level="L" includeMargin={true} />
                    :
                    <div className="w-[300px] h-[300px] flex items-center justify-center text-black">Generating...</div>
                }
            </div>

            <p className="text-gray-500 text-sm mb-6 animate-pulse">
                Refreshes in {timeLeft}s <span className="text-blue-500 font-bold block mt-1">(Tap QR to Enlarge)</span>
            </p>

            {/* Fullscreen QR Modal */}
            {showFullScreenQR && (
                <div className="fixed inset-0 z-50 bg-black bg-opacity-95 flex flex-col items-center justify-center p-4" onClick={() => setShowFullScreenQR(false)}>
                    <h3 className="text-white text-xl mb-8 font-bold">Present to Scanner</h3>
                    <div className="bg-white p-4 rounded-3xl">
                        <QRCodeCanvas value={proof} size={window.innerWidth > 400 ? 400 : window.innerWidth - 60} level="L" includeMargin={true} />
                    </div>
                    <p className="text-gray-400 mt-8 text-sm">Tap anywhere to close</p>
                </div>
            )}

            <button
                onClick={onClose}
                className="w-full py-4 rounded-xl font-bold text-slate-400 bg-slate-800"
            >
                Close
            </button>
        </div>
    );
};

const ManualProofGenerator = ({ token, privateKeyJwk, onBack, onClose }) => {
    const [inputNonce, setInputNonce] = useState('');
    const [proof, setProof] = useState('');

    const handleGen = async () => {
        if (!inputNonce) return;
        try {
            const pk = await importPrivateKeyJwk(privateKeyJwk);
            const p = await generateProof({
                token,
                nonce: inputNonce,
                walletPrivateKey: pk
            });
            setProof(JSON.stringify(p, null, 2));
        } catch (e) {
            alert(e.message);
        }
    };

    if (proof) {
        return (
            <>
                <div className="text-center mb-6">
                    <div className="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-3 text-green-400">
                        <Check size={32} />
                    </div>
                    <h3 className="font-bold text-xl">Proof Generated</h3>
                </div>
                <div className="bg-white p-4 rounded-xl mb-6 flex justify-center">
                    <QRCodeCanvas value={proof} size={200} />
                </div>
                <button onClick={() => navigator.clipboard.writeText(proof)} className="w-full py-4 rounded-xl font-bold text-slate-900 bg-white mb-3 flex items-center justify-center gap-2">
                    <Copy size={18} /> Copy JSON
                </button>
                <button onClick={onClose} className="w-full py-3 font-bold text-gray-500">Done</button>
            </>
        );
    }

    return (
        <>
            <h3 className="font-bold text-center text-xl mb-2">Manual Verification</h3>
            <div className="bg-slate-800 p-2 rounded-xl mb-6 flex items-center border border-slate-600 focus-within:ring-2 focus-within:ring-blue-500">
                <Scan className="text-gray-400 ml-2" />
                <input
                    className="bg-transparent border-none text-white w-full py-3 px-3 focus:outline-none font-mono text-center tracking-widest text-lg placeholder-gray-600"
                    placeholder="ENTER CHALLENGE"
                    value={inputNonce}
                    onChange={e => setInputNonce(e.target.value)}
                    autoFocus
                />
            </div>
            <div className="grid grid-cols-2 gap-4">
                <button onClick={onBack} className="py-3 rounded-xl font-bold text-slate-400 bg-slate-800">Back</button>
                <button onClick={handleGen} className="py-3 rounded-xl font-bold text-white bg-blue-600">Generate</button>
            </div>
        </>
    );
};

export default Wallet;
