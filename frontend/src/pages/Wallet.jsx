import React, { useState, useEffect } from 'react';
import { generateKeyPair, signData } from '../utils/crypto';
import api from '../utils/api';
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
        setTimeout(() => {
            const newKeys = generateKeyPair();
            setKeys(newKeys);
            localStorage.setItem('alacard_keys', JSON.stringify(newKeys));
            setLoading(false);
        }, 500);
    };

    const handleIssueToken = async () => {
        if (!citizenId) return;
        setLoading(true);
        try {
            const res = await api.post('/issue-token', {
                citizen_id: citizenId,
                wallet_public_key: keys.publicKeyPem
            });
            const { token, signature } = res.data;
            setToken(token);
            setTokenSignature(signature);
            localStorage.setItem('alacard_token', JSON.stringify(token));
            localStorage.setItem('alacard_token_sig', signature);
            setView('home');
        } catch (err) {
            alert('Error: ' + (err.response?.data?.error || err.message));
        }
        setLoading(false);
    };

    const handleGenerateProof = () => {
        if (!nonce) return;

        const walletSignature = signData(nonce, keys.privateKeyPem);
        const proofData = {
            token,
            token_signature: tokenSignature,
            challenge_nonce: nonce,
            wallet_signature: walletSignature
        };

        setProof(JSON.stringify(proofData, null, 2));
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
                                <h3 className="text-xl font-bold tracking-tight">{token.subsidy_type}</h3>
                            </div>

                            <div className="relative z-10 flex justify-between items-end">
                                <div>
                                    <p className="text-blue-300 text-[10px]">Holder ID</p>
                                    <p className="font-mono text-sm opacity-80">{token.token_id.slice(0, 4)} •••• •••• {token.token_id.slice(-4)}</p>
                                </div>
                                <div className="text-right">
                                    <p className="text-blue-300 text-[10px]">Expires</p>
                                    <p className="text-sm font-medium">{new Date(token.expiry).toLocaleDateString()}</p>
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

                        {!proof ? (
                            <>
                                <h3 className="font-bold text-center text-xl mb-2">Scan & Verify</h3>
                                <p className="text-center text-gray-400 text-sm mb-6">Enter the code displayed on the terminal to prove eligibility securely.</p>

                                <div className="bg-slate-800 p-2 rounded-xl mb-6 flex items-center border border-slate-600 focus-within:ring-2 focus-within:ring-blue-500">
                                    <Scan className="text-gray-400 ml-2" />
                                    <input
                                        className="bg-transparent border-none text-white w-full py-3 px-3 focus:outline-none font-mono text-center tracking-widest text-lg placeholder-gray-600"
                                        placeholder="ENTER CODE"
                                        value={nonce}
                                        onChange={e => setNonce(e.target.value)}
                                        autoFocus
                                    />
                                </div>

                                <div className="grid grid-cols-2 gap-4">
                                    <button
                                        onClick={() => { setView('home'); setNonce(''); }}
                                        className="py-3 rounded-xl font-bold text-slate-400 bg-slate-800"
                                    >
                                        Cancel
                                    </button>
                                    <button
                                        onClick={handleGenerateProof}
                                        className="py-3 rounded-xl font-bold text-white bg-blue-600 shadow-lg shadow-blue-600/20 active:scale-95 transition-transform"
                                    >
                                        Generate Proof
                                    </button>
                                </div>
                            </>
                        ) : (
                            <>
                                <div className="text-center mb-6">
                                    <div className="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-3 text-green-400">
                                        <Check size={32} />
                                    </div>
                                    <h3 className="font-bold text-xl">Proof Generated</h3>
                                    <p className="text-gray-400 text-xs">This data proves your eligibility without revealing your personal income or ID.</p>
                                </div>

                                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 mb-6 relative group cursor-pointer" onClick={() => navigator.clipboard.writeText(proof)}>
                                    <div className="absolute top-2 right-2 text-xs bg-slate-800 px-2 py-1 rounded text-gray-400">JSON</div>
                                    <pre className="text-[10px] text-gray-500 font-mono h-24 overflow-hidden mask-linear-fade">
                                        {proof}
                                    </pre>
                                </div>

                                <button
                                    onClick={() => navigator.clipboard.writeText(proof)}
                                    className="w-full py-4 rounded-xl font-bold text-slate-900 bg-white shadow-lg active:scale-95 transition-transform flex items-center justify-center gap-2 mb-3"
                                >
                                    <Copy size={18} /> Copy Proof Code
                                </button>
                                <button
                                    onClick={() => { setProof(''); setNonce(''); setView('home'); }}
                                    className="w-full py-3 font-bold text-gray-500 text-sm"
                                >
                                    Done
                                </button>
                            </>
                        )}
                    </div>
                )}

            </div>
        </div>
    );
};

export default Wallet;
