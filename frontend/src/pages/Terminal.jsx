import React, { useState } from 'react';
import api from '../utils/api';
import { TerminalSquare, CheckCircle, XCircle, RefreshCw, ShieldCheck } from 'lucide-react';

const Terminal = () => {
    const [nonce, setNonce] = useState('');
    const [proofInput, setProofInput] = useState('');
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);

    const generateNonce = () => {
        const random = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
        setNonce(random);
        setProofInput('');
        setResult(null);
    };

    const handleVerify = async () => {
        if (!proofInput) return;
        setLoading(true);
        try {
            let proof;
            try {
                proof = JSON.parse(proofInput);
            } catch (e) {
                throw new Error("Invalid Proof Format (JSON expected)");
            }

            if (proof.challenge_nonce !== nonce) {
                throw new Error("Nonce mismatch! Possible Replay Attack.");
            }

            // Send to backend for formal verification and audit logging
            // The backend performs the same PKI checks we would do locally
            const res = await api.post('/verify-token', {
                ...proof,
                terminal_id: 'TERM-001'
            });

            if (res.data.status === 'ELIGIBLE') {
                setResult('ELIGIBLE');
            } else {
                setResult('NOT ELIGIBLE');
            }
        } catch (err) {
            console.error(err);
            setResult('NOT ELIGIBLE');
            alert(err.response?.data?.error || err.message);
        }
        setLoading(false);
    };

    return (
        <div className="p-6 max-w-lg mx-auto space-y-8 animate-in slide-in-from-bottom-5 duration-500">
            <h1 className="text-3xl font-bold text-center bg-clip-text text-transparent bg-gradient-to-r from-green-400 to-teal-500">
                Verification Terminal
            </h1>

            <div className="glass-panel p-6">
                <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                    <TerminalSquare className="text-green-400" /> Session Control
                </h2>

                {!nonce ? (
                    <button onClick={generateNonce} className="btn-primary w-full flex justify-center items-center gap-2">
                        <RefreshCw size={18} /> Start New Verification
                    </button>
                ) : (
                    <div className="space-y-4">
                        <div className="bg-slate-800 p-4 rounded border border-slate-600 text-center">
                            <p className="text-xs text-gray-400 uppercase tracking-widest mb-1">Challenge Nonce</p>
                            <p className="text-2xl font-mono text-white tracking-wider break-all">{nonce}</p>
                        </div>
                        <p className="text-xs text-center text-gray-400">Ask user to sign this nonce with their wallet.</p>

                        <div className="border-t border-slate-700 pt-4">
                            <label className="text-sm text-gray-300 mb-2 block">Paste Proof JSON here:</label>
                            <textarea
                                className="input-field h-32 font-mono text-xs"
                                value={proofInput}
                                onChange={e => setProofInput(e.target.value)}
                                placeholder='{"token": ..., "signature": ...}'
                            />
                        </div>

                        <button
                            onClick={handleVerify}
                            disabled={loading || !proofInput}
                            className={`w-full py-3 rounded font-bold text-white transition-all shadow-lg ${loading ? 'bg-gray-600' : 'bg-green-600 hover:bg-green-500 hover:scale-105'}`}
                        >
                            {loading ? 'Verifying with Government Node...' : 'Verify Eligibility'}
                        </button>

                        <button onClick={generateNonce} className="w-full text-xs text-gray-500 hover:text-white underline">
                            Reset / New Session
                        </button>
                    </div>
                )}
            </div>

            {result && (
                <div className={`glass-panel p-8 text-center animate-in zoom-in-95 duration-300 border-2 ${result === 'ELIGIBLE' ? 'border-green-500 bg-green-500/10' : 'border-red-500 bg-red-500/10'}`}>
                    {result === 'ELIGIBLE' ? (
                        <>
                            <CheckCircle className="w-16 h-16 text-green-500 mx-auto mb-4" />
                            <h2 className="text-3xl font-bold text-white mb-2">ELIGIBLE</h2>
                            <p className="text-green-200">Subsidy Approved</p>
                            <div className="mt-4 p-2 bg-black/20 rounded text-xs text-green-300 font-mono">
                                Audit Logged: {new Date().toLocaleTimeString()}
                            </div>
                        </>
                    ) : (
                        <>
                            <XCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
                            <h2 className="text-3xl font-bold text-white mb-2">NOT ELIGIBLE</h2>
                            <p className="text-red-200">Verification Failed</p>
                        </>
                    )}
                </div>
            )}
        </div>
    );
};

export default Terminal;
