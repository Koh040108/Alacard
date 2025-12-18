import React, { useState, useEffect, useRef } from 'react';
import api from '../utils/api';
import { TerminalSquare, CheckCircle, XCircle, RefreshCw, ShieldCheck } from 'lucide-react';
import { Html5QrcodeScanner, Html5QrcodeSupportedFormats } from 'html5-qrcode';

const Terminal = () => {
    const [nonce, setNonce] = useState('');
    const [proofInput, setProofInput] = useState('');
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);
    const [processedProof, setProcessedProof] = useState('');
    const [cameraError, setCameraError] = useState('');
    const [debugLog, setDebugLog] = useState('Initializing...'); // DEBUG STATE
    const scannerRef = useRef(null);

    useEffect(() => {
        // Only initialize scanner if waiting for input (no active nonce session) and no manual input
        if (!nonce && !proofInput && !result) {

            if (scannerRef.current) return; // Prevent double-init

            const scanner = new Html5QrcodeScanner(
                "reader",
                {
                    fps: 10, // Lower FPS for stability
                    qrbox: { width: 250, height: 250 },
                    aspectRatio: 1.0,
                    // Remove Native Flag to ensure JS fallback works on all devices
                    formatsToSupport: [Html5QrcodeSupportedFormats.QR_CODE]
                },
                /* verbose= */ false
            );

            scannerRef.current = scanner;

            scanner.render((decodedText) => {
                setDebugLog(`Success: ${decodedText.substring(0, 10)}...`);
                // Success callback
                try {
                    console.log("Scanned:", decodedText);

                    // 1. Haptic Feedback
                    if (navigator.vibrate) navigator.vibrate(200);

                    // 2. Validate JSON
                    JSON.parse(decodedText);

                    setProofInput(decodedText);

                    // Stop scanning on success
                    scanner.clear().then(() => {
                        scannerRef.current = null;
                    }).catch(console.error);

                } catch (e) {
                    console.warn("Scanned invalid format");
                    setDebugLog("Invalid JSON Format");
                    // 3. User Feedback for Invalid Code
                    alert("Invalid QR Code Format. Please scan an Alacard proof.");
                }
            }, (error) => {
                // Error callback - capture permission errors (ignore transient errors)
                if (error?.message?.includes("No MultiFormat Readers")) {
                    setDebugLog("Scanning... (No QR found)");
                } else if (error?.name === "NotAllowedError") {
                    setCameraError("Camera Permission Denied!");
                } else {
                    // Catch-all info
                    setDebugLog(`Scanning... ${Math.floor(Date.now() / 1000) % 10}`);
                }
            });

            return () => {
                if (scannerRef.current) {
                    scannerRef.current.clear().catch(console.error);
                    scannerRef.current = null;
                }
            };
        }
    }, [nonce, proofInput, result]);

    // Use effect to auto-verify when proofInput is set from scanner
    useEffect(() => {
        if (proofInput && !nonce && proofInput !== processedProof) {
            handleVerify();
        }
    }, [proofInput, processedProof]); // Add processedProof dep

    const generateNonce = async () => {
        setLoading(true);
        try {
            // Fetch challenge from backend (required for server-side verification)
            const res = await api.post('/challenge', { terminalId: 'TERM-001' });
            setNonce(res.data.nonce);
            setProofInput('');
            setResult(null);
            setProcessedProof(''); // Reset processed proof
        } catch (err) {
            console.error("Failed to get challenge:", err);
            alert("Network Error: Could not reach backend challenge service.");
        }
        setLoading(false);
    };

    const handleVerify = async () => {
        if (!proofInput) return;

        // Prevent re-verifying the same proof (React StrictMode defense)
        if (proofInput === processedProof) return;
        setProcessedProof(proofInput);

        setLoading(true);
        try {
            let proof;
            try {
                proof = JSON.parse(proofInput);
            } catch (e) {
                throw new Error("Invalid Proof Format (JSON expected)");
            }

            // Client-side check: Ensure the proof corresponds to THIS session's nonce
            // Note: The proof object key is 'nonce', not 'challenge_nonce'

            // Only enforce nonce match if we are in an ACTIVE session (nonce is set)
            const pNonce = proof.n || proof.nonce;
            if (nonce && pNonce !== nonce) {
                throw new Error("Nonce mismatch! Possible Replay Attack.");
            }
            // If nonce is NOT set, we are in passive mode (timestamp nonce), server validates it.

            // Send to backend for formal verification and audit logging
            // The backend performs the same PKI checks we would do locally
            const res = await api.post('/verify-token', {
                proof: proof, // Wrap in proof object as expected by server
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

                {!nonce && !proofInput ? (
                    <div className="space-y-4">
                        <div id="reader" className="w-full bg-black rounded-xl overflow-hidden min-h-[300px]"></div>

                        {cameraError && (
                            <div className="p-3 bg-red-900/50 border border-red-500 rounded text-red-200 text-xs text-center">
                                {cameraError}
                            </div>
                        )}

                        {/* DEBUG OVERLAY */}
                        <p className="text-[10px] font-mono text-gray-600 text-center animate-pulse">
                            Status: {debugLog}
                        </p>

                        <p className="text-center text-xs text-gray-500">Scan User QR Code</p>

                        <div className="flex gap-2">
                            <button onClick={generateNonce} className="btn-secondary w-full flex justify-center items-center gap-2 text-xs">
                                <RefreshCw size={14} /> Manual Challenge (Active)
                            </button>
                        </div>
                    </div>
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

                        <button onClick={() => { setNonce(''); setProofInput(''); setProcessedProof(''); setResult(null); }} className="w-full text-xs text-gray-500 hover:text-white underline">
                            Cancel / Scan Again
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
