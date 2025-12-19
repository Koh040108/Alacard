import React, { useState, useEffect, useRef } from 'react';
import api from '../utils/api';
import { TerminalSquare, CheckCircle, XCircle, RefreshCw, ShieldCheck, AlertCircle, MapPin, Fuel } from 'lucide-react';
import { Html5QrcodeScanner, Html5QrcodeSupportedFormats } from 'html5-qrcode';

const Terminal = () => {
    const [nonce, setNonce] = useState('');
    const [proofInput, setProofInput] = useState('');
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);
    const [processedProof, setProcessedProof] = useState('');
    const [cameraError, setCameraError] = useState('');
    const [debugLog, setDebugLog] = useState(`API: ${api.defaults.baseURL}`);
    const [location, setLocation] = useState({ state: 'Selangor', city: 'Petaling Jaya' });
    const [riskData, setRiskData] = useState(null);

    // Claim State
    const [claimAmount, setClaimAmount] = useState(50);
    const [isUserRequested, setIsUserRequested] = useState(false);
    const [claimStatus, setClaimStatus] = useState(null); // 'claiming', 'success', 'error'
    const [claimResult, setClaimResult] = useState(null);

    const scannerRef = useRef(null);

    const locations = [
        { state: 'Selangor', city: 'Petaling Jaya' },
        { state: 'Perak', city: 'Ipoh' },
        { state: 'Penang', city: 'George Town' },
        { state: 'Johor', city: 'Johor Bahru' },
        { state: 'Sabah', city: 'Kota Kinabalu' },
        { state: 'Sarawak', city: 'Kuching' }
    ];

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
            setRiskData(null);
            setClaimStatus(null);
            setClaimResult(null);
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

        console.log("Raw QR Input:", proofInput);

        setLoading(true);
        try {
            let proof;
            let walletLoc = null;
            let requestedAmount = null;

            let json = JSON.parse(proofInput);

            // Handle double-stringified JSON (common in QR scanning of strings)
            if (typeof json === 'string') {
                console.log("Detected double-encoded JSON, parsing again...");
                json = JSON.parse(json);
            }

            // 1. Extract Proof
            if (json.proof) {
                proof = json.proof;
            } else {
                proof = json; // Legacy direct proof
            }

            // 2. Extract Location (Support multiple keys)
            if (json.loc) walletLoc = json.loc;
            else if (json.wallet_location) walletLoc = json.wallet_location;
            else if (json.location) walletLoc = json.location;

            // 3. Normalize Location to { lat, lng }
            if (walletLoc) {
                if (walletLoc.latitude && !walletLoc.lat) {
                    walletLoc = { lat: walletLoc.latitude, lng: walletLoc.longitude };
                }
            }

            // 4. Extract Amount
            if (json.claim_amount) requestedAmount = json.claim_amount;

            if (requestedAmount && !isNaN(parseFloat(requestedAmount))) {
                setClaimAmount(parseFloat(requestedAmount));
                setIsUserRequested(true);
            } else {
                setClaimAmount(50); // Default
                setIsUserRequested(false);
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
            // DEBUG: Alert user to confirm data quality
            const debugMsg = `DEBUG PRE-SEND CHECK:\n\nWallet Loc: ${walletLoc ? JSON.stringify(walletLoc) : 'MISSING/NULL'}\nTerminal Loc: ${JSON.stringify(location)}\n\nClick OK to send to Server.`;
            alert(debugMsg);

            console.log("sending to backend:", { walletLoc, location });
            const res = await api.post('/verify-token', {
                proof: proof,
                terminal_id: 'TERM-001',
                location: location, // Terminal Location
                wallet_location: walletLoc // Wallet Location (from QR)
            });

            setRiskData(res.data.risk);

            if (res.data.status === 'ELIGIBLE') {
                setResult('ELIGIBLE');
            } else if (res.data.status === 'BLOCKED_FRAUD') {
                setResult('BLOCKED_FRAUD');
            } else if (res.data.status === 'WARNING') {
                setResult('WARNING');
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

    const handleClaim = async () => {
        if (!processedProof) return;
        setClaimStatus('claiming');
        try {
            const json = JSON.parse(processedProof);
            // Support both wrapper format and direct format
            const proofObj = json.proof ? ((typeof json.proof === 'string') ? JSON.parse(json.proof) : json.proof) : json;

            // Fallback: Check 't' (standard) or 'token' (legacy/direct)
            let actualToken;
            if (proofObj.t) actualToken = proofObj.t;
            else if (proofObj.token) actualToken = proofObj.token;
            else throw new Error("Could not extract token from proof");

            const res = await api.post('/claim-subsidy', {
                token: actualToken,
                amount: parseFloat(claimAmount)
            });

            setClaimResult(res.data);
            setClaimStatus('success');
        } catch (err) {
            console.error(err);
            setClaimStatus('error');
            alert(err.response?.data?.error || "Claim Failed");
        }
    };

    return (
        <div className="p-6 max-w-lg mx-auto space-y-8 animate-in slide-in-from-bottom-5 duration-500">
            <h1 className="text-3xl font-bold text-center bg-clip-text text-transparent bg-gradient-to-r from-green-400 to-teal-500">
                Verification Terminal
            </h1>
            <p className="text-[10px] text-center text-slate-500 font-mono">v1.2 - Debug Patch Loaded</p>

            {/* Location Selector */}
            <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700 flex flex-col gap-2">
                <div className="flex justify-between items-center">
                    <span className="text-gray-400 text-sm">Terminal Location:</span>
                    {location.latitude ? (
                        <span className="text-green-400 text-xs font-mono">
                            GPS: {location.latitude.toFixed(4)}, {location.longitude.toFixed(4)}
                        </span>
                    ) : null}
                </div>

                <div className="flex gap-2">
                    <select
                        value={location.state === 'Custom' ? '' : location.state}
                        onChange={(e) => {
                            const sel = locations.find(l => l.state === e.target.value);
                            if (sel) setLocation(sel);
                        }}
                        className="flex-1 bg-slate-900 text-white border border-slate-600 rounded px-2 py-2 text-sm outline-none focus:border-green-500"
                    >
                        <option value="" disabled>-- Select Simulation --</option>
                        {locations.map(l => (
                            <option key={l.state} value={l.state}>{l.city}, {l.state}</option>
                        ))}
                    </select>

                    <button
                        onClick={() => {
                            navigator.geolocation.getCurrentPosition(
                                (pos) => {
                                    setLocation({
                                        state: 'Custom', // Marker for frontend logic
                                        city: 'Detected Location',
                                        latitude: pos.coords.latitude,
                                        longitude: pos.coords.longitude
                                    });
                                },
                                (err) => alert("Location Access Denied")
                            );
                        }}
                        className="bg-blue-600 hover:bg-blue-500 text-white p-2 rounded transition-colors"
                        title="Use Real Device Location"
                    >
                        <MapPin size={18} />
                    </button>
                </div>
            </div>

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
                <div className={`glass-panel p-8 text-center animate-in zoom-in-95 duration-300 border-2 ${result === 'ELIGIBLE' ? 'border-green-500 bg-green-500/10' :
                    result === 'BLOCKED_FRAUD' ? 'border-red-600 bg-red-900/20' :
                        result === 'WARNING' ? 'border-orange-500 bg-orange-500/10' :
                            'border-red-500 bg-red-500/10'
                    }`}>
                    {result === 'ELIGIBLE' ? (
                        <>
                            <CheckCircle className="w-16 h-16 text-green-500 mx-auto mb-4" />
                            <h2 className="text-3xl font-bold text-white mb-2">ELIGIBLE</h2>
                            <p className="text-green-200">Subsidy Approved</p>
                        </>
                    ) : result === 'BLOCKED_FRAUD' ? (
                        <>
                            <ShieldCheck className="w-16 h-16 text-red-500 mx-auto mb-4 animate-pulse" />
                            <h2 className="text-3xl font-bold text-red-500 mb-2">RISK DETECTED</h2>
                            <p className="text-red-300 mb-4">Transaction Blocked by AI Engine</p>
                        </>
                    ) : result === 'WARNING' ? (
                        <>
                            <AlertCircle className="w-16 h-16 text-orange-500 mx-auto mb-4" />
                            <h2 className="text-3xl font-bold text-orange-400 mb-2">WARNING</h2>
                            <p className="text-orange-200 mb-4">Unusual Activity Detected</p>
                        </>
                    ) : (
                        <>
                            <XCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
                            <h2 className="text-3xl font-bold text-white mb-2">NOT ELIGIBLE</h2>
                            <p className="text-red-200">Verification Failed</p>
                        </>
                    )}

                    {/* AI Risk Analysis Details */}
                    {riskData && riskData.score > 0 && (
                        <div className="mt-6 text-left bg-slate-900/50 p-4 rounded-lg border border-slate-700">
                            <div className="flex justify-between items-center mb-2">
                                <span className="text-xs text-gray-400 uppercase font-bold">AI Risk Score</span>
                                <span className={`text-lg font-bold font-mono ${riskData.score > 60 ? 'text-red-500' :
                                    riskData.score > 20 ? 'text-orange-400' : 'text-green-400'
                                    }`}>
                                    {riskData.score}/100
                                </span>
                            </div>

                            {/* Progress Bar */}
                            <div className="w-full bg-slate-700 h-2 rounded-full mb-3 overflow-hidden">
                                <div
                                    className={`h-full transition-all duration-1000 ${riskData.score > 60 ? 'bg-red-600' :
                                        riskData.score > 20 ? 'bg-orange-500' : 'bg-green-500'
                                        }`}
                                    style={{ width: `${riskData.score}%` }}
                                ></div>
                            </div>

                            <div className="space-y-1">
                                {riskData.reasons.map((reason, idx) => (
                                    <div key={idx} className="flex items-start gap-2 text-xs text-gray-300">
                                        <span className="text-red-400 font-bold">•</span>
                                        {reason}
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {result === 'ELIGIBLE' && (
                        <div className="mt-6 border-t border-slate-700 pt-6">
                            {!claimStatus ? (
                                <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2">
                                    <h3 className="text-lg font-bold text-white flex items-center justify-center gap-2">
                                        <Fuel size={20} className="text-yellow-400" /> Pump Authorization
                                    </h3>



                                    <div className={`flex items-center justify-center gap-2 bg-slate-900 p-2 rounded border border-slate-700 ${isUserRequested ? 'opacity-50 pointer-events-none' : ''}`}>
                                        <span className="text-gray-400 text-sm">Amount: RM</span>
                                        <input
                                            type="number"
                                            value={claimAmount}
                                            readOnly={isUserRequested}
                                            onChange={e => setClaimAmount(e.target.value)}
                                            className="bg-transparent w-20 text-xl font-bold text-white outline-none border-b border-gray-600 focus:border-yellow-400 transition-colors"
                                        />
                                    </div>

                                    <button
                                        onClick={handleClaim}
                                        className="w-full btn-primary bg-gradient-to-r from-yellow-600 to-orange-600 hover:from-yellow-500 hover:to-orange-500 text-white font-bold py-3 rounded-lg shadow-lg transform active:scale-95 transition-all"
                                    >
                                        Authorize Pump
                                    </button>
                                </div>
                            ) : claimStatus === 'claiming' ? (
                                <div className="text-center py-4 text-yellow-500 animate-pulse">
                                    Processing Claim...
                                </div>
                            ) : claimStatus === 'success' ? (
                                <div className="bg-green-500/20 border border-green-500/50 p-4 rounded-lg animate-in zoom-in">
                                    <h3 className="text-xl font-bold text-green-300 mb-1">Transaction Approved</h3>
                                    <p className="text-white text-sm mb-2">Subsidy Claimed Successfully</p>
                                    <div className="font-mono text-xs text-green-200 opacity-80">
                                        Remaining Quota: RM {claimResult?.remaining?.toFixed(2)}
                                    </div>
                                    <button
                                        onClick={() => { setNonce(''); setProofInput(''); setProcessedProof(''); setResult(null); setClaimStatus(null); }}
                                        className="mt-4 text-xs bg-green-900/50 hover:bg-green-800 text-green-200 py-2 px-4 rounded border border-green-700 transition-colors"
                                    >
                                        Start Next Session
                                    </button>
                                </div>
                            ) : (
                                <button
                                    onClick={() => setClaimStatus(null)}
                                    className="text-red-400 text-sm underline hover:text-red-300"
                                >
                                    Transaction Failed. Try Again.
                                </button>
                            )}

                            {result === 'ELIGIBLE' && !claimStatus && (
                                <div className="mt-4 p-2 bg-black/20 rounded text-xs text-green-300 font-mono">
                                    Audit Logged: {new Date().toLocaleTimeString()}
                                </div>
                            )}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default Terminal;
