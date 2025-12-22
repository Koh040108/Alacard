import React, { useState, useEffect } from 'react';
import { ArrowLeft, Lock, Unlock, ChevronRight, Fingerprint } from 'lucide-react';
import api from '../../utils/api';

const SubsidyWallet = ({ onNavigate, onScan, token, citizenId }) => {
    const [tokenStatus, setTokenStatus] = useState('ACTIVE');
    const [myKadStatus, setMyKadStatus] = useState('ACTIVE'); // Mock state for Demo
    const [petrolBalance, setPetrolBalance] = useState(0);

    // Biometric State
    const [showBiometric, setShowBiometric] = useState(false);
    const [loading, setLoading] = useState(false);
    const [pendingAction, setPendingAction] = useState(null); // { type: 'freeze'|'unfreeze', target: 'budi'|'mykad' }

    useEffect(() => {
        const fetchStatus = () => {
            if (token) {
                api.post('/token-status', { token })
                    .then(res => setTokenStatus(res.data.status || 'ACTIVE'))
                    .catch(console.error);
            }
            if (citizenId) {
                api.post('/my-balance', { citizen_id: citizenId })
                    .then(res => setPetrolBalance(res.data.balance))
                    .catch(console.error);
            }
        };

        fetchStatus();

        // Auto-refresh every 3s to reflect terminal transactions quickly
        const interval = setInterval(fetchStatus, 3000);

        return () => clearInterval(interval);
    }, [token, citizenId]);

    const toggleFreeze = (e) => {
        e.stopPropagation(); // Prevent card click (scan)
        const type = tokenStatus === 'FROZEN' ? 'unfreeze' : 'freeze';
        setPendingAction({ type, target: 'budi' });
        setShowBiometric(true);
    };

    const toggleMyKad = (e) => {
        e.stopPropagation();
        const type = myKadStatus === 'FROZEN' ? 'unfreeze' : 'freeze';
        setPendingAction({ type, target: 'mykad' });
        setShowBiometric(true);
    };

    const handleBiometricSuccess = async () => {
        const { type, target } = pendingAction;
        setShowBiometric(false);
        setLoading(true);

        try {
            if (target === 'budi') {
                const action = type === 'freeze' ? '/freeze-token' : '/unfreeze-token';
                await api.post(action, { token });
                setTokenStatus(type === 'freeze' ? 'FROZEN' : 'ACTIVE');
            } else if (target === 'mykad') {
                // Mock API call simulation
                await new Promise(r => setTimeout(r, 500));
                setMyKadStatus(type === 'freeze' ? 'FROZEN' : 'ACTIVE');
            }
            alert(`Success: Token ${type === 'freeze' ? 'Frozen' : 'Activated'}`);
        } catch (err) {
            alert("Action failed: " + err.message);
        } finally {
            setLoading(false);
            setPendingAction(null);
        }
    };

    const simulatePump = async (e) => {
        e.stopPropagation();
        const amount = 50; // Simulate RM50 pump
        if (petrolBalance < amount) return alert("Insufficient Subsidy Quota!");

        try {
            const res = await api.post('/claim-subsidy', { token, citizen_id: citizenId, amount });
            setPetrolBalance(res.data.remaining);
            alert("Simulated RM50 Pump Successful!");
        } catch (err) {
            alert("Claim Failed: " + (err.response?.data?.error || err.message));
        }
    };

    return (
        <div className="bg-slate-50 min-h-screen pb-24 font-sans flex flex-col">
            {/* Header */}
            <div className="bg-blue-600 text-white pt-12 pb-6 px-6 rounded-b-3xl shadow-lg relative shrink-0">
                <button
                    onClick={() => onNavigate('home')}
                    className="flex items-center gap-1 font-bold text-sm mb-4 opacity-80 hover:opacity-100 transition-opacity"
                >
                    <ArrowLeft size={18} /> Back
                </button>
                <h1 className="text-2xl font-bold tracking-tight">Subsidy Token</h1>
                {citizenId && <p className="text-blue-200 text-xs font-mono mt-1 mb-1">ID: {citizenId}</p>}
                <p className="text-blue-100 text-xs">Manage your government entitlements</p>

                {/* Decorative Pattern */}
                <div className="absolute top-0 right-0 w-32 h-32 bg-white/10 rounded-bl-full blur-2xl"></div>
            </div>

            {/* Content */}
            <div className="flex-1 px-6 py-6 space-y-4 overflow-y-auto">
                <SubsidyCard
                    title="BUDI MADANI RON95"
                    subtitle={`Quota: RM ${petrolBalance.toFixed(2)}`}
                    color={petrolBalance > 0 ? "from-blue-600 to-blue-800" : "from-slate-600 to-slate-800 grayscale"}
                    logo="⛽"
                    onClick={() => {
                        if (petrolBalance <= 0) return;
                        // Prompt for interaction flow
                        const amountStr = prompt("Enter Claim Amount (RM):\n(Click OK with empty value to just verify eligibility)", "50");
                        if (amountStr === null) return; // Cancelled

                        const amount = parseFloat(amountStr);
                        onScan(!isNaN(amount) && amount > 0 ? amount : null);
                    }}
                    active={tokenStatus !== 'FROZEN' && petrolBalance > 0}
                    isFrozen={tokenStatus === 'FROZEN'}
                    onToggleFreeze={toggleFreeze}
                    extraAction={
                        <div className="flex gap-2">
                            <button
                                onClick={simulatePump}
                                disabled={petrolBalance <= 0 || tokenStatus === 'FROZEN'}
                                className="bg-white/20 hover:bg-white/30 text-white text-[10px] font-bold px-3 py-1.5 rounded-lg border border-white/10 backdrop-blur-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                Sim (-RM50)
                            </button>
                        </div>
                    }
                />

                <SubsidyCard
                    title="BANTUAN MYKAD"
                    subtitle="RM100 Cash Aid"
                    color="from-red-600 to-red-800"
                    logo="💵"
                    onClick={() => onScan()}
                    active={myKadStatus !== 'FROZEN'}
                    isFrozen={myKadStatus === 'FROZEN'}
                    onToggleFreeze={toggleMyKad}
                />

                <SubsidyCard
                    title="FLYSISWA"
                    subtitle="Student Flight Aid"
                    color="from-slate-200 to-slate-300"
                    textColor="text-slate-800"
                    logo="✈️"
                    onClick={() => alert("Not eligible for this timeline")}
                />
            </div>

            {/* Biometric Modal */}
            {showBiometric && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
                    <div className="bg-white w-full max-w-xs p-8 rounded-3xl shadow-2xl flex flex-col items-center text-center animate-in zoom-in-95" onClick={handleBiometricSuccess}>
                        <h3 className="text-lg font-bold text-slate-900 mb-2">Biometric Verification</h3>
                        <p className="text-slate-500 text-xs mb-8">Scan fingerprint to confirm action</p>

                        <div className="w-20 h-20 bg-red-50 rounded-full flex items-center justify-center mb-8 ring-4 ring-red-500/10 animate-pulse cursor-pointer">
                            <Fingerprint size={48} className="text-red-500" />
                        </div>

                        <p className="text-[10px] text-slate-400 uppercase tracking-widest font-bold">Touch Sensor</p>
                        <p className="text-[10px] text-slate-300 mt-2">(Click icon to simulate scan)</p>
                    </div>
                </div>
            )}
        </div>
    );
};

const SubsidyCard = ({ title, subtitle, color, textColor = "text-white", logo, onClick, active, isFrozen, onToggleFreeze, extraAction }) => (
    <div
        onClick={isFrozen ? undefined : onClick}
        className={`bg-gradient-to-r ${isFrozen ? 'from-slate-700 to-slate-800 grayscale' : color} ${textColor} p-1 rounded-2xl shadow-md cursor-pointer transition-all group relative overflow-hidden`}
    >
        <div className="bg-white/10 backdrop-blur-sm p-5 rounded-xl h-24 flex items-center justify-between border border-white/10">
            <div className="flex items-center gap-4">
                <div className="text-3xl bg-white/20 w-12 h-12 flex items-center justify-center rounded-lg shadow-inner">
                    {logo}
                </div>
                <div>
                    <h3 className="font-bold text-lg leading-tight flex items-center gap-2">
                        {title}
                        {isFrozen && <span className="text-[10px] bg-red-500 text-white px-2 py-0.5 rounded-full">FROZEN</span>}
                    </h3>
                    <p className="text-xs opacity-80 font-medium uppercase tracking-wider">{subtitle}</p>
                </div>
            </div>

            <div className="flex items-center gap-2">
                {extraAction}
                {onToggleFreeze && (
                    <button
                        onClick={onToggleFreeze}
                        className={`p-2 rounded-full backdrop-blur-md shadow-lg transition-transform hover:scale-110 active:scale-95 ${isFrozen ? 'bg-red-500 text-white' : 'bg-white/20 text-white hover:bg-white/30'
                            }`}
                        title={isFrozen ? "Unlock Token" : "Freeze Token"}
                    >
                        {isFrozen ? <Lock size={18} /> : <Unlock size={18} />}
                    </button>
                )}
                {!isFrozen && active && <ChevronRight className="opacity-50 group-hover:translate-x-1 transition-transform" />}
            </div>
        </div>

        {isFrozen && (
            <div className="absolute inset-0 bg-slate-900/10 pointer-events-none flex items-center justify-center">
                {/* Optional Overlay Pattern */}
            </div>
        )}
    </div>
);

export default SubsidyWallet;
