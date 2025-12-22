import React, { useState, useEffect } from 'react';
import { User, Settings, Shield, Bell, LogOut, ChevronRight, HelpCircle, Lock, Unlock, Fingerprint, ChevronLeft } from 'lucide-react';
import api from '../../utils/api';

const Profile = ({ onNavigate, token, citizenId }) => {
    const [view, setView] = useState('main'); // main, security
    const [tokenStatus, setTokenStatus] = useState('ACTIVE');
    const [loading, setLoading] = useState(false);
    const [showBiometric, setShowBiometric] = useState(false);
    const [pendingAction, setPendingAction] = useState(null); // 'freeze' | 'unfreeze'

    // Fetch initial status
    useEffect(() => {
        if (view === 'security' && token) {
            checkStatus();
        }
    }, [view, token]);

    const checkStatus = async () => {
        if (!token) return;
        try {
            const res = await api.post('/token-status', { token });
            setTokenStatus(res.data.status);
        } catch (err) {
            console.error("Status check failed", err);
        }
    };

    const handleActionRequest = (action) => {
        setPendingAction(action);
        setShowBiometric(true);
    };

    const handleBiometricSuccess = async () => {
        setShowBiometric(false);
        setLoading(true);
        try {
            const endpoint = pendingAction === 'freeze' ? '/freeze-token' : '/unfreeze-token';
            await api.post(endpoint, { token });
            await checkStatus();
            alert(`Success: Token ${pendingAction === 'freeze' ? 'Frozen' : 'Activated'}`);
        } catch (err) {
            alert("Action Failed: " + err.message);
        } finally {
            setLoading(false);
            setPendingAction(null);
        }
    };

    // Sub-view: Security
    if (view === 'security') {
        return (
            <div className="bg-slate-50 min-h-screen pb-24 font-sans flex flex-col animate-in slide-in-from-right duration-300">
                <div className="bg-white px-6 pt-12 pb-6 shadow-sm sticky top-0 z-10 flex items-center gap-4">
                    <button onClick={() => setView('main')} className="p-2 -ml-2 rounded-full hover:bg-slate-100">
                        <ChevronLeft className="text-slate-600" />
                    </button>
                    <div>
                        <h1 className="text-xl font-bold text-slate-900">Security & Privacy</h1>
                        <p className="text-slate-500 text-xs">Manage detailed security settings</p>
                    </div>
                </div>

                <div className="p-6 space-y-6">
                    {/* Token Management Card */}
                    <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-100">
                        <h3 className="font-bold text-slate-800 mb-4 flex items-center gap-2">
                            <Shield size={18} className="text-blue-600" />
                            Manage Subsidy Tokens
                        </h3>

                        {/* Fake List for Demo */}
                        <div className="space-y-3">
                            {/* Petrol Token (Linked to Real Token) */}
                            <div className="flex items-center justify-between p-4 bg-slate-50 rounded-xl border border-slate-200">
                                <div>
                                    <p className="font-bold text-sm text-slate-700">Petrol Subsidy (RON95)</p>
                                    <p className="text-[10px] text-slate-400 font-mono">ID: {token ? token.substring(0, 12) + '...' : 'N/A'}</p>
                                    <div className={`mt-2 text-[10px] font-bold px-2 py-0.5 rounded w-fit ${tokenStatus === 'ACTIVE' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                                        {tokenStatus}
                                    </div>
                                </div>
                                <button
                                    onClick={() => handleActionRequest(tokenStatus === 'ACTIVE' ? 'freeze' : 'unfreeze')}
                                    disabled={loading}
                                    className={`p-3 rounded-full shadow-sm transition-all active:scale-95 ${tokenStatus === 'ACTIVE' ? 'bg-red-50 text-red-600 hover:bg-red-100' : 'bg-green-50 text-green-600 hover:bg-green-100'}`}
                                >
                                    {tokenStatus === 'ACTIVE' ? <Lock size={20} /> : <Unlock size={20} />}
                                </button>
                            </div>

                            {/* Dummy Diesel Token (Visual Only) */}
                            <div className="flex items-center justify-between p-4 bg-slate-50 rounded-xl border border-slate-200 opacity-60">
                                <div>
                                    <p className="font-bold text-sm text-slate-700">Diesel Subsidy</p>
                                    <p className="text-[10px] text-slate-400 font-mono">NOT ELIGIBLE</p>
                                </div>
                                <button disabled className="p-3 rounded-full bg-slate-100 text-slate-400 cursor-not-allowed">
                                    <Lock size={20} />
                                </button>
                            </div>
                        </div>

                        <div className="mt-6 pt-4 border-t border-slate-100">
                            <button
                                onClick={() => handleActionRequest(tokenStatus === 'ACTIVE' ? 'freeze' : 'unfreeze')}
                                className="w-full py-3 bg-slate-800 text-white rounded-xl text-sm font-bold shadow-lg shadow-slate-300 active:scale-95 transition-transform"
                            >
                                {tokenStatus === 'ACTIVE' ? 'Freeze All Tokens' : 'Unfreeze All Tokens'}
                            </button>
                        </div>
                    </div>
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
    }

    return (
        <div className="bg-slate-50 min-h-screen pb-24 font-sans flex flex-col animate-in fade-in duration-300">
            {/* Header */}
            <div className="bg-white px-6 pt-12 pb-6 shadow-sm sticky top-0 z-10">
                <h1 className="text-2xl font-bold text-slate-900 tracking-tight">Account</h1>
                <p className="text-slate-500 text-sm">Manage your preferences</p>
            </div>

            <div className="p-6 space-y-6 overflow-y-auto">
                {/* User Info Card */}
                <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-2xl p-6 text-white shadow-xl flex items-center gap-4">
                    <div className="w-16 h-16 bg-blue-600 rounded-full flex items-center justify-center text-xl font-bold shadow-inner ring-4 ring-blue-500/30">
                        AH
                    </div>
                    <div>
                        <h2 className="font-bold text-lg">Ahmad Bin Abdullah</h2>
                        <p className="text-slate-400 text-xs font-mono tracking-wider">{citizenId || 'CITIZEN_001'}</p>
                        <span className="inline-block mt-2 px-2 py-0.5 bg-green-500/20 text-green-400 text-[10px] font-bold rounded">VERIFIED IDENTITY</span>
                    </div>
                </div>

                {/* Settings list */}
                <div className="space-y-2">
                    <SectionHeader title="Settings" />
                    <SettingItem
                        icon={<Shield size={18} />}
                        title="Security & Privacy"
                        onClick={() => setView('security')}
                    />
                    <SettingItem icon={<Bell size={18} />} title="Notifications" badge="2" />
                    <SettingItem icon={<User size={18} />} title="Personal Information" />
                </div>

                <div className="space-y-2">
                    <SectionHeader title="Support" />
                    <SettingItem icon={<HelpCircle size={18} />} title="Help Center" />
                    <SettingItem icon={<Settings size={18} />} title="App Settings" />
                </div>

                <button
                    onClick={() => {
                        if (confirm("Logout?")) {
                            localStorage.clear();
                            window.location.reload();
                        }
                    }}
                    className="w-full mt-4 p-4 rounded-xl bg-red-50 text-red-600 font-bold flex items-center justify-center gap-2 active:bg-red-100 transition-colors"
                >
                    <LogOut size={18} /> Sign Out
                </button>

                <p className="text-center text-slate-400 text-xs pt-4">Alacard v1.0.2 (Beta)</p>
            </div>
        </div>
    );
};

const SectionHeader = ({ title }) => (
    <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 px-1">{title}</h3>
);

const SettingItem = ({ icon, title, badge, onClick }) => (
    <button
        onClick={onClick}
        className="w-full bg-white p-4 rounded-xl shadow-sm border border-slate-100 flex items-center justify-between active:scale-98 transition-transform group"
    >
        <div className="flex items-center gap-3 text-slate-700">
            <div className="text-slate-400 group-hover:text-blue-500 transition-colors">{icon}</div>
            <span className="font-medium text-sm">{title}</span>
        </div>
        <div className="flex items-center gap-2">
            {badge && <span className="bg-red-500 text-white text-[10px] font-bold px-2 py-0.5 rounded-full">{badge}</span>}
            <ChevronRight size={16} className="text-slate-300" />
        </div>
    </button>
);

export default Profile;
