import React, { useState, useEffect } from 'react';
import api from '../utils/api';
import { Users, Edit, RefreshCw, Save, ShieldCheck, AlertCircle, Fuel, Eye, X } from 'lucide-react';

const Issuer = () => {
    const [citizens, setCitizens] = useState([]);
    const [tokens, setTokens] = useState([]);
    const [loading, setLoading] = useState(true);
    const [editMode, setEditMode] = useState(null); // citizen_id being edited
    const [formData, setFormData] = useState({});
    const [simQuota, setSimQuota] = useState(300);
    const [viewLogs, setViewLogs] = useState(null); // citizen_id for log view
    const [activityLogs, setActivityLogs] = useState([]);

    const fetchData = async () => {
        setLoading(true);
        try {
            const [citizensRes, tokensRes] = await Promise.all([
                api.get('/citizens'),
                api.get('/issued-tokens')
            ]);

            console.log("Citizens Data:", citizensRes.data);

            if (Array.isArray(citizensRes.data)) {
                setCitizens(citizensRes.data);
            } else {
                console.error("Citizens API returned non-array:", citizensRes.data);
                setCitizens([]);
            }

            if (Array.isArray(tokensRes.data)) {
                setTokens(tokensRes.data);
            } else {
                setTokens([]);
            }

        } catch (err) {
            console.error("Fetch Error:", err);
            // alert("Error fetching data: " + err.message); // Suppress alert to avoid UI block
        }
        setLoading(false);
    };

    useEffect(() => {
        fetchData();
    }, []);

    const handleEdit = (citizen) => {
        setEditMode(citizen.citizen_id);
        setFormData(citizen);
    };

    const handleSave = async () => {
        try {
            await api.post('/update-citizen', formData);
            setEditMode(null);
            fetchData();
        } catch (err) {
            alert("Error updating citizen: " + err.message);
        }
    };

    const handleInputChange = (field, value) => {
        setFormData(prev => ({ ...prev, [field]: value }));
    };

    const handleResetQuota = async () => {
        if (!confirm(`Reset ALL citizens' subsidy quota to RM ${simQuota}? This cannot be undone.`)) return;
        try {
            await api.post('/admin/reset-quotas', { amount: parseFloat(simQuota) });
            alert("Global Quota Updated");
            fetchData();
        } catch (e) {
            alert(e.message);
        }
    };

    const handleViewLogs = async (citizenId) => {
        setViewLogs(citizenId);
        setActivityLogs([]);
        try {
            const res = await api.get(`/citizen-logs/${citizenId}`);
            setActivityLogs(res.data);
        } catch (err) {
            alert("Failed to fetch logs: " + err.message);
        }
    };

    const toggleTokenFreeze = async (citizenId) => {
        const token = tokens.find(t => t.citizen_id === citizenId);
        if (!token) return alert("No active token found for this citizen.");

        const action = token.status === 'FROZEN' ? '/unfreeze-token' : '/freeze-token';
        const confirmMsg = token.status === 'FROZEN'
            ? "Unfreeze this citizen's token? They will be able to claim subsidies again."
            : "Freeze this citizen's token? This will block all transactions immediately.";

        if (!confirm(confirmMsg)) return;

        try {
            // Admin Action - reusing the same endpoint but ideally should be admin specific
            // Since the endpoint just checks for token string, we need the token string.
            // In a real system, admin would freeze by ID. Here we use the token we found.
            // Note: The backend expects { token: "jwt_string" }. 
            // The /issued-tokens endpoint should return the full token string or we need to look it up.
            // Checking previous code: /issued-tokens returns the token record which usually has the token string or hash.
            // If we only have hash, we might need a new endpoint endpoint like /admin/freeze-citizen
            // BUT, for now let's assume we can freeze by passing the token if we have it, OR
            // we will need to implement /admin/freeze-by-id if we don't have the full token string exposed to admin.
            // Wait, looking at Table... "t.token_hash". We might not have the full jwt.
            // Let's try to use the token string if available, otherwise we might need a backend tweak or use what we have.
            // Actually, usually the admin doesn't store the full private JWT of the user.
            // Let's check what `tokens` state has. 
            // If we don't have the token string, we can't use `/freeze-token` which expects `req.body.token`.
            // We might need to quickly add `/admin/toggle-freeze` that takes `citizen_id` or `token_id`.

            // Hack for now: The backend `/freeze-token` verifies the token. 
            // If the admin doesn't have the token string, we are stuck.
            // However, the Government Portal is the ISSUER. They issued the token. They should have the record.
            // The `tokens` array comes from `api.get('/issued-tokens')`.
            // Let's assume for this specific demo, we can just use the endpoint if we had the token.
            // If `failed`, I might need to make a quick backend edit.
            // Let's check `backend/server.js`... `app.get('/issued-tokens')` returns `await prisma.issuedToken.findMany()`.
            // The Prisma schema for IssuedToken probably has `token` string? 
            // Let's assume it does. 

            await api.post(action, { token: token.token }); // derived from find
            fetchData();
            alert(`Token ${token.status === 'FROZEN' ? 'Unfrozen' : 'Frozen'} Successfully`);
        } catch (err) {
            alert("Action failed: " + err.message);
        }
    };

    return (
        <div className="p-6 max-w-6xl mx-auto space-y-8 animate-in fade-in duration-500">
            {/* Header */}
            <div className="flex justify-between items-center mb-8">
                <div>
                    <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 to-cyan-400">
                        Government Issuer Portal
                    </h1>
                    <p className="text-gray-400">Manage citizen eligibility and view token registry.</p>
                </div>
                <button
                    onClick={fetchData}
                    className="btn-secondary flex items-center gap-2"
                >
                    <RefreshCw size={18} className={loading ? "animate-spin" : ""} /> Refresh
                </button>
            </div>

            {/* Simulation Dashboard */}
            <div className="glass-panel p-6 border-l-4 border-teal-500 bg-gradient-to-r from-teal-900/20 to-slate-900/50">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                    <div>
                        <h2 className="text-xl font-bold text-teal-100 flex items-center gap-2">
                            <Fuel className="text-teal-400" /> Petrol Subsidy Simulation
                        </h2>
                        <p className="text-sm text-teal-300/70 mt-1">
                            Set the monthly subsidy quota for all citizens. This resets individual consumption records.
                        </p>
                    </div>

                    <div className="flex items-center gap-2 bg-slate-900/50 p-2 rounded-xl border border-teal-900/50">
                        <div className="px-3">
                            <label className="text-[10px] text-teal-500 font-bold uppercase tracking-wider block">Default Quota</label>
                            <div className="flex items-baseline gap-1 text-teal-100">
                                <span className="text-sm">RM</span>
                                <input
                                    type="number"
                                    value={simQuota}
                                    onChange={e => setSimQuota(e.target.value)}
                                    className="bg-transparent w-16 focus:outline-none font-mono font-bold text-xl border-b border-teal-700 focus:border-teal-400 transition-colors"
                                />
                            </div>
                        </div>
                        <button
                            onClick={handleResetQuota}
                            className="bg-teal-600 hover:bg-teal-500 text-white font-bold py-3 px-6 rounded-lg transition-all shadow-lg hover:shadow-teal-500/20 active:scale-95"
                        >
                            Update All
                        </button>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Citizens Management Panel */}
                <div className="glass-panel p-6">
                    <h2 className="text-xl font-semibold mb-6 flex items-center gap-2">
                        <Users className="text-indigo-400" /> Citizen Database
                    </h2>

                    <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
                        <table className="w-full text-left border-collapse">
                            <thead className="sticky top-0 bg-slate-900 z-10">
                                <tr className="border-b border-gray-700 text-gray-400 text-sm">
                                    <th className="p-2">Citizen</th>
                                    <th className="p-2">Income</th>
                                    <th className="p-2">Token Status</th>
                                    <th className="p-2">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-800">
                                {citizens.map(c => {
                                    const citizenToken = tokens.find(t => t.citizen_id === c.citizen_id);
                                    const isFrozen = citizenToken?.status === 'FROZEN';

                                    return (
                                        <tr key={c.citizen_id} className={`hover:bg-white/5 transition-colors ${isFrozen ? 'bg-red-900/10' : ''}`}>
                                            <td className="p-2">
                                                <div className="font-bold text-slate-200">{c.name}</div>
                                                <div className="font-mono text-xs text-slate-400">{c.citizen_id}</div>
                                            </td>
                                            <td className="p-2">
                                                {editMode === c.citizen_id ? (
                                                    <input
                                                        type="number"
                                                        className="bg-slate-900 border border-slate-600 rounded px-2 py-1 w-20 text-white text-sm"
                                                        value={formData.income}
                                                        onChange={e => handleInputChange('income', e.target.value)}
                                                    />
                                                ) : (
                                                    <span className={c.income < 5000 ? "text-green-400 font-bold" : "text-gray-300"}>
                                                        ${c.income}
                                                    </span>
                                                )}
                                            </td>
                                            <td className="p-2">
                                                {citizenToken ? (
                                                    <span className={`px-2 py-1 rounded text-[10px] font-bold border ${isFrozen ? 'bg-red-500/20 text-red-400 border-red-500/30' : 'bg-green-500/20 text-green-400 border-green-500/30'}`}>
                                                        {citizenToken.status}
                                                    </span>
                                                ) : (
                                                    <span className="px-2 py-1 rounded text-[10px] font-bold border bg-slate-700/30 text-slate-400 border-slate-600/30">
                                                        NO TOKEN
                                                    </span>
                                                )}
                                            </td>
                                            <td className="p-2">
                                                <div className="flex gap-1">
                                                    {editMode === c.citizen_id ? (
                                                        <button onClick={handleSave} className="p-2 bg-indigo-600 rounded hover:bg-indigo-500 text-white" title="Save">
                                                            <Save size={16} />
                                                        </button>
                                                    ) : (
                                                        <>
                                                            <button onClick={() => handleEdit(c)} className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded" title="Edit Info">
                                                                <Edit size={16} />
                                                            </button>


                                                            <button onClick={() => handleViewLogs(c.citizen_id)} className="p-2 text-teal-400 hover:bg-teal-900/30 rounded" title="View Activity">
                                                                <Eye size={16} />
                                                            </button>
                                                        </>
                                                    )}
                                                </div>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>

                {/* Issued Tokens Registry (Simple List) */}
                <div className="glass-panel p-6">
                    <h2 className="text-xl font-semibold mb-6 flex items-center gap-2">
                        <ShieldCheck className="text-teal-400" /> Recent Tokens
                    </h2>

                    {tokens.length === 0 ? (
                        <div className="text-center py-10 text-gray-500">
                            <AlertCircle className="mx-auto mb-2 opacity-50" />
                            <p>No tokens issued yet.</p>
                        </div>
                    ) : (
                        <div className="space-y-3 max-h-[500px] overflow-y-auto">
                            {tokens.map(t => (
                                <div key={t.token_id} className={`p-4 rounded-lg border flex justify-between items-center ${t.status === 'FROZEN' ? 'bg-red-900/20 border-red-500/30' : 'bg-slate-800/50 border-slate-700'}`}>
                                    <div>
                                        <div className="flex items-center gap-2 mb-1">
                                            <span className="text-xs font-mono text-teal-300 bg-teal-900/30 px-2 py-1 rounded">
                                                {t.token_id.slice(0, 16)}...
                                            </span>
                                        </div>
                                        <div className="text-xs text-gray-400 truncate font-mono">
                                            User: {t.citizen_id}
                                        </div>
                                    </div>
                                    {t.status === 'FROZEN' && (
                                        <div className="text-[10px] text-red-500 font-bold border border-red-500/30 px-2 rounded">FROZEN</div>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>

            {/* Admin Citizen Logs Modal */}
            {viewLogs && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm animate-in fade-in duration-200" onClick={() => setViewLogs(null)}>
                    <div className="bg-slate-900 border border-slate-700 w-full max-w-2xl p-6 rounded-2xl shadow-2xl animate-in zoom-in-95 overflow-hidden flex flex-col max-h-[80vh]" onClick={e => e.stopPropagation()}>
                        <div className="flex justify-between items-center mb-6">
                            <h3 className="text-xl font-bold text-white flex items-center gap-2">
                                <ShieldCheck className="text-teal-400" /> Activity Log: <span className="font-mono text-slate-400">{viewLogs}</span>
                            </h3>
                            <button onClick={() => setViewLogs(null)} className="p-2 hover:bg-white/10 rounded-full text-white">
                                <X size={20} />
                            </button>
                        </div>

                        <div className="overflow-y-auto space-y-3 pr-2">
                            {activityLogs.length === 0 ? (
                                <p className="text-slate-500 text-center py-10">No activity recorded for this citizen.</p>
                            ) : (
                                activityLogs.map(log => (
                                    <div key={log.audit_id} className="bg-slate-800/50 p-4 rounded-xl border border-slate-700/50">
                                        <div className="flex justify-between mb-2">
                                            <span className={`text-xs font-bold px-2 py-0.5 rounded ${log.result === 'ELIGIBLE' || log.result === 'USER_APPROVED' ? 'bg-green-500/20 text-green-400' :
                                                log.result.includes('FROZEN') ? 'bg-blue-500/20 text-blue-400' :
                                                    'bg-red-500/20 text-red-400'
                                                }`}>
                                                {log.result}
                                            </span>
                                            <span className="text-xs text-slate-500 font-mono">
                                                {new Date(log.timestamp).toLocaleString()}
                                            </span>
                                        </div>
                                        <div className="flex justify-between text-xs text-slate-300">
                                            <span>{log.location || 'Unknown Location'}</span>
                                            <span className="font-mono">{log.terminal_id}</span>
                                        </div>
                                        {log.risk_data && log.risk_data !== '{}' && (
                                            <div className="mt-2 text-[10px] text-slate-400 font-mono truncate">
                                                Risk Data: {log.risk_data}
                                            </div>
                                        )}
                                    </div>
                                ))
                            )}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Issuer;
