import React, { useState, useEffect } from 'react';
import api from '../utils/api';
import { Users, Edit, RefreshCw, Save, ShieldCheck, AlertCircle, Fuel } from 'lucide-react';

const Issuer = () => {
    const [citizens, setCitizens] = useState([]);
    const [tokens, setTokens] = useState([]);
    const [loading, setLoading] = useState(true);
    const [editMode, setEditMode] = useState(null); // citizen_id being edited
    const [formData, setFormData] = useState({});
    const [simQuota, setSimQuota] = useState(300);

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

    return (
        <div className="p-6 max-w-6xl mx-auto space-y-8 animate-in fade-in duration-500">
            {/* Header ... */}
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

                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="border-b border-gray-700 text-gray-400 text-sm">
                                    <th className="p-2">Citizen ID</th>
                                    <th className="p-2">Income ($)</th>
                                    <th className="p-2">Status</th>
                                    <th className="p-2">Action</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-800">
                                {citizens.map(c => (
                                    <tr key={c.citizen_id} className="hover:bg-white/5 transition-colors">
                                        <td className="p-3 font-mono text-sm">{c.citizen_id}</td>
                                        <td className="p-3">
                                            {editMode === c.citizen_id ? (
                                                <input
                                                    type="number"
                                                    className="bg-slate-900 border border-slate-600 rounded px-2 py-1 w-24"
                                                    value={formData.income}
                                                    onChange={e => handleInputChange('income', e.target.value)}
                                                />
                                            ) : (
                                                <span className={c.income < 5000 ? "text-green-400 font-bold" : "text-gray-300"}>
                                                    ${c.income}
                                                </span>
                                            )}
                                        </td>
                                        <td className="p-3">
                                            {editMode === c.citizen_id ? (
                                                <select
                                                    className="bg-slate-900 border border-slate-600 rounded px-2 py-1"
                                                    value={formData.eligibility_status}
                                                    onChange={e => handleInputChange('eligibility_status', e.target.value)}
                                                >
                                                    <option value="true">Eligible</option>
                                                    <option value="false">Revoked</option>
                                                </select>
                                            ) : (
                                                <span className={`px-2 py-1 rounded text-xs font-bold ${c.eligibility_status === 'true' && c.income < 5000 ? 'bg-green-500/20 text-green-300' : 'bg-red-500/20 text-red-300'}`}>
                                                    {c.eligibility_status === 'true' && c.income < 5000 ? 'ACTIVE' : 'INELIGIBLE'}
                                                </span>
                                            )}
                                        </td>
                                        <td className="p-3">
                                            {editMode === c.citizen_id ? (
                                                <button onClick={handleSave} className="text-indigo-400 hover:text-indigo-300 p-1">
                                                    <Save size={18} />
                                                </button>
                                            ) : (
                                                <button onClick={() => handleEdit(c)} className="text-gray-400 hover:text-white p-1">
                                                    <Edit size={18} />
                                                </button>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>

                {/* Issued Tokens Registry */}
                <div className="glass-panel p-6">
                    <h2 className="text-xl font-semibold mb-6 flex items-center gap-2">
                        <ShieldCheck className="text-teal-400" /> Token Registry
                    </h2>

                    {tokens.length === 0 ? (
                        <div className="text-center py-10 text-gray-500">
                            <AlertCircle className="mx-auto mb-2 opacity-50" />
                            <p>No tokens issued yet.</p>
                        </div>
                    ) : (
                        <div className="space-y-3 max-h-[500px] overflow-y-auto">
                            {tokens.map(t => (
                                <div key={t.token_id} className="bg-slate-800/50 p-4 rounded-lg border border-slate-700">
                                    <div className="flex justify-between items-start mb-2">
                                        <span className="text-xs font-mono text-teal-300 bg-teal-900/30 px-2 py-1 rounded">
                                            {t.token_id.slice(0, 16)}...
                                        </span>
                                        <span className="text-[10px] text-gray-400">
                                            Exp: {new Date(parseInt(t.expiry)).toLocaleDateString()}
                                        </span>
                                    </div>
                                    <div className="text-xs text-gray-400 truncate font-mono">
                                        <span className="text-indigo-400">Sig:</span> {t.issuer_signature.slice(0, 40)}...
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default Issuer;
