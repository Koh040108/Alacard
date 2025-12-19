import React, { useState, useEffect } from 'react';
import { ArrowLeft, CheckCircle, XCircle, AlertTriangle, Shield } from 'lucide-react';
import api from '../../utils/api';

const History = ({ onNavigate, token }) => {
    const [filter, setFilter] = useState('All');
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(false);

    const fetchActivity = async () => {
        if (!token) return;
        setLoading(true);
        try {
            const res = await api.post('/my-activity', { token });
            setLogs(res.data);
            console.log("Activity Logs:", res.data); // Debug log
        } catch (err) {
            console.error("Failed to load history", err);
        }
        setLoading(false);
    };

    useEffect(() => {
        fetchActivity();
    }, [token]);

    const filteredLogs = logs.filter(log => {
        if (filter === 'All') return true;
        if (filter === 'Verified') return log.result === 'ELIGIBLE' || log.result === 'WARNING'; // Treat warnings as verified but flagged
        if (filter === 'Cancelled') return log.result === 'BLOCKED_FRAUD';
        return true;
    });

    return (
        <div className="bg-slate-50 min-h-screen pb-24 font-sans flex flex-col">
            {/* Header */}
            <div className="bg-white pt-12 pb-4 px-6 sticky top-0 z-10 shadow-sm">
                <div className="flex justify-between items-center mb-4">
                    <button
                        onClick={() => onNavigate('home')}
                        className="flex items-center gap-1 font-bold text-sm text-slate-500 hover:text-slate-800 transition-colors"
                    >
                        <ArrowLeft size={18} /> Back
                    </button>
                    <button
                        onClick={() => fetchActivity()}
                        disabled={loading}
                        className="text-blue-600 text-xs font-bold hover:bg-blue-50 px-3 py-1.5 rounded-full transition-colors"
                    >
                        {loading ? 'Refreshing...' : 'Refresh History'}
                    </button>
                </div>
                <h1 className="text-2xl font-bold text-slate-900">Personal Dashboard</h1>

                {/* Filter Tabs */}
                <div className="flex gap-2 mt-4 overflow-x-auto no-scrollbar pb-1">
                    {['All', 'Verified', 'Cancelled'].map(tab => (
                        <button
                            key={tab}
                            onClick={() => setFilter(tab)}
                            className={`px-4 py-2 rounded-lg text-xs font-bold whitespace-nowrap transition-colors border ${filter === tab
                                ? 'bg-slate-900 text-white border-slate-900'
                                : 'bg-white text-slate-500 border-slate-200 hover:border-slate-300'
                                }`}
                        >
                            {tab}
                        </button>
                    ))}
                </div>
            </div>

            {/* List */}
            <div className="px-6 py-6 space-y-6">
                {loading ? (
                    <p className="text-center text-gray-400 mt-10">Loading activity...</p>
                ) : filteredLogs.length === 0 ? (
                    <div className="text-center py-10 opacity-50">
                        <p>No activity found.</p>
                    </div>
                ) : (
                    filteredLogs.map(log => {
                        // Parse Location safely
                        let locName = "Unknown Location";
                        try {
                            const l = JSON.parse(log.location);
                            locName = l.state ? `${l.state}, Malaysia` : "Unknown Location";
                        } catch (e) { }

                        // Parse Time
                        const dateObj = new Date(log.timestamp);
                        const dateStr = dateObj.toLocaleDateString();
                        const timeStr = dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

                        return (
                            <TransactionCard
                                key={log.audit_id}
                                title={locName} // Using Location as Title for now
                                total="-" // Amount not tracked in these logs yet
                                subsidy="Verified"
                                details={`Terminal: ${log.terminal_id}`}
                                date={`${dateStr}, ${timeStr}`}
                                status={log.result}
                                riskData={log.risk_data}
                            />
                        );
                    })
                )}
            </div>
        </div>
    );
};

const TransactionCard = ({ title, total, subsidy, details, date, status, riskData }) => {
    const isCompleted = status === 'ELIGIBLE';
    const isWarning = status === 'WARNING';
    const isBlocked = status === 'BLOCKED_FRAUD';

    let statusColor = 'bg-slate-100 text-slate-700';
    let StatusIcon = CheckCircle;

    if (isCompleted) {
        statusColor = 'bg-green-100 text-green-700';
        StatusIcon = CheckCircle;
    } else if (isWarning) {
        statusColor = 'bg-yellow-100 text-yellow-700';
        StatusIcon = AlertTriangle;
    } else if (isBlocked) {
        statusColor = 'bg-red-100 text-red-700';
        StatusIcon = XCircle;
    }

    // Parse Risk Data if available
    let risk = null;
    try {
        if (typeof riskData === 'string') risk = JSON.parse(riskData);
        else risk = riskData;
    } catch (e) { }

    return (
        <div className="bg-white p-5 rounded-2xl shadow-sm border border-slate-100">
            <div className="flex justify-between items-start mb-3">
                <h4 className="font-bold text-slate-800 text-sm w-2/3 truncate">{title}</h4>
                <div className={`px-2 py-1 rounded text-[10px] font-bold flex items-center gap-1 ${statusColor}`}>
                    {status}
                </div>
            </div>

            <div className="space-y-1 text-xs text-slate-500 mb-4">
                <div className="flex justify-between">
                    <span>Details:</span>
                    <span className="font-mono text-slate-900 font-bold">{details}</span>
                </div>
            </div>

            {/* AI FRAUD ALERT SECTION */}
            {isWarning && risk && (
                <div className="mb-4 bg-yellow-50 border border-yellow-100 rounded-xl p-3 animate-in fade-in zoom-in duration-300">
                    <div className="flex items-center gap-2 mb-2">
                        <Shield size={14} className="text-yellow-600" />
                        <span className="text-[10px] font-bold text-yellow-800 uppercase tracking-wider">AI Security Alert</span>
                    </div>
                    <div className="flex justify-between items-center mb-2">
                        <span className="text-xs text-yellow-700 font-medium">Risk Score:</span>
                        <span className="text-sm font-black text-yellow-900">{risk.score}/100</span>
                    </div>
                    {risk.reasons && risk.reasons.length > 0 && (
                        <div className="space-y-1">
                            {risk.reasons.map((r, i) => (
                                <div key={i} className="flex items-center gap-1.5">
                                    <div className="w-1 h-1 bg-yellow-400 rounded-full"></div>
                                    <span className="text-[10px] text-yellow-800 font-medium">{r}</span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}

            <div className="flex items-center gap-2 text-[10px] text-slate-400 font-medium pt-3 border-t border-slate-50">
                <StatusIcon size={12} className={isCompleted ? "text-green-500" : isBlocked ? "text-red-500" : "text-yellow-500"} />
                <p>{date}</p>
            </div>
        </div>
    );
};

export default History;
