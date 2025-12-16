import React, { useEffect, useState } from 'react';
import api from '../utils/api';
import { Database, Link as LinkIcon, ArrowDown, Activity } from 'lucide-react';

const Audit = () => {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        api.get('/audit-logs')
            .then(res => {
                setLogs(res.data);
                setLoading(false);
            })
            .catch(err => {
                console.error(err);
                setLoading(false);
            });
    }, []);

    return (
        <div className="p-6 max-w-4xl mx-auto space-y-8 animate-in fade-in duration-500">
            <h1 className="text-3xl font-bold text-center bg-clip-text text-transparent bg-gradient-to-r from-orange-400 to-red-500">
                Immutable Audit Trail
            </h1>

            <div className="glass-panel p-6">
                <div className="flex items-center gap-2 mb-6">
                    <Database className="text-orange-400" />
                    <h2 className="text-xl font-semibold">Live Blockchain-style Log</h2>
                </div>

                {loading ? (
                    <p className="text-center text-gray-400">Loading chain data...</p>
                ) : (
                    <div className="space-y-4">
                        {logs.length === 0 && <p className="text-center text-gray-500">No records found.</p>}

                        {logs.map((log, index) => (
                            <div key={log.audit_id} className="relative">
                                {/* Connector Line */}
                                {index !== logs.length - 1 && (
                                    <div className="absolute left-6 top-12 bottom-0 w-0.5 bg-gray-700 -z-10 h-16"></div>
                                )}

                                <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 hover:bg-slate-800 transition-colors flex flex-col md:flex-row gap-4 items-start md:items-center">
                                    <div className="bg-orange-500/20 p-3 rounded-full">
                                        <LinkIcon size={20} className="text-orange-400" />
                                    </div>

                                    <div className="flex-1 overflow-hidden">
                                        <div className="flex justify-between items-center mb-1">
                                            <span className="text-xs font-bold text-gray-500 uppercase">Block #{log.audit_id}</span>
                                            <span className="text-xs text-gray-400 font-mono">{new Date(log.timestamp).toLocaleString()}</span>
                                        </div>

                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono text-gray-300">
                                            <div className="truncate">
                                                <span className="text-gray-600">Prev Hash:</span> {log.prev_hash.slice(0, 20)}...
                                            </div>
                                            <div className="truncate">
                                                <span className="text-gray-600">Curr Hash:</span> <span className="text-white">{log.current_hash.slice(0, 20)}...</span>
                                            </div>
                                            <div className="truncate col-span-2">
                                                <span className="text-gray-600">Token Hash:</span> {log.token_hash}
                                            </div>
                                        </div>
                                    </div>

                                    <div className={`px-3 py-1 rounded text-xs font-bold ${log.result === 'ELIGIBLE' ? 'bg-green-900/50 text-green-400' : 'bg-red-900/50 text-red-400'}`}>
                                        {log.result}
                                    </div>
                                </div>
                                {index !== logs.length - 1 && (
                                    <div className="flex justify-center my-2">
                                        <ArrowDown size={16} className="text-gray-600" />
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
};

export default Audit;
