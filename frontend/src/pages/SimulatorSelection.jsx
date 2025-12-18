import React from 'react';
import { useNavigate } from 'react-router-dom';
import { User, Terminal, Building2, ChevronRight } from 'lucide-react';

const SimulatorSelection = () => {
    const navigate = useNavigate();

    const roles = [
        {
            id: 'citizen',
            title: 'Citizen',
            description: 'Manage personal wallet and view balance.',
            icon: <User size={48} className="text-blue-400" />,
            path: '/wallet',
            color: 'from-blue-500/20 to-cyan-500/20',
            borderColor: 'group-hover:border-blue-500/50'
        },
        {
            id: 'kiosk',
            title: 'Terminal / Kiosk',
            description: 'Verify tokens and check eligibility status.',
            icon: <Terminal size={48} className="text-purple-400" />,
            path: '/terminal',
            color: 'from-purple-500/20 to-pink-500/20',
            borderColor: 'group-hover:border-purple-500/50'
        },
        {
            id: 'government',
            title: 'Government',
            description: 'Issue tokens and manage citizen registry.',
            icon: <Building2 size={48} className="text-amber-400" />,
            path: '/issuer',
            color: 'from-amber-500/20 to-orange-500/20',
            borderColor: 'group-hover:border-amber-500/50'
        }
    ];

    return (
        <div className="min-h-screen flex flex-col items-center justify-center p-6 animate-in fade-in zoom-in duration-500">
            <div className="text-center mb-12 space-y-4">
                <h1 className="text-5xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 via-purple-400 to-amber-400">
                    AlaCard Simulator
                </h1>
                <p className="text-gray-400 text-lg max-w-2xl mx-auto">
                    Select a role to enter the simulation environment. Each role represents a different actor in the ecosystem.
                </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-6xl w-full">
                {roles.map((role) => (
                    <div
                        key={role.id}
                        onClick={() => navigate(role.path)}
                        className={`group relative cursor-pointer overflow-hidden rounded-2xl border border-slate-700 bg-slate-800/40 p-8 transition-all hover:scale-[1.02] hover:shadow-2xl ${role.borderColor}`}
                    >
                        <div className={`absolute inset-0 bg-gradient-to-br ${role.color} opacity-0 group-hover:opacity-100 transition-opacity duration-500`} />

                        <div className="relative z-10 flex flex-col h-full items-center text-center space-y-6">
                            <div className="p-4 bg-slate-900/50 rounded-full shadow-inner ring-1 ring-white/10 group-hover:ring-white/20 transition-all">
                                {role.icon}
                            </div>

                            <div className="space-y-2">
                                <h3 className="text-2xl font-bold text-white group-hover:text-white/90">
                                    {role.title}
                                </h3>
                                <p className="text-gray-400 group-hover:text-gray-300">
                                    {role.description}
                                </p>
                            </div>

                            <div className="mt-auto pt-4 flex items-center gap-2 text-sm font-bold opacity-0 -translate-y-2 group-hover:opacity-100 group-hover:translate-y-0 transition-all duration-300">
                                ENTER DASHBOARD <ChevronRight size={16} />
                            </div>
                        </div>
                    </div>
                ))}
            </div>

            <div className="absolute bottom-8 text-center">
                <p className="text-gray-600 text-sm font-mono">
                    System Version: 2.0.1-SIM | Environment: Local
                </p>
            </div>
        </div>
    );
};

export default SimulatorSelection;
