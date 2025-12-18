import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';

const BackButton = () => {
    const navigate = useNavigate();
    const location = useLocation();

    // Don't show on the root selection screen
    if (location.pathname === '/') return null;

    return (
        <button
            onClick={() => navigate('/')}
            className="fixed bottom-6 left-6 z-50 bg-slate-800/80 hover:bg-slate-700 text-white px-4 py-3 rounded-full shadow-lg backdrop-blur-sm border border-slate-600 transition-all flex items-center gap-2 group"
        >
            <ArrowLeft size={20} className="group-hover:-translate-x-1 transition-transform" />
            <span className="font-medium">Exit Simulation</span>
        </button>
    );
};

export default BackButton;
