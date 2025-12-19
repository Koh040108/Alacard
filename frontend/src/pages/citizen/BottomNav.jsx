import React from 'react';
import { Home, Scan, Bell, User } from 'lucide-react';

const BottomNav = ({ activeTab, onTabChange }) => {
    return (
        <div className="fixed bottom-6 left-6 right-6 h-16 bg-slate-900 rounded-2xl shadow-2xl flex items-center justify-around px-2 z-50">
            <NavItem
                icon={<Home size={20} />}
                label="Home"
                active={activeTab === 'home'}
                onClick={() => onTabChange('home')}
            />
            <NavItem
                icon={<Scan size={20} />}
                label="Scan"
                active={activeTab === 'scan'} // Maps 'scan' to SubsidyWallet or Scanner
                onClick={() => onTabChange('scan')}
            />
            <NavItem
                icon={<Bell size={20} />}
                label="Notification"
                active={activeTab === 'notification'}
                onClick={() => onTabChange('notification')}
            />
            <NavItem
                icon={<User size={20} />}
                label="Profile"
                active={activeTab === 'profile'} // Maps to History/Dashboard
                onClick={() => onTabChange('profile')}
            />
        </div>
    );
};

const NavItem = ({ icon, label, active, onClick }) => (
    <button
        onClick={onClick}
        className={`flex flex-col items-center justify-center w-14 transition-all duration-300 ${active ? 'text-blue-400 -translate-y-1' : 'text-slate-500 hover:text-slate-300'
            }`}
    >
        <div className={`p-1 rounded-lg transition-all ${active ? 'bg-blue-500/10' : ''}`}>
            {icon}
        </div>
        <span className="text-[9px] font-bold mt-1 tracking-wide">{label}</span>
    </button>
);

export default BottomNav;
