import React from 'react';
import { User, Settings, Shield, Bell, LogOut, ChevronRight, HelpCircle } from 'lucide-react';

const Profile = ({ onNavigate }) => {
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
                        <p className="text-slate-400 text-xs font-mono tracking-wider">CITIZEN_001</p>
                        <span className="inline-block mt-2 px-2 py-0.5 bg-green-500/20 text-green-400 text-[10px] font-bold rounded">VERIFIED IDENTITY</span>
                    </div>
                </div>

                {/* Settings list */}
                <div className="space-y-2">
                    <SectionHeader title="Settings" />
                    <SettingItem icon={<Shield size={18} />} title="Security & Privacy" />
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

const SettingItem = ({ icon, title, badge }) => (
    <button className="w-full bg-white p-4 rounded-xl shadow-sm border border-slate-100 flex items-center justify-between active:scale-98 transition-transform group">
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
