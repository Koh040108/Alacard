import React from 'react';
import { Search, Bell, CreditCard, Car, Utensils, Info } from 'lucide-react';

const Home = ({ onNavigate }) => {
    return (
        <div className="bg-slate-50 min-h-screen pb-24 text-slate-800 font-sans">
            {/* Header */}
            <div className="bg-gradient-to-br from-blue-100 to-white pt-12 pb-6 px-6 rounded-b-3xl shadow-sm">
                <div className="flex justify-between items-start mb-6">
                    <div>
                        <h1 className="text-2xl font-bold text-slate-900">Hi<br />AlaCard</h1>
                    </div>
                    <div className="text-right">
                        <div className="flex justify-end gap-3 text-blue-600 mb-1">
                            <Bell size={20} />
                            <Search size={20} />
                        </div>
                        <p className="text-xs text-slate-500 font-medium">Cyberjaya</p>
                        <p className="text-xs text-slate-900 font-bold">32 °C, No rain</p>
                        <span className="inline-block mt-1 px-2 py-0.5 bg-white border border-slate-200 rounded text-[10px] uppercase font-bold text-slate-500 shadow-sm">
                            Weather Info
                        </span>
                    </div>
                </div>

                {/* Search Bar */}
                <div className="relative mb-6">
                    <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 text-slate-400" size={20} />
                    <input
                        className="w-full bg-white py-3 pl-12 pr-4 rounded-full border border-slate-200 shadow-sm text-sm focus:outline-none focus:border-blue-300 focus:ring-4 focus:ring-blue-100/50 transition-all placeholder-slate-400"
                        placeholder="Search services..."
                    />
                </div>

                {/* Quick Actions */}
                <div className="flex justify-between px-2">
                    <QuickAction icon={<CreditCard className="text-blue-500" />} label="Identity Card" onClick={() => { }} />
                    <QuickAction icon={<Car className="text-yellow-600" />} label="JPJ" onClick={() => { }} />
                    <QuickAction icon={<Utensils className="text-emerald-500" />} label="Subsidy" onClick={() => onNavigate('scan')} />
                </div>
            </div>

            <div className="px-6 mt-6">
                {/* Notification Widget */}
                <h3 className="font-bold text-lg mb-3">Notification</h3>
                <div className="grid grid-cols-2 gap-4 mb-8">
                    <div className="bg-orange-500 text-white p-4 rounded-2xl shadow-lg shadow-orange-500/20 relative overflow-hidden">
                        <div className="relative z-10 text-center">
                            <h2 className="text-3xl font-bold mb-1">2</h2>
                            <p className="text-sm font-medium opacity-90">Warning</p>
                        </div>
                        <div className="absolute -right-4 -bottom-4 w-16 h-16 bg-white/20 rounded-full blur-xl"></div>
                    </div>
                    <div className="bg-blue-400 text-white p-4 rounded-2xl shadow-lg shadow-blue-400/20 relative overflow-hidden">
                        <div className="relative z-10 text-center">
                            <h2 className="text-3xl font-bold mb-1">5</h2>
                            <p className="text-sm font-medium opacity-90">General</p>
                        </div>
                        <div className="absolute -left-4 -top-4 w-16 h-16 bg-white/20 rounded-full blur-xl"></div>
                    </div>
                </div>

                {/* Announcement Widget */}
                <h3 className="font-bold text-lg mb-3">Announcement</h3>
                <div className="grid grid-cols-2 gap-4">
                    <AnnouncementCard
                        title="BUDI MADANI"
                        desc="Are you in the category of recipient?"
                        color="bg-sky-400"
                    />
                    <AnnouncementCard
                        title="PROGRAM RAKYAT"
                        desc="Digital Adoption"
                        color="bg-slate-800"
                        dark
                    />
                </div>
            </div>
        </div>
    );
};

const QuickAction = ({ icon, label, onClick }) => (
    <button onClick={onClick} className="flex flex-col items-center gap-2 group">
        <div className="w-12 h-12 bg-white rounded-xl shadow-md flex items-center justify-center border border-slate-100 group-active:scale-95 transition-transform">
            {icon}
        </div>
        <span className="text-[10px] font-bold text-slate-600">{label}</span>
    </button>
);

const AnnouncementCard = ({ title, desc, color, dark }) => (
    <div className={`${color} ${dark ? 'text-white' : 'text-slate-900'} p-4 rounded-2xl shadow-md h-32 flex flex-col justify-between relative overflow-hidden`}>
        <div className="relative z-10">
            <h4 className={`font-bold text-sm mb-1 ${dark ? 'text-white' : 'text-white'}`}>{title}</h4>
            <p className={`text-[10px] leading-tight ${dark ? 'text-gray-300' : 'text-blue-50'}`}>{desc}</p>
        </div>

        {/* Decorative Circle */}
        <div className={`absolute -right-2 -bottom-2 w-16 h-16 rounded-full ${dark ? 'bg-white/10' : 'bg-white/20'} blur-lg`}></div>
    </div>
);

export default Home;
