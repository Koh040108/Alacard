import React from 'react';
import { Link } from 'react-router-dom';
import { Wallet, Terminal, ShieldAlert, Cpu } from 'lucide-react';

const Home = () => {
    return (
        <div className="flex flex-col items-center justify-center min-h-[80vh] space-y-12 animate-in text-center p-6">
            <div className="space-y-4">
                <div className="flex justify-center">
                    <div className="p-4 bg-blue-600 rounded-2xl shadow-[0_0_50px_rgba(37,99,235,0.5)]">
                        <Cpu className="w-16 h-16 text-white" />
                    </div>
                </div>
                <h1 className="text-6xl font-black text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-purple-500 to-pink-500 tracking-tight">
                    AlaCard
                </h1>
                <p className="text-xl text-gray-400 max-w-2xl">
                    Privacy-Preserving Eligibility Verification System backed by Cryptographic Zero-Knowledge Proofs.
                </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-8 w-full max-w-5xl">
                <Link to="/wallet" className="group">
                    <div className="glass-panel p-8 h-full hover:bg-white/5 transition-all duration-300 hover:scale-105 border-t-4 border-blue-500">
                        <Wallet className="w-12 h-12 text-blue-400 mb-4 group-hover:text-blue-300" />
                        <h2 className="text-2xl font-bold mb-2">Citizen Wallet</h2>
                        <p className="text-gray-400 text-sm">Securely store your eligibility tokens and generate zero-knowledge proofs without revealing personal data.</p>
                    </div>
                </Link>

                <Link to="/terminal" className="group">
                    <div className="glass-panel p-8 h-full hover:bg-white/5 transition-all duration-300 hover:scale-105 border-t-4 border-green-500">
                        <Terminal className="w-12 h-12 text-green-400 mb-4 group-hover:text-green-300" />
                        <h2 className="text-2xl font-bold mb-2">Verify Terminal</h2>
                        <p className="text-gray-400 text-sm">Verify citizen eligibility offline using cryptographic challenges while maintaining strict privacy.</p>
                    </div>
                </Link>

                <Link to="/audit" className="group">
                    <div className="glass-panel p-8 h-full hover:bg-white/5 transition-all duration-300 hover:scale-105 border-t-4 border-orange-500">
                        <ShieldAlert className="w-12 h-12 text-orange-400 mb-4 group-hover:text-orange-300" />
                        <h2 className="text-2xl font-bold mb-2">Audit Log</h2>
                        <p className="text-gray-400 text-sm">View the immutable, append-only hash chain of all verifications for complete transparency.</p>
                    </div>
                </Link>
            </div>
        </div>
    );
};

export default Home;
