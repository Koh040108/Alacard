import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import Home from './pages/Home';
import Wallet from './pages/Wallet';
import Terminal from './pages/Terminal';
import Audit from './pages/Audit';
import Issuer from './pages/Issuer';
import { LayoutGrid } from 'lucide-react';

const NavLink = ({ to, children }) => {
  const location = useLocation();
  const isActive = location.pathname === to;
  return (
    <Link to={to} className={`px-4 py-2 rounded-lg transition-colors ${isActive ? 'bg-white/10 text-white font-bold' : 'text-gray-400 hover:text-white hover:bg-white/5'}`}>
      {children}
    </Link>
  );
};

const NavBar = () => {
  return (
    <nav className="border-b border-white/10 bg-slate-900/50 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <Link to="/" className="flex items-center gap-2 font-bold text-xl tracking-tight">
            <LayoutGrid className="text-blue-500" />
            <span>AlaCard</span>
          </Link>
          <div className="flex gap-2">
            <NavLink to="/">Home</NavLink>
            <NavLink to="/wallet">Wallet</NavLink>
            <NavLink to="/terminal">Terminal</NavLink>
            <NavLink to="/audit">Audit</NavLink>
            <NavLink to="/issuer">Issuer</NavLink>
          </div>
        </div>
      </div>
    </nav>
  );
};

const App = () => {
  return (
    <Router>
      <div className="min-h-screen bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-900 via-slate-900 to-black text-white">
        <NavBar />
        <main className="container mx-auto py-8">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/wallet" element={<Wallet />} />
            <Route path="/terminal" element={<Terminal />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/issuer" element={<Issuer />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
};

export default App;
