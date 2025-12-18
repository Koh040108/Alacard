import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AppErrorBoundary } from './components/ErrorBoundary';
import SimulatorSelection from './pages/SimulatorSelection';
import Wallet from './pages/Wallet';
import Terminal from './pages/Terminal';
import Audit from './pages/Audit';
import Issuer from './pages/Issuer';
import BackButton from './components/BackButton';

const App = () => {
  return (
    <Router>
      <div className="min-h-screen bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-900 via-slate-900 to-black text-white relative">
        <main className="container mx-auto py-8">
          <AppErrorBoundary>
            <Routes>
              <Route path="/" element={<SimulatorSelection />} />
              <Route path="/wallet" element={<Wallet />} />
              <Route path="/terminal" element={<Terminal />} />
              <Route path="/audit" element={<Audit />} />
              <Route path="/issuer" element={<Issuer />} />
            </Routes>
          </AppErrorBoundary>
        </main>

        {/* Global Back Button for Simulator Navigation */}
        <BackButton />
      </div>
    </Router>
  );
};

export default App;
