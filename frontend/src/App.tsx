import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Navbar } from './components/Navbar';
import { Home } from './pages/Home';
import { Scan } from './pages/Scan';
import { ScanUrl } from './pages/ScanUrl';
import { ScanMessage } from './pages/ScanMessage';
import { ScanEmail } from './pages/ScanEmail';
import { ScanPhone } from './pages/ScanPhone';
import { ScanApk } from './pages/ScanApk';
import { Dashboard } from './pages/Dashboard';
import { History } from './pages/History';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-dark-950 text-slate-100 flex flex-col">
        <Navbar />
        <main className="flex-1">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/scan" element={<Scan />} />
            <Route path="/scan/url" element={<ScanUrl />} />
            <Route path="/scan/message" element={<ScanMessage />} />
            <Route path="/scan/email" element={<ScanEmail />} />
            <Route path="/scan/phone" element={<ScanPhone />} />
            <Route path="/scan/apk" element={<ScanApk />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/history" element={<History />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
        <footer className="border-t border-slate-800 py-6 text-center text-xs text-slate-500">
          ScamBuster — AI Cybersecurity Platform &copy; 2026. Phase 01 Project Foundation.
        </footer>
      </div>
    </BrowserRouter>
  );
};

export default App;
