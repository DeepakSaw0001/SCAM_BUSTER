import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Navbar } from './components/Navbar';
import { AIChatbot } from './components/AIChatbot';
import { AuthModal } from './components/AuthModal';
import { AnalyzeGate } from './components/AnalyzeGate';
import { AuthLoadingSplash } from './components/AuthLoadingSplash';
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

import { ErrorBoundary } from './components/ErrorBoundary';

const AppContent: React.FC = () => {
  const { loading } = useAuth();

  // Show cyber splash while checking initial session token with MongoDB / backend
  if (loading) {
    return <AuthLoadingSplash />;
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 flex flex-col transition-colors duration-200">
      <Navbar />
      <main className="flex-1">
        <ErrorBoundary>
          <Routes>
            <Route path="/" element={<Home />} />
            {/* Analyze Section: Appears only once for non-logged-in users, never for logged-in users */}
            <Route path="/scan" element={<AnalyzeGate><Scan /></AnalyzeGate>} />
            <Route path="/scan/url" element={<AnalyzeGate><ScanUrl /></AnalyzeGate>} />
            <Route path="/scan/message" element={<AnalyzeGate><ScanMessage /></AnalyzeGate>} />
            <Route path="/scan/email" element={<AnalyzeGate><ScanEmail /></AnalyzeGate>} />
            <Route path="/scan/phone" element={<AnalyzeGate><ScanPhone /></AnalyzeGate>} />
            <Route path="/scan/apk" element={<AnalyzeGate><ScanApk /></AnalyzeGate>} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/history" element={<History />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </ErrorBoundary>
      </main>
      <AIChatbot />
      <AuthModal />
      <footer className="border-t border-slate-200 dark:border-slate-800 py-6 text-center text-xs text-slate-500 dark:text-slate-400">
        ScamBuster — AI Cybersecurity Platform &copy; 2026 &nbsp;·&nbsp; Multi-Channel Threat Detection &nbsp;·&nbsp; Threat Intelligence Correlation &nbsp;·&nbsp; ML Risk Engine &nbsp;·&nbsp; MongoDB Atlas
      </footer>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <ErrorBoundary>
      <ThemeProvider>
        <AuthProvider>
          <BrowserRouter>
            <AppContent />
          </BrowserRouter>
        </AuthProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
};

export default App;
