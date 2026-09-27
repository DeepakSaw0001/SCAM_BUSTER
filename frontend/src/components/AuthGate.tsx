import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';

export interface AuthGateProps {
  onDismiss?: () => void;
  onSuccess?: () => void;
  onBackHome?: () => void;
}

export const AuthGate: React.FC<AuthGateProps> = ({ onDismiss, onSuccess, onBackHome }) => {
  const { login, register, markAuthGateSeen } = useAuth();
  const { resolvedTheme, toggleTheme } = useTheme();

  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [username, setUsername] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (mode === 'login') {
        if (!email.trim() || !password) {
          throw new Error('Please enter both email/username and password.');
        }
        await login({ email: email.trim(), password });
      } else {
        if (!email.trim() || !password) {
          throw new Error('Email and password are required to create an account.');
        }
        if (password.length < 6) {
          throw new Error('Password must be at least 6 characters long.');
        }
        await register({
          email: email.trim(),
          password,
          full_name: fullName.trim() || undefined,
          username: username.trim() || undefined,
        });
      }
      markAuthGateSeen();
      onSuccess?.();
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleContinueAsGuest = () => {
    markAuthGateSeen();
    onDismiss?.();
  };

  const handleBackHome = () => {
    if (onBackHome) {
      onBackHome();
    } else {
      window.location.href = '/';
    }
  };

  const handleQuickDemo = () => {
    setEmail('testuser@scambuster.ai');
    setPassword('password123');
    setMode('login');
    setError(null);
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 flex flex-col justify-between relative overflow-hidden font-sans transition-colors duration-200 selection:bg-brand-500 selection:text-white">
      {/* Background Cyber Grid & Glow effects */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#cbd5e1_1px,transparent_1px),linear-gradient(to_bottom,#cbd5e1_1px,transparent_1px)] dark:bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-25 pointer-events-none" />
      <div className="absolute -top-40 left-1/2 -translate-x-1/2 w-[700px] h-[350px] bg-brand-500/10 dark:bg-brand-500/15 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute -bottom-20 right-10 w-[500px] h-[250px] bg-emerald-500/10 rounded-full blur-[100px] pointer-events-none" />

      {/* Top Bar with Brand and Theme Switcher */}
      <header className="relative z-10 w-full px-6 py-4 flex items-center justify-between border-b border-slate-200 dark:border-slate-800/80 bg-white/80 dark:bg-slate-950/70 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-brand-600 to-emerald-500 flex items-center justify-center shadow-lg shadow-brand-500/25 text-xl font-bold text-white">
            🛡️
          </div>
          <div>
            <div className="text-base font-extrabold tracking-tight text-slate-900 dark:text-white flex items-center gap-2">
              ScamBuster <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-brand-500/10 dark:bg-brand-500/20 text-brand-600 dark:text-brand-400 border border-brand-500/20 dark:border-brand-500/30">AI DEFENSE MATRIX</span>
            </div>
            <div className="text-[11px] text-slate-500 dark:text-slate-400">Zero-Trust Threat Intelligence Platform</div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Back to Home Button */}
          <button
            id="authgate-back-home-btn"
            onClick={handleBackHome}
            type="button"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-100 dark:bg-slate-800/90 hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white border border-slate-200 dark:border-slate-700/80 transition-all text-xs font-semibold shadow-sm cursor-pointer"
            title="Return to website home page"
          >
            <span>←</span>
            <span>Back to Home</span>
          </button>

          {/* Theme Switcher */}
          <button
            id="authgate-theme-toggle"
            onClick={toggleTheme}
            type="button"
            className="p-2 px-3 rounded-xl bg-slate-100 dark:bg-slate-800/90 hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white border border-slate-200 dark:border-slate-700/80 transition-all flex items-center gap-2 text-xs shadow-sm"
            title="Toggle color theme"
          >
            {resolvedTheme === 'dark' ? (
              <>
                <svg className="w-4 h-4 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
                <span className="text-[11px] font-semibold text-slate-300">Light Mode</span>
              </>
            ) : (
              <>
                <svg className="w-4 h-4 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                </svg>
                <span className="text-[11px] font-semibold text-slate-700">Dark Mode</span>
              </>
            )}
          </button>

          {/* Database Indicator */}
          <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/50 text-[11px] text-emerald-700 dark:text-emerald-300 font-mono">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            MongoDB Atlas Connected
          </div>
        </div>
      </header>

      {/* Main Authentication Card */}
      <main className="relative z-10 flex-1 flex items-center justify-center p-4 sm:p-6 my-4">
        <div className="relative w-full max-w-md bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-xl dark:shadow-2xl dark:shadow-black/80 backdrop-blur-xl overflow-hidden transition-all duration-300">
          {/* Top Gradient Stripe */}
          <div className="h-1.5 bg-gradient-to-r from-brand-600 via-emerald-400 to-teal-500" />

          {/* Close / Dismiss Button */}
          <button
            id="authgate-close-btn"
            type="button"
            onClick={handleContinueAsGuest}
            className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition cursor-pointer z-10"
            title="Continue to Analyzer as Guest"
            aria-label="Continue as Guest"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>

          <div className="p-6 sm:p-8 space-y-6">
            {/* Header / Security Notice */}
            <div className="text-center space-y-2">
              <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-semibold tracking-wide uppercase bg-rose-50 dark:bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-500/20">
                <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping" />
                Mandatory Sign-In Required
              </div>
              <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight">
                {mode === 'login' ? 'Authentication Gate' : 'Create Security Account'}
              </h1>
              <p className="text-xs text-slate-600 dark:text-slate-400 max-w-sm mx-auto leading-relaxed">
                {mode === 'login'
                  ? 'Access to ScamBuster scanners, intelligence telemetry, and audit logs requires verified authentication.'
                  : 'Register a credentialed profile to perform scans, store audit feeds, and track risk metrics.'}
              </p>
            </div>

            {/* Mode Switcher Tabs */}
            <div className="grid grid-cols-2 p-1 rounded-xl bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs font-semibold">
              <button
                id="authgate-tab-login"
                type="button"
                onClick={() => { setMode('login'); setError(null); }}
                className={`py-2.5 rounded-lg transition-all ${
                  mode === 'login'
                    ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white font-bold shadow-sm'
                    : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-white'
                }`}
              >
                Sign In
              </button>
              <button
                id="authgate-tab-register"
                type="button"
                onClick={() => { setMode('register'); setError(null); }}
                className={`py-2.5 rounded-lg transition-all ${
                  mode === 'register'
                    ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white font-bold shadow-sm'
                    : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-white'
                }`}
              >
                Create Account
              </button>
            </div>

            {/* Error Message Alert */}
            {error && (
              <div className="p-3.5 rounded-xl bg-rose-50 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800 text-rose-700 dark:text-rose-300 text-xs flex items-start gap-2.5 animate-shake">
                <span className="text-base shrink-0 leading-none">⚠️</span>
                <span className="leading-relaxed font-medium">{error}</span>
              </div>
            )}

            {/* Form */}
            <form onSubmit={handleSubmit} className="space-y-4">
              {mode === 'register' && (
                <>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                      Full Name <span className="text-slate-400 font-normal">(Optional)</span>
                    </label>
                    <input
                      id="authgate-name-input"
                      type="text"
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      placeholder="e.g. Elena Fisher"
                      className="w-full px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700/80 text-slate-900 dark:text-white text-xs placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500/50 transition"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                      Security Handle / Username <span className="text-slate-400 font-normal">(Optional)</span>
                    </label>
                    <input
                      id="authgate-username-input"
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      placeholder="e.g. cyber_officer_7"
                      className="w-full px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700/80 text-slate-900 dark:text-white font-mono text-xs placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500/50 transition"
                    />
                  </div>
                </>
              )}

              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                  {mode === 'login' ? 'Email or Username Handle' : 'Email Address'}
                </label>
                <div className="relative">
                  <input
                    id="authgate-email-input"
                    type={mode === 'login' ? 'text' : 'email'}
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder={mode === 'login' ? 'analyst@domain.com or username' : 'analyst@domain.com'}
                    className="w-full pl-9 pr-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700/80 text-slate-900 dark:text-white text-xs placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500/50 transition"
                  />
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-xs">✉️</span>
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300">
                    Password
                  </label>
                  {mode === 'register' && (
                    <span className="text-[10px] text-slate-400">Min 6 characters</span>
                  )}
                </div>
                <div className="relative">
                  <input
                    id="authgate-password-input"
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full pl-9 pr-10 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700/80 text-slate-900 dark:text-white text-xs placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500/50 transition"
                  />
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-xs">🔒</span>
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-white text-xs transition"
                    title={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? '🙈' : '👁️'}
                  </button>
                </div>
              </div>

              <button
                id="authgate-submit-btn"
                type="submit"
                disabled={loading}
                className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-brand-600 via-emerald-600 to-teal-600 hover:from-brand-500 hover:to-emerald-500 text-white font-bold text-xs shadow-lg shadow-brand-500/20 transition-all transform active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 cursor-pointer"
              >
                {loading ? (
                  <>
                    <svg className="w-4 h-4 animate-spin text-white" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    <span>Authenticating with MongoDB Atlas...</span>
                  </>
                ) : (
                  <span>{mode === 'login' ? 'Sign In & Access Platform' : 'Create Account & Sign In'}</span>
                )}
              </button>
            </form>

            {/* Quick Demo Helper */}
            <div className="pt-2 border-t border-slate-200 dark:border-slate-800/80 flex flex-col gap-2">
              <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
                <span>Want to test quickly?</span>
                <button
                  id="authgate-quick-demo-btn"
                  type="button"
                  onClick={handleQuickDemo}
                  className="font-mono text-emerald-600 dark:text-emerald-400 hover:text-emerald-500 dark:hover:text-emerald-300 font-semibold underline underline-offset-2 transition"
                >
                  Fill Demo Credentials
                </button>
              </div>

              <div className="text-center text-xs text-slate-500 dark:text-slate-400 pt-2">
                {mode === 'login' ? (
                  <span>
                    New to ScamBuster?{' '}
                    <button
                      type="button"
                      onClick={() => { setMode('register'); setError(null); }}
                      className="font-semibold text-brand-600 dark:text-brand-400 hover:underline"
                    >
                      Register an account
                    </button>
                  </span>
                ) : (
                  <span>
                    Already registered?{' '}
                    <button
                      type="button"
                      onClick={() => { setMode('login'); setError(null); }}
                      className="font-semibold text-brand-600 dark:text-brand-400 hover:underline"
                    >
                      Sign in here
                    </button>
                  </span>
                )}
              </div>
            </div>

            {/* Continue as Guest Option */}
            <div className="pt-3 border-t border-slate-200 dark:border-slate-800/80 text-center">
              <button
                id="authgate-continue-guest-btn"
                type="button"
                onClick={handleContinueAsGuest}
                className="w-full py-2.5 px-4 rounded-xl bg-slate-100 dark:bg-slate-800/70 hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white font-semibold text-xs border border-slate-200 dark:border-slate-700/60 transition-all flex items-center justify-center gap-2 cursor-pointer"
              >
                <span>Continue to Analyzer as Guest</span>
                <span>→</span>
              </button>
              <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-1.5">
                You can run full scam analysis as a guest. This gate won't appear again.
              </p>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="relative z-10 py-4 px-6 border-t border-slate-200 dark:border-slate-800/80 bg-white/70 dark:bg-slate-950/60 text-center text-[11px] text-slate-500 dark:text-slate-400 flex flex-wrap items-center justify-center gap-4">
        <span>ScamBuster Security Defense &copy; 2026</span>
        <span>•</span>
        <span>MongoDB Atlas Persistence Active</span>
        <span>•</span>
        <span>BCrypt 12-Rounds + HS256 Token Vault</span>
        <span>•</span>
        <span>Restricted Access Protocol</span>
      </footer>
    </div>
  );
};
