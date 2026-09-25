import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { scanPhone, ScanResult } from '../services/api';
import { ScanResultCard } from '../components/ScanResultCard';

const DEMO_PHONES = [
  {
    label: 'Sierra Leone Wangiri Callback (+232)',
    phone: '+23276123456',
    context: 'One ring missed call received in middle of the night',
  },
  {
    label: 'IRS Scam Impersonation (+1 800)',
    phone: '+18005550199',
    context: 'Caller claiming to be IRS agent demanding gift card payment to cancel arrest warrant',
  },
  {
    label: 'Benign Customer Service Number',
    phone: '+14155552671',
    context: 'Local bank branch consultation',
  },
];

export const ScanPhone: React.FC = () => {
  const [phoneNumber, setPhoneNumber] = useState('');
  const [context, setContext] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!phoneNumber.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const res = await scanPhone(phoneNumber.trim(), context.trim() || undefined);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze phone number');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-10 px-4">
      <div className="flex items-center gap-2 text-sm text-slate-400 mb-4">
        <Link to="/scan" className="hover:text-slate-200">Scanner</Link>
        <span>/</span>
        <span className="text-brand-400">Phone Analysis</span>
      </div>
      <h1 className="text-3xl font-extrabold text-white mb-2">Phone & Robocall Scam Scanner</h1>
      <p className="text-slate-400 mb-6">
        Detects international Wangiri (one-ring toll fraud) high-risk prefixes, VoIP caller ID spoofing signatures, and imposter coercion tactics.
      </p>

      {/* Form */}
      <form onSubmit={handleScan} className="p-6 rounded-2xl bg-dark-900 border border-slate-800 shadow-xl space-y-4">
        <div>
          <label className="block text-xs font-semibold text-slate-300 mb-1">
            Phone Number (with Country Code) *
          </label>
          <input
            type="text"
            value={phoneNumber}
            onChange={(e) => setPhoneNumber(e.target.value)}
            placeholder="e.g. +23276123456 or +1-800-555-0199"
            className="w-full px-4 py-3 rounded-xl bg-dark-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm font-mono"
            required
          />
        </div>

        <div>
          <label className="block text-xs font-semibold text-slate-300 mb-1">
            Caller Context / Claimed Identity (Optional)
          </label>
          <textarea
            rows={2}
            value={context}
            onChange={(e) => setContext(e.target.value)}
            placeholder="e.g. Caller claimed to be IRS agent demanding immediate gift card settlement..."
            className="w-full px-4 py-2.5 rounded-xl bg-dark-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm"
          />
        </div>

        <button
          type="submit"
          disabled={loading || !phoneNumber.trim()}
          className="w-full sm:w-auto px-6 py-3 rounded-xl bg-brand-500 hover:bg-brand-400 text-dark-950 font-bold text-sm transition shadow-lg shadow-brand-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
        >
          {loading ? (
            <>
              <svg className="animate-spin h-4 w-4 text-dark-950" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
              </svg>
              <span>Analyzing Number...</span>
            </>
          ) : (
            <span>Scan Phone Number</span>
          )}
        </button>

        {/* Demo Chips */}
        <div className="pt-2">
          <div className="text-xs text-slate-400 mb-2">Quick Test Presets:</div>
          <div className="flex flex-wrap gap-2">
            {DEMO_PHONES.map((demo, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setPhoneNumber(demo.phone);
                  setContext(demo.context);
                }}
                className="px-3 py-1.5 rounded-lg bg-dark-950 border border-slate-800 hover:border-brand-500/50 text-xs text-slate-300 hover:text-white transition"
              >
                {demo.label}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800 text-rose-300 text-xs font-mono">
            ⚠️ {error}
          </div>
        )}
      </form>

      {/* Result Display */}
      {result && <ScanResultCard result={result} />}
    </div>
  );
};
