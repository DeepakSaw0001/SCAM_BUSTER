import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { scanUrl, ScanResult } from '../services/api';
import { ScanResultCard } from '../components/ScanResultCard';

const DEMO_URLS = [
  { label: 'Phishing IP + PayPal Lure', url: 'http://192.168.1.1/paypal/login.php?update=true' },
  { label: 'High-Risk TLD Credential Portal', url: 'http://secure-account-verification.xyz/login' },
  { label: 'Benign Corporate Domain', url: 'https://google.com/search?q=cybersecurity' },
];

export const ScanUrl: React.FC = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const res = await scanUrl(url.trim());
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze URL');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-10 px-4">
      <div className="flex items-center gap-2 text-sm text-slate-400 mb-4">
        <Link to="/scan" className="hover:text-slate-200">Scanner</Link>
        <span>/</span>
        <span className="text-brand-400">URL Analysis</span>
      </div>
      <h1 className="text-3xl font-extrabold text-white mb-2">URL & Phishing Scanner</h1>
      <p className="text-slate-400 mb-6">
        Correlates deterministic heuristic cybersecurity indicators with a Random Forest machine learning classifier to detect deceptive, malicious, and phishing URLs.
      </p>

      {/* Form */}
      <form onSubmit={handleScan} className="p-6 rounded-2xl bg-dark-900 border border-slate-800 shadow-xl space-y-4">
        <label className="block text-sm font-semibold text-slate-200">Target Web Address (URL)</label>
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="e.g. http://192.168.1.50/account/login.php or https://paypal-security.xyz"
            className="flex-1 px-4 py-3 rounded-xl bg-dark-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm font-mono transition"
            required
          />
          <button
            type="submit"
            disabled={loading || !url.trim()}
            className="px-6 py-3 rounded-xl bg-brand-500 hover:bg-brand-400 text-dark-950 font-bold text-sm transition shadow-lg shadow-brand-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <svg className="animate-spin h-4 w-4 text-dark-950" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                </svg>
                <span>Analyzing...</span>
              </>
            ) : (
              <span>Scan URL</span>
            )}
          </button>
        </div>

        {/* Demo Chips */}
        <div className="pt-2">
          <div className="text-xs text-slate-400 mb-2">Quick Test Presets:</div>
          <div className="flex flex-wrap gap-2">
            {DEMO_URLS.map((demo, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => setUrl(demo.url)}
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
