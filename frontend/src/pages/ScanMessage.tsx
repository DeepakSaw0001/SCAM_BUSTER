import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { scanText, ScanResult } from '../services/api';
import { ScanResultCard } from '../components/ScanResultCard';

const DEMO_MESSAGES = [
  {
    label: 'Urgent OTP Theft',
    sender: '+14155550199',
    text: 'URGENT: Your Chase bank account has been locked due to suspicious activity. Reply with your one-time password (OTP) immediately to avoid permanent suspension.',
  },
  {
    label: 'Lottery Prize Lure',
    sender: 'PROMO-ALERT',
    text: 'Congratulations! You have been selected as the winner of $10,000 in cash. Claim your reward now at http://win-claim-cash.xyz within 24 hours.',
  },
  {
    label: 'Benign Personal Chat',
    sender: '+15551234567',
    text: 'Hey Alex, are we still meeting at the library at 4pm to work on our presentation?',
  },
];

export const ScanMessage: React.FC = () => {
  const [text, setText] = useState('');
  const [sender, setSender] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!text.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const res = await scanText(text.trim(), sender.trim() || undefined);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze message');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-10 px-4">
      <div className="flex items-center gap-2 text-sm text-slate-400 mb-4">
        <Link to="/scan" className="hover:text-slate-200">Scanner</Link>
        <span>/</span>
        <span className="text-brand-400">Message Analysis</span>
      </div>
      <h1 className="text-3xl font-extrabold text-white mb-2">SMS & Social Engineering Scanner</h1>
      <p className="text-slate-400 mb-6">
        Analyzes text messages, Smishing alerts, and social engineering coercion patterns using NLP TF-IDF lexical models and deterministic cybersecurity heuristics.
      </p>

      {/* Form */}
      <form onSubmit={handleScan} className="p-6 rounded-2xl bg-dark-900 border border-slate-800 shadow-xl space-y-4">
        <div>
          <label className="block text-xs font-semibold text-slate-300 mb-1">
            Sender Number / ID (Optional)
          </label>
          <input
            type="text"
            value={sender}
            onChange={(e) => setSender(e.target.value)}
            placeholder="e.g. +14155550199 or BANK-ALERT"
            className="w-full px-4 py-2.5 rounded-xl bg-dark-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm font-mono"
          />
        </div>

        <div>
          <label className="block text-xs font-semibold text-slate-300 mb-1">
            Message Content
          </label>
          <textarea
            rows={4}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Paste suspicious SMS, WhatsApp, or instant message text..."
            className="w-full px-4 py-3 rounded-xl bg-dark-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm leading-relaxed"
            required
          />
        </div>

        <button
          type="submit"
          disabled={loading || !text.trim()}
          className="w-full sm:w-auto px-6 py-3 rounded-xl bg-brand-500 hover:bg-brand-400 text-dark-950 font-bold text-sm transition shadow-lg shadow-brand-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
        >
          {loading ? (
            <>
              <svg className="animate-spin h-4 w-4 text-dark-950" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
              </svg>
              <span>Analyzing Message...</span>
            </>
          ) : (
            <span>Scan Message</span>
          )}
        </button>

        {/* Demo Chips */}
        <div className="pt-2">
          <div className="text-xs text-slate-400 mb-2">Quick Test Presets:</div>
          <div className="flex flex-wrap gap-2">
            {DEMO_MESSAGES.map((demo, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setText(demo.text);
                  setSender(demo.sender);
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
