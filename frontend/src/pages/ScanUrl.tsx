import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { scanUrl, ScanResult } from '../services/api';

type ScannerState = 'idle' | 'loading' | 'success' | 'error';

const DEMO_URLS = [
  { label: 'Phishing IP + Credential Lure', url: 'http://192.168.1.1/paypal/login.php?update=true' },
  { label: 'Deep Subdomain Spoofing', url: 'https://login.verify.account.paypal.com.account-check.xyz/auth' },
  { label: 'Userinfo @ Authority Spoof', url: 'https://legitimate-bank.com@phishing-portal.com/login' },
  { label: 'Clean Baseline HTTPS', url: 'https://example.com' },
];

export const ScanUrl: React.FC = () => {
  const [url, setUrl] = useState('');
  const [scannerState, setScannerState] = useState<ScannerState>('idle');
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const targetUrl = url.trim();
    if (!targetUrl) return;

    setScannerState('loading');
    setError(null);

    try {
      const res = await scanUrl(targetUrl);
      setResult(res);
      setScannerState('success');
    } catch (err: any) {
      setError(err.message || 'Failed to analyze URL');
      setScannerState('error');
    }
  };

  const getRiskColor = (level: string) => {
    const l = level.toUpperCase();
    if (l === 'CRITICAL' || l === 'HIGH') return 'text-rose-400';
    if (l === 'MEDIUM') return 'text-amber-400';
    if (l === 'LOW' || l === 'VERY_LOW' || l === 'VERY LOW' || l === 'SAFE') return 'text-emerald-400';
    return 'text-slate-400';
  };

  const getRiskBadge = (level: string) => {
    const l = level.toUpperCase();
    if (l === 'CRITICAL' || l === 'HIGH') {
      return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
    }
    if (l === 'MEDIUM') {
      return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
    }
    if (l === 'LOW' || l === 'VERY_LOW' || l === 'VERY LOW' || l === 'SAFE') {
      return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
    }
    return 'bg-slate-800 text-slate-300 border-slate-700';
  };

  const formatCategoryName = (cat: string) => {
    return cat
      .split('_')
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  };

  return (
    <div className="max-w-4xl mx-auto py-10 px-4 space-y-8">
      {/* Breadcrumb Header */}
      <div>
        <div className="flex items-center gap-2 text-sm text-slate-400 mb-3">
          <Link to="/scan" className="hover:text-slate-200">Scanner</Link>
          <span>/</span>
          <span className="text-brand-400">URL Analysis</span>
        </div>
        <h1 className="text-3xl font-extrabold text-white tracking-tight">URL & Phishing Scanner</h1>
        <p className="text-slate-400 mt-1">
          Static lexical and structural inspection engine evaluating protocol legitimacy, domain topology, and obfuscation heuristics.
        </p>
      </div>

      {/* Input Form */}
      <form onSubmit={handleScan} className="p-6 rounded-2xl bg-dark-900 border border-slate-800 shadow-xl space-y-4">
        <label htmlFor="url-input" className="block text-sm font-semibold text-slate-200">
          Enter a URL to analyze
        </label>
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            id="url-input"
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            disabled={scannerState === 'loading'}
            className="flex-1 px-4 py-3 rounded-xl bg-dark-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm font-mono transition"
            required
          />
          <button
            id="analyze-url-btn"
            type="submit"
            disabled={scannerState === 'loading' || !url.trim()}
            className="px-7 py-3 rounded-xl bg-brand-500 hover:bg-brand-400 text-dark-950 font-bold text-sm transition shadow-lg shadow-brand-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {scannerState === 'loading' ? (
              <>
                <svg className="animate-spin h-4 w-4 text-dark-950" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                </svg>
                <span>Analyzing...</span>
              </>
            ) : (
              <span>Analyze URL</span>
            )}
          </button>
        </div>

        {/* Quick Test Presets */}
        <div className="pt-2">
          <div className="text-xs text-slate-400 mb-2 font-medium">Quick Test Presets:</div>
          <div className="flex flex-wrap gap-2">
            {DEMO_URLS.map((demo, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setUrl(demo.url);
                  setScannerState('idle');
                  setError(null);
                }}
                className="px-3 py-1.5 rounded-lg bg-dark-950 border border-slate-800 hover:border-brand-500/50 text-xs text-slate-300 hover:text-white transition"
              >
                {demo.label}
              </button>
            ))}
          </div>
        </div>
      </form>

      {/* STATE: Loading */}
      {scannerState === 'loading' && (
        <div className="p-12 rounded-2xl bg-dark-900 border border-slate-800 text-center space-y-4 shadow-xl">
          <div className="animate-spin w-10 h-10 border-3 border-brand-500 border-t-transparent rounded-full mx-auto" />
          <div>
            <div className="text-base font-bold text-white">Analyzing URL Structure</div>
            <p className="text-xs text-slate-400 mt-1">
              Executing lexical normalization, extracting character & path metrics, and correlating security rules...
            </p>
          </div>
        </div>
      )}

      {/* STATE: Error */}
      {scannerState === 'error' && error && (
        <div className="p-6 rounded-2xl bg-rose-950/40 border border-rose-800 text-rose-200 space-y-2 shadow-xl">
          <div className="flex items-center gap-2 font-bold text-sm text-rose-300">
            <span>⚠️</span>
            <span>URL Validation Failed</span>
          </div>
          <p className="text-xs font-mono bg-dark-950/60 p-3 rounded-lg border border-rose-900/60 text-rose-300">
            {error}
          </p>
          <p className="text-xs text-slate-400">
            Please ensure the URL begins with <code className="text-white">http://</code> or <code className="text-white">https://</code> and contains a valid hostname.
          </p>
        </div>
      )}

      {/* STATE: Success Result */}
      {scannerState === 'success' && result && (
        <div className="rounded-2xl bg-dark-900 border border-slate-800 shadow-2xl p-6 sm:p-8 space-y-8">
          {/* Header */}
          <div className="border-b border-slate-800 pb-6">
            <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
              <span className="text-xs uppercase font-mono tracking-wider px-3 py-1 rounded-md bg-dark-950 border border-slate-800 text-slate-400">
                Static Lexical Inspection
              </span>
              <span className="text-xs text-slate-500 font-mono">
                Model: {result.model_version || 'rules-v1'}
              </span>
            </div>
            <h2 className="text-2xl font-bold text-white break-all">{result.target}</h2>
            {result.normalized_url && result.normalized_url !== result.target && (
              <p className="text-xs text-slate-400 font-mono mt-1">
                <span className="text-slate-500">Normalized:</span> {result.normalized_url}
              </p>
            )}
          </div>

          {/* Primary Metrics Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {/* Risk Score */}
            <div className="p-4 rounded-xl bg-dark-950 border border-slate-800">
              <div className="text-xs uppercase font-semibold text-slate-400">Risk Score</div>
              <div className={`text-3xl font-extrabold mt-1 ${getRiskColor(result.risk_level)}`}>
                {result.risk_score ?? result.composite_risk_score}
                <span className="text-xs font-normal text-slate-500 ml-1">/ 100</span>
              </div>
            </div>

            {/* Risk Level */}
            <div className="p-4 rounded-xl bg-dark-950 border border-slate-800">
              <div className="text-xs uppercase font-semibold text-slate-400">Risk Level</div>
              <div className="mt-2">
                <span className={`px-2.5 py-1 rounded-full text-xs font-bold border uppercase tracking-wider ${getRiskBadge(result.risk_level)}`}>
                  {result.risk_level}
                </span>
              </div>
            </div>

            {/* Category */}
            <div className="p-4 rounded-xl bg-dark-950 border border-slate-800">
              <div className="text-xs uppercase font-semibold text-slate-400">Category</div>
              <div className="text-sm font-bold text-white mt-2 truncate">
                {result.category && result.category.length > 0
                  ? formatCategoryName(result.category[0])
                  : 'Benign Baseline'}
              </div>
            </div>

            {/* Confidence */}
            <div className="p-4 rounded-xl bg-dark-950 border border-slate-800">
              <div className="text-xs uppercase font-semibold text-slate-400">Confidence</div>
              <div className="text-2xl font-bold text-slate-200 mt-1">
                {result.confidence !== undefined ? result.confidence.toFixed(2) : '0.80'}
              </div>
            </div>
          </div>

          {/* Executive Summary */}
          <div className="p-4 rounded-xl bg-dark-950 border border-slate-800">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
              Assessment Summary
            </h3>
            <p className="text-sm text-slate-200 leading-relaxed">{result.summary}</p>
          </div>

          {/* Why was this flagged? */}
          <div className="space-y-3">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <span>Why was this flagged?</span>
              <span className="px-2 py-0.5 rounded-full text-xs bg-slate-800 text-slate-300">
                {result.indicators.length}
              </span>
            </h3>

            {/* Bulleted reasons list */}
            {result.reasons && result.reasons.length > 0 && (
              <ul className="space-y-1.5 p-4 rounded-xl bg-dark-950 border border-slate-800">
                {result.reasons.map((reason, idx) => (
                  <li key={idx} className="flex items-start gap-2 text-xs text-slate-300">
                    <span className="text-amber-400 font-bold">•</span>
                    <span>{reason}</span>
                  </li>
                ))}
              </ul>
            )}

            {/* Individual Indicator Cards */}
            <div className="space-y-2.5">
              {result.indicators.map((ind, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-xl bg-dark-950 border border-slate-800/80 space-y-2 hover:border-slate-700 transition"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-sm text-slate-200">{ind.name}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-bold border uppercase ${getRiskBadge(ind.severity)}`}
                    >
                      {ind.severity}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">{ind.description}</p>
                  {ind.evidence && (
                    <div className="p-2 rounded bg-dark-900 border border-slate-800 text-xs font-mono text-slate-300">
                      <span className="text-slate-500 mr-2">Evidence:</span>
                      {ind.evidence}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Recommended Action */}
          <div className="p-5 rounded-xl bg-brand-950/20 border border-brand-500/30 space-y-2">
            <h3 className="text-xs uppercase font-bold tracking-wider text-brand-400">
              Recommended Action
            </h3>
            <p className="text-sm font-semibold text-white leading-relaxed">
              {result.recommendation || result.recommendations?.[0] || 'Avoid entering sensitive credentials or payment information.'}
            </p>
          </div>

          {/* Collapsible Features Drawer */}
          {result.features && (
            <details className="p-4 rounded-xl bg-dark-950 border border-slate-800 text-xs text-slate-400">
              <summary className="font-semibold text-slate-300 cursor-pointer hover:text-white">
                View Extracted Lexical & Structural Features ({Object.keys(result.features).length})
              </summary>
              <div className="mt-3 grid grid-cols-2 sm:grid-cols-3 gap-2 font-mono text-[11px] pt-3 border-t border-slate-800">
                {Object.entries(result.features).map(([key, val]) => (
                  <div key={key} className="p-2 rounded bg-dark-900 border border-slate-800/60 truncate">
                    <span className="text-slate-500 block truncate">{key}</span>
                    <span className="text-slate-200 font-semibold">{String(val)}</span>
                  </div>
                ))}
              </div>
            </details>
          )}
        </div>
      )}
    </div>
  );
};
