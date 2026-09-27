import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { scanPhone, ScanResult } from '../services/api';
import { ThreatIntelligencePanel } from '../components/ThreatIntelligencePanel';
import { MLArchitectureAttribution } from '../components/MLArchitectureAttribution';

interface CountryOption {
  code: string;
  name: string;
  dialCode: string;
}

const COUNTRIES: CountryOption[] = [
  { code: 'IN', name: 'India', dialCode: '+91' },
  { code: 'US', name: 'United States', dialCode: '+1' },
  { code: 'GB', name: 'United Kingdom', dialCode: '+44' },
  { code: 'CA', name: 'Canada', dialCode: '+1' },
  { code: 'AU', name: 'Australia', dialCode: '+61' },
  { code: 'SG', name: 'Singapore', dialCode: '+65' },
  { code: 'AE', name: 'United Arab Emirates', dialCode: '+971' },
  { code: 'SL', name: 'Sierra Leone', dialCode: '+232' },
];

const PRESETS = [
  {
    label: 'Wangiri Callback (+232 Sierra Leone)',
    phone: '+23221123456',
    country: 'SL',
    context: 'Missed call received late at night after one ring',
  },
  {
    label: 'Sequential Spoofed ID (+91 1234567890)',
    phone: '1234567890',
    country: 'IN',
    context: 'Robocall claiming unpaid electricity bill with immediate disconnection',
  },
  {
    label: 'Bank Impersonator (+91 9876543210)',
    phone: '9876543210',
    country: 'IN',
    context: 'Caller claiming to be SBI Fraud Department requesting debit card OTP',
  },
  {
    label: 'Legitimate Helpline (+91 1800 11 2211)',
    phone: '1800112211',
    country: 'IN',
    context: 'Official bank toll-free helpline',
  },
];

export const ScanPhone: React.FC = () => {
  const [phoneNumber, setPhoneNumber] = useState('');
  const [country, setCountry] = useState('IN');
  const [context, setContext] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  const selectedCountry = COUNTRIES.find((c) => c.code === country) || COUNTRIES[0];

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!phoneNumber.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const res = await scanPhone(phoneNumber.trim(), country, context.trim() || undefined);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze phone number');
    } finally {
      setLoading(false);
    }
  };

  const getRiskBadgeColor = (level: string) => {
    switch ((level || '').toLowerCase()) {
      case 'critical':
      case 'dangerous':
        return 'bg-rose-500/20 text-rose-700 dark:text-rose-400 border-rose-500/30';
      case 'high':
        return 'bg-amber-500/20 text-amber-700 dark:text-amber-400 border-amber-500/30';
      case 'medium':
      case 'suspicious':
        return 'bg-yellow-500/20 text-yellow-700 dark:text-yellow-400 border-yellow-500/30';
      case 'low':
      case 'safe':
        return 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-400 border-emerald-500/30';
      case 'very_low':
        return 'bg-cyan-500/20 text-cyan-700 dark:text-cyan-400 border-cyan-500/30';
      default:
        return 'bg-slate-100 dark:bg-slate-500/20 text-slate-700 dark:text-slate-400 border-slate-300 dark:border-slate-500/30';
    }
  };

  const intelStatus = result?.detection?.intelligence?.status || 'not_configured';
  const intelProvider = result?.detection?.intelligence?.provider || 'none';
  const intelRep = result?.detection?.intelligence?.reputation || 'unknown';

  return (
    <div className="max-w-4xl mx-auto py-10 px-4">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400 mb-4">
        <Link to="/scan" className="hover:text-slate-900 dark:hover:text-slate-200">Scanner</Link>
        <span>/</span>
        <span className="text-brand-600 dark:text-brand-400 font-medium">Phone Number Scanner</span>
      </div>

      <div className="mb-6">
        <h1 className="text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight flex items-center gap-3">
          <span className="p-2 rounded-xl bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/20">
            📞
          </span>
          Phone Number Scam & Robocall Scanner
        </h1>
        <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm">
          Analyzes telephony metadata, international Wangiri toll fraud signatures, spoofed digit patterns,
          and authoritative threat intelligence.
        </p>
      </div>

      {/* Privacy Notice Banner */}
      <div className="p-4 rounded-xl bg-slate-100 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 text-xs text-slate-700 dark:text-slate-300 flex items-start gap-3 mb-6 transition-colors">
        <span className="text-base">🛡️</span>
        <div>
          <strong className="text-slate-900 dark:text-slate-100 font-semibold block mb-0.5">Privacy Engineering Guarantee:</strong>
          Phone numbers are sensitive personal data. ScamBuster does not unnecessarily log raw numbers in application telemetry.
          Internal processing uses keyed HMAC-SHA256 tokens and user-facing views strictly mask intermediate digits
          (e.g., <code className="text-brand-600 dark:text-brand-400 font-mono">+91 ******3210</code>). Zero contact or SMS permissions required.
        </div>
      </div>

      {/* Scan Input Form */}
      <form onSubmit={handleScan} className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-5 transition-colors">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
              Default Country / Region
            </label>
            <select
              value={country}
              onChange={(e) => setCountry(e.target.value)}
              className="w-full px-3 py-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white text-sm focus:outline-none focus:border-brand-500"
            >
              {COUNTRIES.map((c) => (
                <option key={c.code} value={c.code}>
                  {c.dialCode} ({c.name})
                </option>
              ))}
            </select>
          </div>

          <div className="md:col-span-2">
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
              Phone Number *
            </label>
            <div className="relative">
              <input
                type="text"
                value={phoneNumber}
                onChange={(e) => setPhoneNumber(e.target.value)}
                placeholder={`e.g. ${selectedCountry.dialCode}9876543210 or local format`}
                className="w-full px-4 py-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm font-mono"
                required
              />
            </div>
          </div>
        </div>

        <div>
          <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
            Caller Context / Claimed Identity <span className="text-slate-400 dark:text-slate-500 font-normal">(Optional)</span>
          </label>
          <input
            type="text"
            value={context}
            onChange={(e) => setContext(e.target.value)}
            placeholder="e.g. Caller claimed to be Police / Bank Fraud Dept / Courier demanding immediate action"
            className="w-full px-4 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm"
          />
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2">
          <button
            type="submit"
            disabled={loading || !phoneNumber.trim()}
            className="w-full sm:w-auto px-8 py-3 rounded-xl bg-brand-500 hover:bg-brand-400 text-slate-950 font-bold text-sm transition shadow-lg shadow-brand-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <svg className="animate-spin h-4 w-4 text-slate-950" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                </svg>
                <span>Analyzing Number...</span>
              </>
            ) : (
              <span>Analyze Number</span>
            )}
          </button>

          <span className="text-xs text-slate-500">
            Powered by libphonenumber + Random Forest + Threat Intel
          </span>
        </div>

        {/* Test Presets */}
        <div className="pt-3 border-t border-slate-200 dark:border-slate-800/80">
          <div className="text-xs text-slate-500 dark:text-slate-400 mb-2 font-medium">Quick Test Scenarios:</div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {PRESETS.map((p, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setPhoneNumber(p.phone);
                  setCountry(p.country);
                  setContext(p.context);
                }}
                className="text-left px-3 py-2 rounded-xl bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 hover:border-brand-500/40 text-xs text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition group"
              >
                <div className="font-semibold text-slate-800 dark:text-slate-200 group-hover:text-brand-600 dark:group-hover:text-brand-400">{p.label}</div>
                <div className="text-slate-500 text-[11px] truncate">{p.context}</div>
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-700 dark:text-rose-300 text-xs font-mono">
            ⚠️ {error}
          </div>
        )}
      </form>

      {/* Result Display */}
      {result && (
        <div className="mt-8 space-y-6">
          {/* Main Risk Card */}
          <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm transition-colors">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-200 dark:border-slate-800">
              <div>
                <div className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400 font-semibold mb-1">
                  Phone Number Analysis
                </div>
                <div className="text-2xl font-mono font-bold text-slate-900 dark:text-white tracking-wide">
                  {result.technical_details?.masked || result.target.replace('Phone: ', '')}
                </div>
                <div className="text-xs text-slate-500 dark:text-slate-400 mt-1 flex items-center gap-2">
                  <span>Region: <span className="text-slate-700 dark:text-slate-200 font-semibold">{result.technical_details?.region_code || 'Unknown'}</span></span>
                  <span>•</span>
                  <span>Type: <span className="text-slate-700 dark:text-slate-200 font-semibold">{result.technical_details?.number_type || 'Unknown'}</span></span>
                </div>
              </div>

              <div className="flex items-center gap-4">
                <div className="text-right">
                  <div className="text-xs text-slate-500 dark:text-slate-400">Risk Score</div>
                  <div className="text-3xl font-extrabold text-slate-900 dark:text-white">
                    {result.composite_risk_score}
                    <span className="text-sm text-slate-400 dark:text-slate-500 font-normal"> / 100</span>
                  </div>
                </div>
                <div className={`px-4 py-2 rounded-xl text-sm font-bold uppercase tracking-wider border ${getRiskBadgeColor(result.risk_level)}`}>
                  {result.risk_level.replace('_', ' ')}
                </div>
              </div>
            </div>

            {/* Detection Sources Matrix */}
            <div className="py-5 border-b border-slate-200 dark:border-slate-800 grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mb-1">
                  <span>Static Analysis</span>
                  <span className="text-emerald-600 dark:text-emerald-400">✓ Active</span>
                </div>
                <div className="text-sm font-semibold text-slate-900 dark:text-white">
                  Score: {result.technical_details?.rule_risk_score ?? result.heuristic_score ?? 0}/100
                </div>
                <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">
                  {result.indicators.length} indicators flagged
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mb-1">
                  <span>ML Classifier</span>
                  <span className="text-emerald-600 dark:text-emerald-400">✓ Active</span>
                </div>
                <div className="text-sm font-semibold text-slate-900 dark:text-white">
                  {Math.round((result.detection?.ml?.model_score || 0) * 100)}% Probability
                </div>
                <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">
                  {result.detection?.ml?.prediction || 'N/A'} ({result.detection?.ml?.model_version || 'v1.0'})
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mb-1">
                  <span>Threat Intelligence</span>
                  {intelStatus === 'available' ? (
                    <span className="text-emerald-600 dark:text-emerald-400 font-medium">✓ Available</span>
                  ) : (
                    <span className="text-slate-400 dark:text-slate-500 font-medium">○ Offline / Unconfigured</span>
                  )}
                </div>
                <div className="text-sm font-semibold text-slate-900 dark:text-white capitalize">
                  {intelRep.replace('_', ' ')}
                </div>
                <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">
                  Provider: {intelProvider}
                </div>
              </div>
            </div>

            {/* Dynamic ML Algorithm & Architecture Attribution */}
            <div className="pt-5 border-b border-slate-200 dark:border-slate-800 pb-5">
              <MLArchitectureAttribution
                mlMetadata={result.ml_metadata}
                scanType="phone"
                heuristicScore={result.heuristic_score}
              />
            </div>

            {/* Summary & Uncertainty Banner */}
            <div className="pt-5 space-y-4">
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 text-sm">
                <div className="text-xs uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider mb-1">
                  Analysis Summary
                </div>
                <p className="text-slate-700 dark:text-slate-200 leading-relaxed">{result.summary}</p>
              </div>

              {/* Actionable Guidance */}
              {result.recommendation && (
                <div className="p-4 rounded-xl bg-brand-50 dark:bg-brand-500/10 border border-brand-200 dark:border-brand-500/20 text-sm">
                  <div className="text-xs uppercase font-bold text-brand-600 dark:text-brand-400 tracking-wider mb-1 flex items-center gap-1.5">
                    <span>🛡️</span> Recommendation & Defensive Action
                  </div>
                  <p className="text-brand-800 dark:text-brand-200 leading-relaxed">{result.recommendation}</p>
                </div>
              )}

              {/* Reasons & Evidence */}
              {result.reasons && result.reasons.length > 0 && (
                <div>
                  <h4 className="text-xs uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider mb-2">
                    Evidence & Contributing Signals
                  </h4>
                  <ul className="space-y-1.5">
                    {result.reasons.map((reason, idx) => (
                      <li key={idx} className="text-xs text-slate-700 dark:text-slate-300 flex items-start gap-2">
                        <span className="text-brand-600 dark:text-brand-400 mt-0.5 font-bold">•</span>
                        <span>{reason}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Threat Intelligence & Reputation Correlation */}
              {(result.threat_intelligence || result.threat_graph) && (
                <div className="pt-2">
                  <ThreatIntelligencePanel
                    threatIntelligence={result.threat_intelligence as any}
                    threatGraph={result.threat_graph as any}
                  />
                </div>
              )}

              {/* Heuristic Threat Indicators */}
              {result.indicators.length > 0 && (
                <div className="pt-2">
                  <h4 className="text-xs uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider mb-2">
                    Triggered Heuristic Indicators ({result.indicators.length})
                  </h4>
                  <div className="space-y-2">
                    {result.indicators.map((ind, idx) => (
                      <div key={idx} className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 flex items-start justify-between gap-3">
                        <div>
                          <div className="text-xs font-semibold text-slate-900 dark:text-slate-200">{ind.name}</div>
                          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">{ind.description}</div>
                          {ind.evidence && (
                            <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 mt-1">
                              Evidence: {ind.evidence}
                            </div>
                          )}
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${
                          (ind?.severity || '').toLowerCase() === 'critical' ? 'bg-rose-500/20 text-rose-700 dark:text-rose-400 border-rose-500/30' :
                          (ind?.severity || '').toLowerCase() === 'high' ? 'bg-amber-500/20 text-amber-700 dark:text-amber-400 border-amber-500/30' :
                          (ind?.severity || '').toLowerCase() === 'medium' ? 'bg-yellow-500/20 text-yellow-700 dark:text-yellow-400 border-yellow-500/30' :
                          'bg-slate-100 dark:bg-slate-500/20 text-slate-700 dark:text-slate-400 border-slate-200 dark:border-slate-500/30'
                        }`}>
                          {ind?.severity || 'INFO'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanPhone;
