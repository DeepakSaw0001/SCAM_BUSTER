import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { scanMessage, ScanResult, ThreatIndicator } from '../services/api';
import { ThreatIntelligencePanel } from '../components/ThreatIntelligencePanel';
import { MLArchitectureAttribution } from '../components/MLArchitectureAttribution';

type ScannerState = 'idle' | 'loading' | 'success' | 'error';

interface PresetMessage {
  label: string;
  sender: string;
  text: string;
}

const DEMO_PRESETS: PresetMessage[] = [
  {
    label: 'Bank Account Lock (Urgency + Phish Link)',
    sender: 'CHASE-ALERT',
    text: 'URGENT: Your Chase checking account has been temporarily locked due to suspicious activity. Verify identity within 24 hours: https://chase-security-verify.com/login',
  },
  {
    label: 'USPS Package Delivery Fee',
    sender: '+18445550199',
    text: 'USPS: Your package could not be delivered due to an incorrect address. A $1.99 redelivery fee is required: http://usps-tracking-portal.info/fee',
  },
  {
    label: 'IRS Tax Refund Scam',
    sender: 'IRS-REFUND',
    text: 'INTERNAL REVENUE SERVICE: You have an unclaimed tax refund of $1,420.50 waiting. Confirm direct deposit details: http://irs-gov-tax-refund.org/claim',
  },
  {
    label: 'Tech Support / OTP Scam',
    sender: 'SUPPORT-TEAM',
    text: 'Security Alert: An attempt to reset your account password was detected. Share the 6-digit OTP code below ONLY with your representative: 482910',
  },
  {
    label: 'Clean / Benign Message (Legitimate)',
    sender: '+14155550100',
    text: 'Hey! Are we still on for lunch at noon today? Let me know if that time works for you.',
  },
];

export const ScanMessage: React.FC = () => {
  const [text, setText] = useState('');
  const [sender, setSender] = useState('');
  const [scannerState, setScannerState] = useState<ScannerState>('idle');
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const targetText = text.trim();
    if (!targetText) return;

    setScannerState('loading');
    setError(null);

    try {
      const res = await scanMessage(targetText, sender.trim() || undefined);
      setResult(res);
      setScannerState('success');
    } catch (err: any) {
      setError(err.message || 'Failed to analyze message');
      setScannerState('error');
    }
  };

  const getRiskColor = (level?: string) => {
    switch (level?.toLowerCase()) {
      case 'critical':
        return 'text-rose-600 dark:text-rose-400';
      case 'high':
        return 'text-orange-600 dark:text-orange-400';
      case 'medium':
        return 'text-amber-600 dark:text-amber-400';
      case 'low':
        return 'text-blue-600 dark:text-blue-400';
      case 'very_low':
        return 'text-emerald-600 dark:text-emerald-400';
      default:
        return 'text-slate-500 dark:text-slate-400';
    }
  };

  const getRiskBadge = (level?: string) => {
    switch (level?.toLowerCase()) {
      case 'critical':
        return 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border-rose-500/40';
      case 'high':
        return 'bg-orange-500/20 text-orange-700 dark:text-orange-300 border-orange-500/40';
      case 'medium':
        return 'bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-500/40';
      case 'low':
        return 'bg-blue-500/20 text-blue-700 dark:text-blue-300 border-blue-500/40';
      case 'very_low':
        return 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-500/40';
      default:
        return 'bg-slate-100 dark:bg-slate-700/30 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700';
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch ((severity || '').toUpperCase()) {
      case 'CRITICAL':
        return 'bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border-rose-300 dark:border-rose-700';
      case 'HIGH':
        return 'bg-orange-100 dark:bg-orange-950 text-orange-700 dark:text-orange-300 border-orange-300 dark:border-orange-700';
      case 'MEDIUM':
        return 'bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-300 border-amber-300 dark:border-amber-700';
      case 'LOW':
        return 'bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300 border-blue-300 dark:border-blue-700';
      default:
        return 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700';
    }
  };

  const formatCategoryName = (cat: string) => {
    return cat
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (c) => c.toUpperCase());
  };

  return (
    <div className="max-w-4xl mx-auto py-10 px-4">
      {/* Breadcrumb Navigation */}
      <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400 mb-4">
        <Link to="/scan" className="hover:text-slate-900 dark:hover:text-slate-200 transition">
          Scanner
        </Link>
        <span>/</span>
        <span className="text-brand-600 dark:text-brand-400 font-medium">SMS & Text Message Analysis</span>
      </div>

      <h1 className="text-3xl font-extrabold text-slate-900 dark:text-white mb-2">
        SMS & Smishing Scam Detection
      </h1>
      <p className="text-slate-500 dark:text-slate-400 mb-6 leading-relaxed text-sm">
        Analyzes text messages for social engineering, credential harvesting, artificial urgency,
        and smishing lures using an empirical NLP ML pipeline (TF-IDF + Calibrated LinearSVC),
        deterministic cybersecurity rules, and zero-outbound static embedded link inspection.
      </p>

      {/* Input Form */}
      <form
        onSubmit={handleScan}
        className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4 mb-8 transition-colors"
      >
        <div>
          <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
            Sender Identifier / Phone Number (Optional)
          </label>
          <input
            id="sender-input"
            type="text"
            value={sender}
            onChange={(e) => setSender(e.target.value)}
            placeholder="e.g. +14155550199 or BANK-ALERT"
            disabled={scannerState === 'loading'}
            className="w-full px-4 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm font-mono transition"
          />
        </div>

        <div>
          <div className="flex items-center justify-between mb-1">
            <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
              Message Content
            </label>
            <span className="text-xs text-slate-400 dark:text-slate-500 font-mono">
              {text.length} chars | {text.trim() ? text.trim().split(/\s+/).length : 0} words
            </span>
          </div>
          <textarea
            id="message-textarea"
            rows={4}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Paste suspicious SMS, WhatsApp notification, or text message here..."
            disabled={scannerState === 'loading'}
            className="w-full px-4 py-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm leading-relaxed transition"
            required
          />
        </div>

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          <button
            id="analyze-message-btn"
            type="submit"
            disabled={scannerState === 'loading' || !text.trim()}
            className="px-7 py-3 rounded-xl bg-brand-500 hover:bg-brand-400 text-slate-950 font-bold text-sm transition shadow-lg shadow-brand-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {scannerState === 'loading' ? (
              <>
                <svg className="animate-spin h-4 w-4 text-slate-950" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                </svg>
                <span>Analyzing Message...</span>
              </>
            ) : (
              <span>Analyze Message</span>
            )}
          </button>

          <span className="text-xs text-slate-500 text-right sm:text-left">
            🔒 Privacy: Raw message is never logged or permanently retained.
          </span>
        </div>

        {/* Quick Test Presets */}
        <div className="pt-2 border-t border-slate-200 dark:border-slate-800/80">
          <div className="text-xs text-slate-500 dark:text-slate-400 mb-2 font-medium">Quick Test Presets:</div>
          <div className="flex flex-wrap gap-2">
            {DEMO_PRESETS.map((demo, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setText(demo.text);
                  setSender(demo.sender);
                  setScannerState('idle');
                  setError(null);
                }}
                className="px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 hover:border-brand-500/50 text-xs text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition"
              >
                {demo.label}
              </button>
            ))}
          </div>
        </div>
      </form>

      {/* STATE: Loading */}
      {scannerState === 'loading' && (
        <div className="p-12 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-center space-y-4 shadow-sm transition-colors">
          <div className="animate-spin w-10 h-10 border-3 border-brand-500 border-t-transparent rounded-full mx-auto" />
          <div>
            <div className="text-base font-bold text-slate-900 dark:text-white">Analyzing Message Threat Vectors</div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-md mx-auto">
              Executing lexical normalization, evaluating cybersecurity rules, querying NLP TF-IDF classifier,
              and inspecting embedded link structures...
            </p>
          </div>
        </div>
      )}

      {/* STATE: Error */}
      {scannerState === 'error' && error && (
        <div className="p-6 rounded-2xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-800 dark:text-rose-200 space-y-2 shadow-sm mb-8">
          <div className="flex items-center gap-2 font-bold text-sm text-rose-700 dark:text-rose-300">
            <span>⚠️</span>
            <span>Analysis Request Failed</span>
          </div>
          <p className="text-xs font-mono bg-white dark:bg-slate-950/60 p-3 rounded-lg border border-rose-200 dark:border-rose-900/60 text-rose-700 dark:text-rose-300">
            {error}
          </p>
        </div>
      )}

      {/* STATE: Success Result */}
      {scannerState === 'success' && result && (
        <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm p-6 sm:p-8 space-y-8 animate-fadeIn transition-colors">
          {/* Header Banner */}
          <div className="border-b border-slate-200 dark:border-slate-800 pb-6">
            <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
              <span className="text-xs uppercase font-mono tracking-wider px-3 py-1 rounded-md bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400">
                SMS / Message Inspection
              </span>
              <span className="text-xs text-slate-400 dark:text-slate-500 font-mono">
                Model: {result.model_version || 'message-model-1.0'} | ID: {(result.id || result.scan_id || 'scan-res').slice(0, 8)}...
              </span>
            </div>
            <h2 className="text-xl font-bold text-slate-900 dark:text-white break-words">{result.target}</h2>
          </div>

          {/* Primary Metrics Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {/* Risk Score */}
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
              <div className="text-xs uppercase font-semibold text-slate-500 dark:text-slate-400">Risk Score</div>
              <div className={`text-3xl font-extrabold mt-1 ${getRiskColor(result.risk_level)}`}>
                {result.composite_risk_score}
                <span className="text-xs font-normal text-slate-400 dark:text-slate-500 ml-1">/ 100</span>
              </div>
            </div>

            {/* Risk Level */}
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
              <div className="text-xs uppercase font-semibold text-slate-500 dark:text-slate-400">Risk Level</div>
              <div className="mt-2">
                <span
                  className={`px-2.5 py-1 rounded-full text-xs font-bold border uppercase tracking-wider ${getRiskBadge(
                    result.risk_level
                  )}`}
                >
                  {result.risk_level}
                </span>
              </div>
            </div>

            {/* Category */}
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
              <div className="text-xs uppercase font-semibold text-slate-500 dark:text-slate-400">Primary Category</div>
              <div className="text-sm font-bold text-slate-900 dark:text-white mt-2 truncate">
                {result.category && result.category.length > 0
                  ? formatCategoryName(result.category[0])
                  : 'Benign Baseline'}
              </div>
            </div>

            {/* Confidence */}
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
              <div className="text-xs uppercase font-semibold text-slate-500 dark:text-slate-400">Confidence</div>
              <div className="text-2xl font-bold text-slate-800 dark:text-slate-200 mt-1">
                {result.confidence !== undefined ? result.confidence.toFixed(2) : '0.85'}
              </div>
            </div>
          </div>

          {/* Detection Sources Breakdown */}
          <div className="p-5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
              <span className="text-xs uppercase font-bold tracking-wider text-slate-500 dark:text-slate-400">
                Detection Sources
              </span>
              <span className="text-xs text-brand-600 dark:text-brand-400 font-mono font-semibold">Unified Risk Fusion</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Source 1: Message Rules */}
              <div className="p-4 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/80 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-emerald-600 dark:text-emerald-400 font-bold">✓</span>
                    <span className="text-sm font-bold text-slate-900 dark:text-white">Message Rules</span>
                  </div>
                  <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
                    {result.detection?.rules?.risk_score ?? result.heuristic_score ?? 0}/100
                  </span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  {result.indicators.length > 0
                    ? `${result.indicators.length} heuristic trigger(s) detected`
                    : 'Clean baseline — no suspicious patterns observed'}
                </p>
              </div>

              {/* Source 2: NLP Classifier */}
              <div className="p-4 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/80 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-emerald-600 dark:text-emerald-400 font-bold">✓</span>
                    <span className="text-sm font-bold text-slate-900 dark:text-white">NLP Classifier</span>
                  </div>
                  <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
                    {result.detection?.ml?.model_version || 'message-model-1.0'}
                  </span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  Class: <strong className="text-slate-900 dark:text-white capitalize">{result.detection?.ml?.prediction || 'N/A'}</strong>
                  {result.detection?.ml?.model_score !== undefined && (
                    <span className="ml-1 text-slate-400 dark:text-slate-500">
                      (score: {result.detection.ml.model_score.toFixed(2)})
                    </span>
                  )}
                </p>
              </div>

              {/* Source 3: Embedded URL Analysis */}
              <div className="p-4 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/80 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-emerald-600 dark:text-emerald-400 font-bold">✓</span>
                    <span className="text-sm font-bold text-slate-900 dark:text-white">Embedded URLs</span>
                  </div>
                  <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
                    {result.detection?.embedded_urls?.length || 0} found
                  </span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  {result.detection?.embedded_urls && result.detection.embedded_urls.length > 0
                    ? `Static inspection: ${result.detection.embedded_urls.map((u: any) => u.hostname).join(', ')}`
                    : 'Zero external links detected (no smishing vector)'}
                </p>
              </div>
            </div>
          </div>

          {/* Dynamic ML Algorithm & Architecture Attribution */}
          <MLArchitectureAttribution
            mlMetadata={result.ml_metadata}
            scanType="message"
            heuristicScore={result.heuristic_score}
          />

          {/* Executive Summary */}
          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1">
              Executive Summary
            </h3>
            <p className="text-sm text-slate-700 dark:text-slate-200 leading-relaxed">{result.summary}</p>
          </div>

          {/* Explainability: Why was this message flagged? */}
          {result.reasons && result.reasons.length > 0 && (
            <div className="p-5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Why was this message flagged?
              </h3>
              <ul className="space-y-2">
                {result.reasons.map((reason, idx) => (
                  <li key={idx} className="flex items-start gap-2.5 text-xs text-slate-700 dark:text-slate-300">
                    <span className="text-amber-500 font-bold leading-none mt-0.5">⚠</span>
                    <span>{reason}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Social Engineering Intelligence */}
          {result.social_engineering && (result.social_engineering.findings?.length || 0) > 0 && (
            <div className="p-6 rounded-2xl bg-slate-50 dark:bg-slate-950 border border-amber-500/30 shadow-sm space-y-5">
              {/* Header */}
              <div className="flex items-center justify-between pb-4 border-b border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-500/30 text-xl">🎭</div>
                  <div>
                    <h3 className="text-base font-bold text-slate-900 dark:text-white tracking-tight">SOCIAL ENGINEERING INTELLIGENCE</h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Deception pattern taxonomy, obfuscation detection, and manipulation vector analysis.
                    </p>
                  </div>
                </div>
                {result.social_engineering.detected_categories && result.social_engineering.detected_categories.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 justify-end">
                    {result.social_engineering.detected_categories.slice(0, 3).map((cat, i) => (
                      <span key={i} className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-100 dark:bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-500/30 uppercase">
                        {cat.replace(/_/g, ' ')}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Language & Obfuscation */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                  <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">Language</div>
                  <div className="text-sm font-bold text-slate-900 dark:text-white mt-1 uppercase">{result.social_engineering.language || 'Unknown'}</div>
                  <div className="text-[10px] text-slate-400 dark:text-slate-500 font-mono mt-0.5">
                    {result.social_engineering.language_confidence !== undefined
                      ? `${(result.social_engineering.language_confidence * 100).toFixed(0)}% confidence`
                      : ''}
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                  <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">Obfuscation</div>
                  <div className={`text-sm font-bold mt-1 ${result.social_engineering.obfuscation_detected ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
                    {result.social_engineering.obfuscation_detected ? '⚠️ Detected' : '✓ None'}
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                  <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">SE Findings</div>
                  <div className="text-lg font-bold text-slate-900 dark:text-white mt-1">{result.social_engineering.findings?.length || 0}</div>
                  <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">Deception vectors</div>
                </div>
                <div className="p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                  <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">Categories</div>
                  <div className="text-lg font-bold text-slate-900 dark:text-white mt-1">{result.social_engineering.detected_categories?.length || 0}</div>
                  <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">Taxonomy matches</div>
                </div>
              </div>

              {/* Obfuscation Details */}
              {result.social_engineering.obfuscation_detected && result.social_engineering.obfuscation_details && result.social_engineering.obfuscation_details.length > 0 && (
                <div className="p-3.5 rounded-xl bg-rose-50 dark:bg-rose-950/30 border border-rose-200 dark:border-rose-800/60 space-y-1.5">
                  <div className="text-xs font-bold text-rose-700 dark:text-rose-300 flex items-center gap-2">
                    <span>🔍</span> Anti-Obfuscation Signals Detected
                  </div>
                  <ul className="space-y-1">
                    {result.social_engineering.obfuscation_details.map((detail, i) => (
                      <li key={i} className="text-[11px] text-rose-700 dark:text-rose-200 flex items-start gap-2">
                        <span className="text-rose-500 mt-0.5">•</span>
                        <span>{detail}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* SE Findings Cards */}
              {result.social_engineering.findings && result.social_engineering.findings.length > 0 && (
                <div className="space-y-3">
                  <h4 className="text-xs uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider">Manipulation Vectors Detected</h4>
                  <div className="space-y-2">
                    {result.social_engineering.findings.map((finding, i) => (
                      <div key={i} className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-2">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-semibold text-sm text-slate-900 dark:text-slate-100">{finding.name}</span>
                          <span className={`px-2 py-0.5 rounded text-[11px] font-bold border uppercase ${
                            finding.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border-rose-500/30' :
                            finding.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-700 dark:text-orange-300 border-orange-500/30' :
                            finding.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-500/30' :
                            'bg-slate-100 dark:bg-slate-700/30 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700'
                          }`}>{finding.severity}</span>
                        </div>
                        <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">{finding.why_it_matters}</p>
                        {finding.evidence && (
                          <div className="p-2 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 text-xs font-mono text-slate-700 dark:text-slate-300">
                            <span className="text-slate-400 dark:text-slate-500 mr-2">Evidence:</span>{finding.evidence}
                          </div>
                        )}
                        {finding.safe_recommendations && finding.safe_recommendations.length > 0 && (
                          <ul className="space-y-1 pt-1">
                            {finding.safe_recommendations.slice(0, 2).map((rec, ri) => (
                              <li key={ri} className="text-[11px] text-brand-600 dark:text-brand-400 flex items-start gap-1.5 font-medium">
                                <span>✓</span><span>{rec}</span>
                              </li>
                            ))}
                          </ul>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Actionable Defense Recommendations */}
          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-3">Actionable Defense Guidance</h3>
            <ul className="space-y-2">
              {result.recommendations && result.recommendations.map((rec, idx) => (
                <li
                  key={idx}
                  className="flex items-start gap-2.5 text-xs text-slate-700 dark:text-slate-300 p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80"
                >
                  <span className="text-brand-600 dark:text-brand-400 font-bold">✓</span>
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Threat Intelligence & Reputation Correlation */}
          {(result.threat_intelligence || result.threat_graph) && (
            <ThreatIntelligencePanel
              threatIntelligence={result.threat_intelligence as any}
              threatGraph={result.threat_graph as any}
            />
          )}

          {/* Threat Indicators */}
          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-3 flex items-center gap-2">
              <span>Threat Indicators</span>
              <span className="px-2 py-0.5 rounded-full text-xs bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                {result.indicators.length}
              </span>
            </h3>

            {result.indicators.length === 0 ? (
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-sm text-slate-500 dark:text-slate-400">
                No malicious signatures or anomalies were triggered for this message.
              </div>
            ) : (
              <div className="space-y-3">
                {result.indicators.map((ind: ThreatIndicator, idx: number) => (
                  <div
                    key={idx}
                    className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 space-y-2 hover:border-slate-300 dark:hover:border-slate-700 transition"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-sm text-slate-900 dark:text-slate-200">{ind.name}</span>
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-bold border ${getSeverityBadge(
                          ind.severity
                        )}`}
                      >
                        {ind.severity}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 dark:text-slate-400">{ind.description}</p>
                    {ind.evidence && (
                      <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-xs font-mono text-slate-700 dark:text-slate-300">
                        <span className="text-slate-400 dark:text-slate-500 mr-2">Evidence:</span>
                        {ind.evidence}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Technical Details Accordion */}
          <div className="border-t border-slate-200 dark:border-slate-800 pt-4">
            <button
              type="button"
              onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
              className="text-xs font-mono text-brand-600 dark:text-brand-400 hover:text-brand-500 dark:hover:text-brand-300 flex items-center gap-2 font-semibold"
            >
              <span>{showTechnicalDetails ? '▼ Hide' : '► Show'} Technical Details & Extracted Features</span>
            </button>

            {showTechnicalDetails && (
              <div className="mt-4 p-5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-6 text-xs font-mono text-slate-700 dark:text-slate-300">
                {/* Feature Metrics Table */}
                <div>
                  <h4 className="text-slate-500 dark:text-slate-400 uppercase font-bold mb-2">Extracted Feature Vector</h4>
                  {result.features ? (
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                      {Object.entries(result.features).map(([key, val]) => (
                        <div key={key} className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/80">
                          <span className="text-slate-400 dark:text-slate-500 block truncate">{key}</span>
                          <span className="text-slate-900 dark:text-white font-bold">{String(val)}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-slate-400 dark:text-slate-500">Feature details unavailable.</p>
                  )}
                </div>

                {/* Model Metadata */}
                <div>
                  <h4 className="text-slate-500 dark:text-slate-400 uppercase font-bold mb-2">Model Specifications</h4>
                  <div className="space-y-1 text-slate-600 dark:text-slate-400">
                    <div>Algorithm: <span className="text-slate-900 dark:text-white font-semibold">TF-IDF + Calibrated LinearSVC</span></div>
                    <div>Feature Extraction: <span className="text-slate-900 dark:text-white font-semibold">Word Unigrams & Bigrams (max 5,000 features)</span></div>
                    <div>Training Dataset: <span className="text-slate-900 dark:text-white font-semibold">UCI SMS Spam Collection (5,167 unique samples)</span></div>
                    <div>Evaluation Metrics: <span className="text-slate-900 dark:text-white font-semibold">Accuracy: 98.2%, Precision: 97.7%, F1: 92.5%, FPR: 0.29%</span></div>
                  </div>
                </div>

                {/* Embedded URLs Details */}
                {result.detection?.embedded_urls && result.detection.embedded_urls.length > 0 && (
                  <div>
                    <h4 className="text-slate-500 dark:text-slate-400 uppercase font-bold mb-2">Embedded URL Details</h4>
                    <div className="space-y-2">
                      {result.detection.embedded_urls.map((u: any, idx: number) => (
                        <div key={idx} className="p-3 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-1">
                          <div className="text-slate-900 dark:text-white font-bold">{u.hostname}</div>
                          <div className="text-slate-500 dark:text-slate-400 break-all">{u.normalized_url}</div>
                          <div className="flex gap-4 text-slate-500 dark:text-slate-400">
                            <span>Risk Score: <strong className="text-slate-900 dark:text-white">{u.risk_score}/100</strong></span>
                            <span>Level: <strong className="text-slate-900 dark:text-white uppercase">{u.risk_level}</strong></span>
                            <span>ML Pred: <strong className="text-slate-900 dark:text-white capitalize">{u.ml_prediction}</strong></span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanMessage;
