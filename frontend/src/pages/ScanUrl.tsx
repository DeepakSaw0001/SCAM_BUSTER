import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { scanUrl, ScanResult } from '../services/api';
import { ThreatIntelligencePanel } from '../components/ThreatIntelligencePanel';
import { MLArchitectureAttribution } from '../components/MLArchitectureAttribution';

type ScannerState = 'idle' | 'loading' | 'success' | 'error';

const DEMO_URLS = [
  { label: 'Phishing IP + Credential Lure', url: 'http://192.168.1.1/paypal/login.php?update=true' },
  { label: 'Deep Subdomain Spoofing', url: 'https://login.verify.account.paypal.com.account-check.xyz/auth' },
  { label: 'SSRF Defense Test (Localhost Blocked)', url: 'http://127.0.0.1:8000/internal-api/keys' },
  { label: 'Multi-Hop Shortener Redirect', url: 'https://bit.ly/sample-redirect-flow' },
  { label: 'Simulated APK Download Lure', url: 'https://cdn-updates-android.xyz/install/scanner.apk' },
  { label: 'Clean Baseline HTTPS', url: 'https://example.com' },
];

export const ScanUrl: React.FC = () => {
  const [url, setUrl] = useState('');
  const [deepAnalysis, setDeepAnalysis] = useState(true);
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
      const res = await scanUrl(targetUrl, deepAnalysis);
      setResult(res);
      setScannerState('success');
    } catch (err: any) {
      setError(err.message || 'Failed to analyze URL');
      setScannerState('error');
    }
  };

  const getRiskColor = (level: string) => {
    const l = (level || '').toUpperCase();
    if (l === 'CRITICAL' || l === 'HIGH' || l === 'DANGEROUS') return 'text-rose-600 dark:text-rose-400';
    if (l === 'MEDIUM' || l === 'SUSPICIOUS') return 'text-amber-600 dark:text-amber-400';
    if (l === 'LOW' || l === 'VERY_LOW' || l === 'VERY LOW' || l === 'SAFE') return 'text-emerald-600 dark:text-emerald-400';
    return 'text-slate-500 dark:text-slate-400';
  };

  const getRiskBadge = (level: string) => {
    const l = (level || '').toUpperCase();
    if (l === 'CRITICAL' || l === 'HIGH' || l === 'DANGEROUS') {
      return 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border-rose-500/40';
    }
    if (l === 'MEDIUM' || l === 'SUSPICIOUS') {
      return 'bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-500/40';
    }
    if (l === 'LOW' || l === 'VERY_LOW' || l === 'VERY LOW' || l === 'SAFE') {
      return 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-500/40';
    }
    return 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700';
  };

  const formatCategoryName = (cat: string) => {
    if (!cat) return '';
    return cat
      .split('_')
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  };

  const webAnalysis = result?.web_analysis;
  const redirects = webAnalysis?.redirects;
  const responseData = webAnalysis?.response;
  const contentData = webAnalysis?.content;
  const downloadData = webAnalysis?.download;

  return (
    <div className="max-w-4xl mx-auto py-10 px-4 space-y-8">
      {/* Breadcrumb Header */}
      <div>
        <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400 mb-3">
          <Link to="/scan" className="hover:text-slate-900 dark:hover:text-slate-200">Scanner</Link>
          <span>/</span>
          <span className="text-brand-600 dark:text-brand-400 font-medium">URL, Website & Redirect Analysis</span>
        </div>
        <h1 className="text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight flex items-center gap-3">
          <span className="p-2 rounded-xl bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20">
            🌐
          </span>
          URL, Website & Redirect Risk Scanner
        </h1>
        <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm">
          Performs multi-layered analysis: static lexical URL heuristics, safe HTTP fetching, redirect-chain tracking,
          SSRF protection, HTML credential-form extraction, and payload/APK download security analysis.
        </p>
      </div>

      {/* Input Form */}
      <form onSubmit={handleScan} className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4 transition-colors">
        <label htmlFor="url-input" className="block text-sm font-semibold text-slate-700 dark:text-slate-200">
          Enter a Website URL to analyze
        </label>
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            id="url-input"
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            disabled={scannerState === 'loading'}
            className="flex-1 px-4 py-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm font-mono transition"
            required
          />
          <button
            id="analyze-url-btn"
            type="submit"
            disabled={scannerState === 'loading' || !url.trim()}
            className="px-7 py-3 rounded-xl bg-brand-500 hover:bg-brand-400 text-slate-950 font-bold text-sm transition shadow-lg shadow-brand-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {scannerState === 'loading' ? (
              <>
                <svg className="animate-spin h-4 w-4 text-slate-950" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                </svg>
                <span>Inspecting...</span>
              </>
            ) : (
              <span>Analyze Website</span>
            )}
          </button>
        </div>

        {/* Deep Analysis Options */}
        <div className="flex items-center justify-between pt-2 border-t border-slate-200 dark:border-slate-800/80">
          <label className="flex items-center gap-2.5 cursor-pointer text-xs text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white select-none">
            <input
              type="checkbox"
              checked={deepAnalysis}
              onChange={(e) => setDeepAnalysis(e.target.checked)}
              className="w-4 h-4 rounded border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-brand-500 focus:ring-brand-500"
            />
            <span className="font-semibold">Enable Live Safe Web Fetch & Redirect Chain Analysis</span>
            <span className="text-[10px] px-2 py-0.5 rounded bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20 font-mono">
              SSRF-Protected
            </span>
          </label>
        </div>

        {/* Quick Test Presets */}
        <div className="pt-2">
          <div className="text-xs text-slate-500 dark:text-slate-400 mb-2 font-medium">Quick Test Presets:</div>
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
            <div className="text-base font-bold text-slate-900 dark:text-white">Inspecting Destination & Redirects</div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-lg mx-auto">
              Validating SSRF security boundaries, tracking HTTP redirect hops, evaluating transport encryption,
              checking for automated downloads, and extracting HTML authentication forms...
            </p>
          </div>
        </div>
      )}

      {/* STATE: Error */}
      {scannerState === 'error' && error && (
        <div className="p-6 rounded-2xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-800 dark:text-rose-200 space-y-2 shadow-sm">
          <div className="flex items-center gap-2 font-bold text-sm text-rose-700 dark:text-rose-300">
            <span>⚠️</span>
            <span>Scan Execution Failed</span>
          </div>
          <p className="text-xs font-mono bg-white dark:bg-slate-950/60 p-3 rounded-lg border border-rose-200 dark:border-rose-900/60 text-rose-700 dark:text-rose-300">
            {error}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Please ensure the URL begins with <code className="text-slate-900 dark:text-white font-semibold">http://</code> or <code className="text-slate-900 dark:text-white font-semibold">https://</code> and contains a reachable hostname.
          </p>
        </div>
      )}

      {/* STATE: Success Result */}
      {scannerState === 'success' && result && (
        <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm p-6 sm:p-8 space-y-8 transition-colors">
          {/* Header */}
          <div className="border-b border-slate-200 dark:border-slate-800 pb-6">
            <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
              <span className="text-xs uppercase font-mono tracking-wider px-3 py-1 rounded-md bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400">
                {webAnalysis ? 'Live Web & Redirect Inspection' : 'Static Lexical Inspection'}
              </span>
              <span className="text-xs text-slate-400 dark:text-slate-500 font-mono">
                Model: {result.model_version || 'rules-v1'}
              </span>
            </div>
            <h2 className="text-2xl font-bold text-slate-900 dark:text-white break-all">{result.target}</h2>
            {result.normalized_url && result.normalized_url !== result.target && (
              <p className="text-xs text-slate-500 dark:text-slate-400 font-mono mt-1">
                <span className="text-slate-400 dark:text-slate-500">Normalized:</span> {result.normalized_url}
              </p>
            )}
          </div>

          {/* Primary Metrics Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {/* Risk Score */}
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
              <div className="text-xs uppercase font-semibold text-slate-500 dark:text-slate-400">Composite Risk</div>
              <div className={`text-3xl font-extrabold mt-1 ${getRiskColor(result.risk_level)}`}>
                {result.risk_score ?? result.composite_risk_score}
                <span className="text-xs font-normal text-slate-400 dark:text-slate-500 ml-1">/ 100</span>
              </div>
            </div>

            {/* Risk Level */}
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
              <div className="text-xs uppercase font-semibold text-slate-500 dark:text-slate-400">Risk Tier</div>
              <div className="mt-2">
                <span className={`px-2.5 py-1 rounded-full text-xs font-bold border uppercase tracking-wider ${getRiskBadge(result.risk_level)}`}>
                  {result.risk_level}
                </span>
              </div>
            </div>

            {/* Category */}
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
              <div className="text-xs uppercase font-semibold text-slate-500 dark:text-slate-400">Category</div>
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

          {/* DEDICATED SECTION: WEBSITE SECURITY & REDIRECT ANALYSIS */}
          {webAnalysis && (
            <div className="p-6 rounded-2xl bg-slate-50 dark:bg-slate-950 border border-blue-500/30 shadow-sm space-y-6">
              {/* Section Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-blue-500/20 text-blue-700 dark:text-blue-300 border border-blue-500/30 text-2xl">
                    🛰️
                  </div>
                  <div>
                    <h3 className="text-lg font-bold text-slate-900 dark:text-white tracking-tight">
                      WEBSITE SECURITY & REDIRECT ANALYSIS
                    </h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Evaluates live destination responses, HTTP redirection progression, credential collection, and downloadable payloads.
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span className={`px-3 py-1 rounded-lg text-xs font-mono font-bold uppercase border ${
                    webAnalysis.status === 'blocked' ? 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border-rose-500/40' :
                    webAnalysis.status === 'completed' ? 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-500/40' :
                    'bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-500/40'
                  }`}>
                    Status: {webAnalysis.status}
                  </span>
                </div>
              </div>

              {/* SSRF Blocked Warning Banner */}
              {webAnalysis.status === 'blocked' && (
                <div className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-xs text-rose-800 dark:text-rose-200 space-y-2">
                  <div className="font-bold text-sm text-rose-700 dark:text-rose-300 flex items-center gap-2">
                    <span>🛑</span>
                    <span>SSRF Security Violation — Connection Aborted</span>
                  </div>
                  <p className="font-mono bg-white dark:bg-slate-900/80 p-2.5 rounded border border-rose-200 dark:border-rose-900/60">
                    {webAnalysis.failure_reason}
                  </p>
                  <p className="text-slate-500 dark:text-slate-400 text-[11px]">
                    ScamBuster's Security Policy strictly refuses connections to localhost, private IP ranges (RFC 1918),
                    link-local interfaces, and cloud metadata services.
                  </p>
                </div>
              )}

              {/* Telemetry Overview Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                  <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">Final Destination</div>
                  <div className="text-sm font-bold text-slate-900 dark:text-white mt-1 truncate" title={redirects?.final_domain}>
                    {redirects?.final_domain || 'N/A'}
                  </div>
                  <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5 truncate font-mono">
                    {redirects?.has_cross_domain ? '⚠️ Cross-Domain' : 'Direct Target'}
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                  <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">Redirect Hops</div>
                  <div className="text-lg font-bold text-slate-900 dark:text-white mt-1">
                    {redirects?.redirect_count ?? 0}
                    <span className="text-xs text-slate-400 dark:text-slate-500 font-normal"> hops</span>
                  </div>
                  <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">
                    {redirects?.domain_hopping ? '⚠️ Domain Hopping' : 'Standard Path'}
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                  <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">Authentication Forms</div>
                  <div className="text-lg font-bold text-slate-900 dark:text-white mt-1">
                    {contentData?.password_form_count ?? 0}
                    <span className="text-xs text-slate-400 dark:text-slate-500 font-normal"> pwd fields</span>
                  </div>
                  <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">
                    {contentData?.has_credential_form ? '⚠️ Credential Input' : 'No Login Forms'}
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                  <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">Transport Security</div>
                  <div className="text-sm font-bold mt-1 text-slate-900 dark:text-white flex items-center gap-1.5">
                    <span>{responseData?.is_https ? '🔒 HTTPS' : '⚠️ Plain HTTP'}</span>
                  </div>
                  <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5 font-mono">
                    Hardening: {responseData?.security_headers?.hardening_score ?? 0}%
                  </div>
                </div>
              </div>

              {/* Redirect Chain Visualization */}
              {redirects && redirects.chain && redirects.chain.length > 0 && (
                <div className="space-y-3">
                  <h4 className="text-xs uppercase font-bold text-slate-700 dark:text-slate-300 tracking-wider flex items-center gap-2">
                    <span>🔀</span> Redirection Progression Map ({redirects.chain.length} hops)
                  </h4>
                  <div className="space-y-2 p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                    <div className="flex items-center gap-2 text-xs font-mono text-slate-600 dark:text-slate-400 pb-2 border-b border-slate-100 dark:border-slate-800/80">
                      <span className="px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-[10px] font-bold text-slate-700 dark:text-slate-300">START</span>
                      <span className="truncate">{redirects.initial_url}</span>
                    </div>

                    {redirects.chain.map((hop: any, idx: number) => (
                      <div key={idx} className="flex items-start gap-3 text-xs font-mono pl-4 border-l-2 border-slate-300 dark:border-slate-700 py-1">
                        <span className="text-slate-400 dark:text-slate-500 mt-0.5">↳</span>
                        <div className="flex-1 space-y-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="px-1.5 py-0.5 rounded bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800 text-[10px] font-bold">
                              {hop.redirect_type || `HTTP ${hop.status_code}`}
                            </span>
                            {hop.is_cross_domain && (
                              <span className="px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800 text-[10px] font-bold">
                                Cross-Domain
                              </span>
                            )}
                            <span className="text-slate-800 dark:text-slate-200 font-semibold">{hop.target_domain}</span>
                          </div>
                          <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate max-w-xl">
                            {hop.to_url}
                          </div>
                        </div>
                      </div>
                    ))}

                    <div className="flex items-center gap-2 text-xs font-mono text-emerald-600 dark:text-emerald-400 pt-2 border-t border-slate-100 dark:border-slate-800/80">
                      <span className="px-2 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950 text-[10px] font-bold text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800">FINAL</span>
                      <span className="truncate">{redirects.final_url}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Download Detection Alert & APK Handoff */}
              {downloadData && downloadData.download_detected && (
                <div className="p-4 rounded-xl bg-purple-50 dark:bg-purple-950/30 border border-purple-200 dark:border-purple-800/60 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-sm font-bold text-purple-700 dark:text-purple-300">
                      <span>📥</span>
                      <span>Automated File Download Detected</span>
                    </div>
                    <span className="px-2.5 py-0.5 rounded bg-purple-500/20 text-purple-700 dark:text-purple-300 border border-purple-500/30 text-xs font-mono font-bold">
                      Type: {downloadData.file_type}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900/80 p-3 rounded-lg border border-purple-200 dark:border-purple-900/40">
                    <div>Filename: <span className="text-slate-900 dark:text-white font-semibold">{downloadData.filename}</span></div>
                    <div>Size: <span className="text-slate-900 dark:text-white">{(downloadData.file_size_bytes / 1024).toFixed(1)} KB</span></div>
                    <div className="sm:col-span-2 truncate">
                      SHA-256: <span className="text-purple-600 dark:text-purple-300">{downloadData.sha256}</span>
                    </div>
                  </div>

                  {/* Embedded APK Analysis Scorecard */}
                  {downloadData.is_apk && downloadData.apk_analysis && (
                    <div className="p-3.5 rounded-lg bg-white dark:bg-slate-900 border border-purple-200 dark:border-purple-500/30 space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-2">
                          <span>🤖</span>
                          <span>Static APK Security Evaluation</span>
                        </div>
                        <Link
                          to="/scan/apk"
                          className="px-2.5 py-1 rounded bg-purple-600 hover:bg-purple-500 text-white text-[11px] font-bold transition"
                        >
                          Open APK Scanner →
                        </Link>
                      </div>
                      <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                        {downloadData.apk_analysis.summary}
                      </p>
                      <div className="flex flex-wrap gap-3 text-[11px] text-slate-500 dark:text-slate-400 font-mono pt-1">
                        <span>Package: <strong className="text-slate-800 dark:text-slate-200">{downloadData.apk_analysis.package_name}</strong></span>
                        <span>•</span>
                        <span>Malware Score: <strong className="text-amber-600 dark:text-amber-300">{downloadData.apk_analysis.rule_risk_score}/100</strong></span>
                        <span>•</span>
                        <span>Privacy Score: <strong className="text-purple-600 dark:text-purple-300">{downloadData.apk_analysis.privacy_risk_score}/100</strong></span>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Technical Limitation Disclaimer */}
              <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-[11px] text-slate-500 dark:text-slate-400 space-y-1">
                <div className="font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                  <span>ℹ️</span> Technical Limitations Notice
                </div>
                <p className="leading-relaxed">
                  {webAnalysis.limitation_disclaimer ||
                    'Static website and redirect analysis evaluates HTTP headers, server responses, HTML forms, and downloaded payloads. The scanner does not execute client-side JavaScript, submit credentials, or authenticate to websites.'}
                </p>
              </div>
            </div>
          )}

          {/* Detection Sources Breakdown */}
          <div className="p-5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
              <span className="text-xs uppercase font-bold tracking-wider text-slate-500 dark:text-slate-400">
                Detection Sources Breakdown
              </span>
              <span className="text-xs text-brand-600 dark:text-brand-400 font-mono font-semibold">Unified Risk Fusion</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Source 1: Rule Analysis */}
              <div className="p-4 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/80 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-emerald-600 dark:text-emerald-400 font-bold">✓</span>
                    <span className="text-sm font-bold text-slate-900 dark:text-white">Rule & Threat Analysis</span>
                  </div>
                  <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
                    Rule Score: {result.detection?.rules?.risk_score ?? result.heuristic_score ?? 0}/100
                  </span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  {result.indicators.length > 0
                    ? `${result.indicators.length} structural, redirect, or content indicator(s) triggered`
                    : 'Clean baseline — no suspicious patterns observed'}
                </p>
              </div>

              {/* Source 2: Machine Learning */}
              <div className="p-4 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/80 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-brand-600 dark:text-brand-400 font-bold">✓</span>
                    <span className="text-sm font-bold text-slate-900 dark:text-white">Machine Learning</span>
                  </div>
                  <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded ${
                    (result.detection?.ml?.prediction || result.ml_metadata?.prediction) === 'malicious' || (result.detection?.ml?.prediction || result.ml_metadata?.prediction) === 'phishing'
                      ? 'bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800'
                      : 'bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800'
                  }`}>
                    Prediction: {result.detection?.ml?.prediction || result.ml_metadata?.prediction || 'Evaluated'}
                  </span>
                </div>
                <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 font-mono">
                  <span>Model Score: {((result.detection?.ml?.model_score ?? result.ml_metadata?.probability ?? 0)).toFixed(2)}</span>
                  <span>Model Version: {result.detection?.ml?.model_version || result.ml_metadata?.model_version || 'url-model-1.0'}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Dynamic ML Algorithm & Architecture Attribution */}
          <MLArchitectureAttribution
            mlMetadata={result.ml_metadata}
            scanType="url"
            heuristicScore={result.heuristic_score}
          />

          {/* Executive Summary */}
          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1">
              Assessment Summary
            </h3>
            <p className="text-sm text-slate-700 dark:text-slate-200 leading-relaxed">{result.summary}</p>
          </div>

          {/* Evidence Breakdown */}
          <div className="space-y-3">
            <h3 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <span>Why was this flagged?</span>
              <span className="px-2 py-0.5 rounded-full text-xs bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                {result.indicators.length}
              </span>
            </h3>

            {/* Bulleted reasons list with evidence tags */}
            {result.reasons && result.reasons.length > 0 && (
              <ul className="space-y-2 p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                {result.reasons.map((reason, idx) => {
                  const isWebRule = reason.startsWith('Web Risk Rule:');
                  const isLexRule = reason.startsWith('Rule Evidence:');
                  const isML = reason.startsWith('ML Evidence:') || reason.startsWith('Web ML Classifier:') || reason.startsWith('ML Features:');
                  const cleanText = isWebRule
                    ? reason.replace('Web Risk Rule:', '').trim()
                    : isLexRule
                    ? reason.replace('Rule Evidence:', '').trim()
                    : isML
                    ? reason.replace(/ML (Evidence|Features):/, '').trim()
                    : reason;

                  return (
                    <li key={idx} className="flex items-start gap-2.5 text-xs text-slate-700 dark:text-slate-300">
                      {isWebRule && (
                        <span className="shrink-0 px-2 py-0.5 rounded bg-purple-100 dark:bg-purple-950/80 border border-purple-200 dark:border-purple-800/80 text-[10px] font-bold text-purple-700 dark:text-purple-300 uppercase tracking-wide">
                          Web Engine
                        </span>
                      )}
                      {isLexRule && (
                        <span className="shrink-0 px-2 py-0.5 rounded bg-blue-100 dark:bg-blue-950/80 border border-blue-200 dark:border-blue-800/80 text-[10px] font-bold text-blue-700 dark:text-blue-300 uppercase tracking-wide">
                          URL Lexical
                        </span>
                      )}
                      {isML && (
                        <span className="shrink-0 px-2 py-0.5 rounded bg-cyan-100 dark:bg-cyan-950/80 border border-cyan-200 dark:border-cyan-800/80 text-[10px] font-bold text-cyan-700 dark:text-cyan-300 uppercase tracking-wide">
                          Machine Learning
                        </span>
                      )}
                      {!isWebRule && !isLexRule && !isML && <span className="text-amber-500 font-bold">•</span>}
                      <span className="leading-relaxed">{cleanText}</span>
                    </li>
                  );
                })}
              </ul>
            )}

            {/* Individual Indicator Cards */}
            <div className="space-y-2.5">
              {result.indicators.map((ind, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 space-y-2 hover:border-slate-300 dark:hover:border-slate-700 transition"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-sm text-slate-900 dark:text-slate-200">{ind.name}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-bold border uppercase ${getRiskBadge(ind.severity)}`}
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
          </div>

          {/* Threat Intelligence & Reputation Correlation */}
          {(result.threat_intelligence || result.threat_graph) && (
            <ThreatIntelligencePanel
              threatIntelligence={result.threat_intelligence as any}
              threatGraph={result.threat_graph as any}
            />
          )}

          {/* Recommended Action */}
          <div className="p-5 rounded-xl bg-brand-50 dark:bg-brand-950/20 border border-brand-200 dark:border-brand-500/30 space-y-2">
            <h3 className="text-xs uppercase font-bold tracking-wider text-brand-600 dark:text-brand-400">
              Recommended Action & Defensive Guidance
            </h3>
            <p className="text-sm font-semibold text-slate-900 dark:text-white leading-relaxed">
              {result.recommendation || result.recommendations?.[0] || 'Avoid entering sensitive credentials or payment information.'}
            </p>
          </div>

          {/* Collapsible Technical Details Section */}
          <details className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs text-slate-600 dark:text-slate-400 space-y-4">
            <summary className="font-semibold text-slate-700 dark:text-slate-300 cursor-pointer hover:text-slate-900 dark:hover:text-white flex items-center justify-between">
              <span>Technical Details & Feature Vectors</span>
              <span className="text-[11px] text-slate-400 dark:text-slate-500 font-mono">Advanced View</span>
            </summary>

            {/* Top ML Contributing Signals */}
            {result.detection?.ml?.top_contributing_features && result.detection.ml.top_contributing_features.length > 0 && (
              <div className="mt-3 pt-3 border-t border-slate-200 dark:border-slate-800 space-y-2">
                <div className="font-semibold text-slate-700 dark:text-slate-300 text-[11px] uppercase tracking-wider">
                  Top Contributing ML Structural Signals
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {result.detection.ml.top_contributing_features.map((item, i) => (
                    <div key={i} className="p-2.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-between font-mono text-[11px]">
                      <span className="text-slate-500 dark:text-slate-400">{item.feature}</span>
                      <div className="text-right">
                        <span className="text-brand-600 dark:text-brand-400 font-bold">val={item.value}</span>
                        <span className="text-slate-400 dark:text-slate-500 text-[10px] ml-2">imp: {((item.global_importance ?? 0) * 100).toFixed(1)}%</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Extracted Features */}
            {result.features && (
              <div className="mt-3 pt-3 border-t border-slate-200 dark:border-slate-800 space-y-2">
                <div className="font-semibold text-slate-700 dark:text-slate-300 text-[11px] uppercase tracking-wider">
                  Extracted Feature Vector ({Object.keys(result.features).length} metrics)
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 font-mono text-[11px]">
                  {Object.entries(result.features).map(([key, val]) => (
                    <div key={key} className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/60 truncate">
                      <span className="text-slate-400 dark:text-slate-500 block truncate">{key}</span>
                      <span className="text-slate-700 dark:text-slate-200 font-semibold">{String(val)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </details>
        </div>
      )}
    </div>
  );
};

export default ScanUrl;
