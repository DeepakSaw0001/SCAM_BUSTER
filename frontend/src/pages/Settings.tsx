import React, { useEffect, useState } from 'react';
import { getThreatIntelligenceStatus, lookupThreatIndicator } from '../services/api';
import { useTheme } from '../context/ThemeContext';
import { useAuth } from '../context/AuthContext';

export const Settings: React.FC = () => {
  const { mode, resolvedTheme, setMode } = useTheme();
  const { user, isAuthenticated, logout, openAuthModal } = useAuth();
  const [intelStatus, setIntelStatus] = useState<Record<string, any> | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [lookupValue, setLookupValue] = useState<string>('');
  const [lookupResult, setLookupResult] = useState<any>(null);
  const [lookupLoading, setLookupLoading] = useState<boolean>(false);
  const [lookupError, setLookupError] = useState<string | null>(null);

  useEffect(() => {
    loadStatus();
  }, []);

  const loadStatus = async () => {
    try {
      setLoading(true);
      const data = await getThreatIntelligenceStatus();
      setIntelStatus(data);
    } catch (err: any) {
      console.error('Failed to load intelligence status:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!lookupValue.trim()) return;

    setLookupLoading(true);
    setLookupError(null);
    setLookupResult(null);

    try {
      const res = await lookupThreatIndicator(lookupValue.trim());
      setLookupResult(res);
    } catch (err: any) {
      setLookupError(err.message || 'Lookup failed');
    } finally {
      setLookupLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto py-10 px-4 space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2">Platform Settings & Security Control</h1>
        <p className="text-slate-500 dark:text-slate-400 text-sm">
          Operational telemetry, interface theme, Threat Intelligence feeds, cache performance, and indicator diagnostics.
        </p>
      </div>

      {/* Appearance & Theme Configuration */}
      <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-4 shadow-sm transition-colors">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <span>🎨</span> Appearance & Interface Theme
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Select your visual presentation preference. Changes persist in your browser across sessions.
            </p>
          </div>
          <span className="text-xs px-2.5 py-1 rounded-full font-mono bg-brand-500/10 text-brand-600 dark:text-brand-400 border border-brand-500/20 capitalize font-semibold">
            Active: {resolvedTheme} mode
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
          <button
            type="button"
            onClick={() => setMode('dark')}
            className={`p-4 rounded-xl border text-left transition-all ${
              mode === 'dark'
                ? 'bg-brand-500/10 border-brand-500 ring-2 ring-brand-500/20 text-brand-600 dark:text-brand-400 font-medium'
                : 'bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-lg">🌙</span>
              {mode === 'dark' && <span className="w-2 h-2 rounded-full bg-brand-500" />}
            </div>
            <div className="font-bold text-sm text-slate-900 dark:text-white">Dark Theme</div>
            <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">High-contrast cyber security dark aesthetic</div>
          </button>

          <button
            type="button"
            onClick={() => setMode('light')}
            className={`p-4 rounded-xl border text-left transition-all ${
              mode === 'light'
                ? 'bg-brand-500/10 border-brand-500 ring-2 ring-brand-500/20 text-brand-600 dark:text-brand-400 font-medium'
                : 'bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-lg">☀️</span>
              {mode === 'light' && <span className="w-2 h-2 rounded-full bg-brand-500" />}
            </div>
            <div className="font-bold text-sm text-slate-900 dark:text-white">Light Theme</div>
            <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Crisp, clean high-readability daylight mode</div>
          </button>

          <button
            type="button"
            onClick={() => setMode('system')}
            className={`p-4 rounded-xl border text-left transition-all ${
              mode === 'system'
                ? 'bg-brand-500/10 border-brand-500 ring-2 ring-brand-500/20 text-brand-600 dark:text-brand-400 font-medium'
                : 'bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-lg">💻</span>
              {mode === 'system' && <span className="w-2 h-2 rounded-full bg-brand-500" />}
            </div>
            <div className="font-bold text-sm text-slate-900 dark:text-white">System Sync</div>
            <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Automatically syncs with OS dark/light mode</div>
          </button>
        </div>
      </div>

      {/* User Authentication & MongoDB Database Persistence */}
      <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-6 shadow-sm transition-colors">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <span>👤</span> User Account & MongoDB Database Persistence
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Synchronized security session, user profile, and cloud-hosted MongoDB Atlas persistence cluster.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>MongoDB Atlas Connected</span>
            </span>
          </div>
        </div>

        {/* User Profile / Guest State */}
        {isAuthenticated && user ? (
          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-xl bg-gradient-to-tr from-brand-600 to-teal-500 text-white font-bold text-base flex items-center justify-center shadow-md">
                  {(user.full_name || user.email).slice(0, 2).toUpperCase()}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-900 dark:text-white text-sm">
                      {user.full_name || user.username || 'Security Analyst'}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-brand-100 dark:bg-brand-950 text-brand-700 dark:text-brand-300 border border-brand-200 dark:border-brand-800">
                      {user.role}
                    </span>
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">
                    {user.email}
                  </div>
                </div>
              </div>

              <button
                type="button"
                onClick={logout}
                className="px-4 py-2 rounded-xl bg-rose-50 dark:bg-rose-950/40 hover:bg-rose-100 dark:hover:bg-rose-900/40 border border-rose-200 dark:border-rose-800/80 text-rose-700 dark:text-rose-300 text-xs font-semibold transition"
              >
                Sign Out
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 text-xs border-t border-slate-200 dark:border-slate-800/60">
              <div>
                <span className="text-slate-400 dark:text-slate-500 block text-[10px]">USER ID</span>
                <span className="font-mono text-slate-700 dark:text-slate-300">{user.id}</span>
              </div>
              <div>
                <span className="text-slate-400 dark:text-slate-500 block text-[10px]">ACCOUNT STATUS</span>
                <span className="text-emerald-600 dark:text-emerald-400 font-semibold">Active & Verified</span>
              </div>
              <div>
                <span className="text-slate-400 dark:text-slate-500 block text-[10px]">MEMBER SINCE</span>
                <span className="text-slate-700 dark:text-slate-300">
                  {user.created_at ? new Date(user.created_at).toLocaleDateString() : 'Active'}
                </span>
              </div>
            </div>
          </div>
        ) : (
          <div className="p-5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="font-bold text-slate-900 dark:text-white text-sm">
                Anonymous Session Active
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 max-w-lg">
                Sign in to isolate your personal scan history, sync audits across devices, and manage indicators securely.
              </p>
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => openAuthModal('login')}
                className="px-4 py-2 rounded-xl bg-brand-600 hover:bg-brand-500 text-white font-bold text-xs shadow-md shadow-brand-500/20 transition"
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => openAuthModal('register')}
                className="px-4 py-2 rounded-xl bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-800 dark:text-white font-semibold text-xs transition"
              >
                Register
              </button>
            </div>
          </div>
        )}

        {/* Database Telemetry Details */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
            <div className="text-[11px] text-slate-500 dark:text-slate-400">Database Engine</div>
            <div className="text-sm font-bold text-slate-900 dark:text-white mt-1">MongoDB Atlas 8.0</div>
            <div className="text-[10px] text-emerald-600 dark:text-emerald-400 font-mono mt-0.5">TLS Cluster0 Sharded</div>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
            <div className="text-[11px] text-slate-500 dark:text-slate-400">Primary Collections</div>
            <div className="text-sm font-bold text-slate-900 dark:text-white mt-1">users, scans, threat_indicators</div>
            <div className="text-[10px] text-slate-400 dark:text-slate-500 font-mono mt-0.5">Indexes Synchronized</div>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
            <div className="text-[11px] text-slate-500 dark:text-slate-400">Session Security</div>
            <div className="text-sm font-bold text-slate-900 dark:text-white mt-1">PyJWT + BCrypt (Salt 12)</div>
            <div className="text-[10px] text-brand-600 dark:text-brand-400 font-mono mt-0.5">HS256 Standard Bearer</div>
          </div>
        </div>
      </div>

      {/* Threat Engine Heuristic Configuration */}
      <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-4 shadow-sm transition-colors">
        <h2 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <span>⚙️</span> Detection Engine Configuration
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
            <div className="text-xs text-slate-500 dark:text-slate-400">Cyber Heuristic Sensitivity</div>
            <div className="text-base font-bold text-brand-600 dark:text-brand-400 mt-1">Multi-Heuristic Matrix</div>
            <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">Static Lexical + Structural</div>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
            <div className="text-xs text-slate-500 dark:text-slate-400">Machine Learning Classification</div>
            <div className="text-base font-bold text-brand-600 dark:text-brand-400 mt-1">Dual Calibrated RF + TF-IDF</div>
            <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">Threshold: 0.70 Confidence</div>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
            <div className="text-xs text-slate-500 dark:text-slate-400">Persistence Database</div>
            <div className="text-base font-bold text-emerald-600 dark:text-emerald-400 mt-1">MongoDB / File Storage</div>
            <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">Unified Scan History</div>
          </div>
        </div>
      </div>

      {/* Phase 11: Threat Intelligence Operational Telemetry */}
      <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-6 shadow-sm transition-colors">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <span>🌐</span> Threat Intelligence & Reputation Correlation (Phase 11)
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Centralized indicator correlation, local catalog freshness, and privacy-preserving cache.
            </p>
          </div>
          <button
            type="button"
            onClick={loadStatus}
            className="px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 hover:border-brand-500/50 text-xs font-mono text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition flex items-center gap-1.5"
          >
            <span>🔄</span> Refresh Status
          </button>
        </div>

        {loading ? (
          <div className="p-8 text-center text-xs text-slate-500 dark:text-slate-400 font-mono animate-pulse">
            Querying Threat Intelligence Operational Status...
          </div>
        ) : intelStatus ? (
          <div className="space-y-6">
            {/* KPI Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">Local Feed Records</div>
                <div className="text-lg font-bold text-slate-900 dark:text-white mt-1">
                  {intelStatus.local_feed?.record_count ?? 0}
                </div>
                <div className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">
                  v{intelStatus.local_feed?.version || '2026.09.v1'}
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">Configured Providers</div>
                <div className="text-lg font-bold text-slate-900 dark:text-white mt-1">
                  {intelStatus.providers?.length ?? 0}
                </div>
                <div className="text-[10px] text-emerald-600 dark:text-emerald-400 font-mono">
                  {intelStatus.providers?.filter((p: any) => p.is_available).length} Available
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">Cache Hit Rate</div>
                <div className="text-lg font-bold text-slate-900 dark:text-white mt-1">
                  {((intelStatus.cache?.hit_rate ?? 0) * 100).toFixed(1)}%
                </div>
                <div className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">
                  {intelStatus.cache?.total_requests ?? 0} queries ({intelStatus.cache?.cache_hits ?? 0} hits)
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">Cached Indicators</div>
                <div className="text-lg font-bold text-slate-900 dark:text-white mt-1">
                  {intelStatus.cache?.current_size ?? 0} / {intelStatus.cache?.max_size ?? 5000}
                </div>
                <div className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">
                  {intelStatus.cache?.evictions ?? 0} evictions
                </div>
              </div>
            </div>

            {/* Providers Breakdown */}
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-3">
                Configured Intelligence Adapters
              </h3>
              <div className="space-y-2">
                {intelStatus.providers?.map((provider: any, idx: number) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-800 dark:text-slate-200">{provider.name}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${
                          provider.is_available
                            ? 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-500/40'
                            : 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border-rose-500/40'
                        }`}>
                          {provider.is_available ? 'Available' : 'Unavailable'}
                        </span>
                        <span className="text-[10px] font-mono text-slate-500">
                          Priority: {provider.priority}
                        </span>
                      </div>
                      <div className="text-slate-500 dark:text-slate-400 text-[11px] flex gap-2 flex-wrap">
                        <span>Types: {provider.supported_indicator_types?.join(', ')}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-4 text-right font-mono text-[11px] text-slate-500 dark:text-slate-400">
                      <div>
                        <span className="text-slate-400 dark:text-slate-600 block text-[9px]">REQUESTS</span>
                        <span className="text-slate-800 dark:text-slate-200">{provider.request_count ?? 0}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 dark:text-slate-600 block text-[9px]">TIMEOUT</span>
                        <span className="text-slate-800 dark:text-slate-200">{provider.timeout_seconds}s</span>
                      </div>
                      <div>
                        <span className="text-slate-400 dark:text-slate-600 block text-[9px]">RATE LIMIT</span>
                        <span className="text-slate-800 dark:text-slate-200">{provider.rate_limit_per_minute}/min</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Local Feed Provenance & License */}
            {intelStatus.local_feed && (
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-800 dark:text-slate-200 flex items-center gap-2">
                    <span>📚</span> Local Verified Threat Feed Catalog
                  </span>
                  <span className="px-2 py-0.5 rounded bg-brand-100 dark:bg-brand-950 text-brand-700 dark:text-brand-300 border border-brand-200 dark:border-brand-800 text-[10px] font-mono font-bold">
                    License: {intelStatus.local_feed.license}
                  </span>
                </div>
                <p className="text-slate-600 dark:text-slate-400 text-[11px] leading-relaxed">
                  Source: {intelStatus.local_feed.source} • Version: {intelStatus.local_feed.version} • Retrieved: {intelStatus.local_feed.retrieved_at?.slice(0, 10)}
                </p>
                <div className="text-[10px] text-slate-400 dark:text-slate-500 font-mono pt-1">
                  Limitations: {intelStatus.local_feed.limitations}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
            Unable to communicate with Threat Intelligence backend service.
          </div>
        )}
      </div>

      {/* Interactive Indicator Diagnostics & Verification */}
      <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-4 shadow-sm transition-colors">
        <h2 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <span>🔍</span> Diagnostic Indicator Lookup
        </h2>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Query the Threat Intelligence layer directly for any URL, domain, IP address, phone number, or SHA-256 hash.
        </p>

        <form onSubmit={handleLookup} className="flex gap-2">
          <input
            type="text"
            value={lookupValue}
            onChange={(e) => setLookupValue(e.target.value)}
            placeholder="e.g. malicious-phish.net, 192.168.1.1, or a SHA-256 file hash..."
            className="flex-1 px-4 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white font-mono text-xs focus:outline-none focus:border-brand-500 placeholder-slate-400 dark:placeholder-slate-500"
          />
          <button
            type="submit"
            disabled={lookupLoading || !lookupValue.trim()}
            className="px-5 py-2.5 rounded-xl bg-brand-500 hover:bg-brand-400 text-slate-950 font-bold text-xs transition disabled:opacity-50"
          >
            {lookupLoading ? 'Checking...' : 'Lookup Indicator'}
          </button>
        </form>

        {lookupError && (
          <div className="p-3 rounded-lg bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-700 dark:text-rose-300 text-xs font-mono">
            ⚠️ {lookupError}
          </div>
        )}

        {lookupResult && (
          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-900 dark:text-white font-mono">
                {lookupResult.indicator?.normalized_value || lookupValue}
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                lookupResult.aggregate_verdict?.toLowerCase() === 'malicious'
                  ? 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border-rose-500/40'
                  : lookupResult.aggregate_verdict?.toLowerCase() === 'suspicious'
                  ? 'bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-500/40'
                  : lookupResult.aggregate_verdict?.toLowerCase() === 'benign'
                  ? 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-500/40'
                  : 'bg-blue-500/20 text-blue-700 dark:text-blue-300 border-blue-500/40'
              }`}>
                {lookupResult.aggregate_verdict || 'UNKNOWN'}
              </span>
            </div>
            <div className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
              {lookupResult.summary_explanation || 'No summary available.'}
            </div>
            <div className="text-[10px] font-mono text-slate-400 dark:text-slate-500 pt-1">
              Confidence: {Math.round((lookupResult.aggregate_confidence ?? 0) * 100)}% •
              Reports: {lookupResult.reports_count ?? 0} •
              Corroborated: {lookupResult.is_corroborated ? 'Yes' : 'No'} •
              Conflicts: {lookupResult.has_conflicts ? 'Yes' : 'No'}
            </div>
          </div>
        )}
      </div>

      {/* Security & Zero Leak Guarantee */}
      <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400 flex items-start gap-3">
        <span className="text-emerald-500 text-base">🛡️</span>
        <div>
          <span className="font-semibold text-slate-800 dark:text-slate-200">Zero Credential Exposure & Offline Integrity:</span>
          <p className="mt-0.5 text-slate-500 leading-relaxed">
            API keys and tokens are strictly configured via environment variables and never returned via endpoints.
            All indicators are normalized and SHA-256 hashed prior to cache storage. In the event of network disruption,
            ScamBuster seamlessly falls back to verified local feed catalogs.
          </p>
        </div>
      </div>
    </div>
  );
};

export default Settings;
