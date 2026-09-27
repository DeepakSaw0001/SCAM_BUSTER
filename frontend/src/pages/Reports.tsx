import React, { useEffect, useState } from 'react';
import { getScanHistory, ScanHistoryItem } from '../services/api';

export const Reports: React.FC = () => {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const items = await getScanHistory(50);
      setHistory(items);
    } catch (err: any) {
      setError(err.message || 'Failed to load report data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const normalizeLevel = (l: string) => (l || '').toUpperCase();

  const totalScans = history.length;
  const critical = history.filter((h) => ['CRITICAL', 'HIGH', 'DANGEROUS'].includes(normalizeLevel(h.risk_level))).length;
  const medium = history.filter((h) => ['MEDIUM', 'SUSPICIOUS'].includes(normalizeLevel(h.risk_level))).length;
  const safe = history.filter((h) => ['LOW', 'VERY_LOW', 'SAFE'].includes(normalizeLevel(h.risk_level))).length;
  const avgScore = totalScans > 0 ? Math.round(history.reduce((s, h) => s + (h.composite_risk_score || 0), 0) / totalScans) : 0;

  const channelStats: Record<string, { total: number; critical: number; medium: number; safe: number; avgScore: number }> = {};
  history.forEach((h) => {
    if (!channelStats[h.scan_type]) channelStats[h.scan_type] = { total: 0, critical: 0, medium: 0, safe: 0, avgScore: 0 };
    channelStats[h.scan_type].total += 1;
    const s = normalizeLevel(h.risk_level);
    if (['CRITICAL', 'HIGH', 'DANGEROUS'].includes(s)) channelStats[h.scan_type].critical += 1;
    else if (['MEDIUM', 'SUSPICIOUS'].includes(s)) channelStats[h.scan_type].medium += 1;
    else channelStats[h.scan_type].safe += 1;
    channelStats[h.scan_type].avgScore += h.composite_risk_score || 0;
  });
  Object.keys(channelStats).forEach((k) => {
    const c = channelStats[k];
    c.avgScore = c.total > 0 ? Math.round(c.avgScore / c.total) : 0;
  });

  const getRiskBadge = (level: string) => {
    const l = normalizeLevel(level);
    if (['CRITICAL', 'HIGH', 'DANGEROUS'].includes(l)) return 'bg-rose-500/20 text-rose-600 dark:text-rose-300 border-rose-500/40';
    if (['MEDIUM', 'SUSPICIOUS'].includes(l)) return 'bg-amber-500/20 text-amber-600 dark:text-amber-300 border-amber-500/40';
    return 'bg-emerald-500/20 text-emerald-600 dark:text-emerald-300 border-emerald-500/40';
  };

  const CHANNEL_ICONS: Record<string, string> = {
    url: '🌐', text: '💬', message: '💬', email: '📧', phone: '📞', apk: '📦',
  };

  return (
    <div className="max-w-5xl mx-auto py-10 px-4 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-extrabold text-slate-900 dark:text-white mb-2">Threat Intelligence Reports</h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm">
            Aggregated threat analysis across all detection vectors and scan channels.
          </p>
        </div>
        <button
          onClick={fetchHistory}
          disabled={loading}
          className="px-4 py-2 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 text-xs font-semibold text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition flex items-center gap-2 shadow-sm"
        >
          <svg className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Refresh
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-700 dark:text-rose-300 text-xs font-mono">
          ⚠️ {error}
        </div>
      )}

      {loading ? (
        <div className="p-12 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-center space-y-3 shadow-sm">
          <div className="animate-spin w-8 h-8 border-2 border-brand-500 border-t-transparent rounded-full mx-auto" />
          <div className="text-sm text-slate-500 dark:text-slate-400">Loading threat data...</div>
        </div>
      ) : (
        <>
          {/* Executive KPI Row */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm transition-colors">
              <div className="text-xs text-slate-500 dark:text-slate-400 uppercase font-semibold">Total Scans</div>
              <div className="text-3xl font-extrabold text-slate-900 dark:text-white mt-1">{totalScans}</div>
              <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-1">All channels</div>
            </div>
            <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm transition-colors">
              <div className="text-xs text-slate-500 dark:text-slate-400 uppercase font-semibold">High / Critical</div>
              <div className="text-3xl font-extrabold text-rose-600 dark:text-rose-400 mt-1">{critical}</div>
              <div className="text-[11px] text-rose-500 dark:text-rose-400/80 mt-1">{totalScans > 0 ? Math.round((critical / totalScans) * 100) : 0}% of scans</div>
            </div>
            <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm transition-colors">
              <div className="text-xs text-slate-500 dark:text-slate-400 uppercase font-semibold">Medium Risk</div>
              <div className="text-3xl font-extrabold text-amber-600 dark:text-amber-400 mt-1">{medium}</div>
              <div className="text-[11px] text-amber-500 dark:text-amber-400/80 mt-1">{totalScans > 0 ? Math.round((medium / totalScans) * 100) : 0}% of scans</div>
            </div>
            <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm transition-colors">
              <div className="text-xs text-slate-500 dark:text-slate-400 uppercase font-semibold">Avg Risk Score</div>
              <div className="text-3xl font-extrabold text-brand-600 dark:text-brand-400 mt-1">{avgScore}<span className="text-xs text-slate-400 dark:text-slate-500 font-normal">/100</span></div>
              <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Session average</div>
            </div>
          </div>

          {/* Risk Distribution Bar */}
          {totalScans > 0 && (
            <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-3 transition-colors">
              <h2 className="text-sm font-bold text-slate-900 dark:text-white">Risk Distribution</h2>
              <div className="flex rounded-full overflow-hidden h-4 bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                {critical > 0 && (
                  <div
                    className="bg-rose-500/80 h-full transition-all"
                    style={{ width: `${(critical / totalScans) * 100}%` }}
                    title={`High/Critical: ${critical}`}
                  />
                )}
                {medium > 0 && (
                  <div
                    className="bg-amber-500/70 h-full transition-all"
                    style={{ width: `${(medium / totalScans) * 100}%` }}
                    title={`Medium: ${medium}`}
                  />
                )}
                {safe > 0 && (
                  <div
                    className="bg-emerald-500/60 h-full transition-all"
                    style={{ width: `${(safe / totalScans) * 100}%` }}
                    title={`Low/Safe: ${safe}`}
                  />
                )}
              </div>
              <div className="flex gap-4 text-[11px] text-slate-500 dark:text-slate-400">
                <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-rose-500/80 inline-block" />{Math.round((critical / totalScans) * 100)}% High/Critical</span>
                <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-amber-500/70 inline-block" />{Math.round((medium / totalScans) * 100)}% Medium</span>
                <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-emerald-500/60 inline-block" />{Math.round((safe / totalScans) * 100)}% Low/Safe</span>
              </div>
            </div>
          )}

          {/* Per-Channel Breakdown */}
          {Object.keys(channelStats).length > 0 && (
            <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4 transition-colors">
              <h2 className="text-sm font-bold text-slate-900 dark:text-white">Detection Vector Breakdown</h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {Object.entries(channelStats).map(([channel, stats]) => (
                  <div key={channel} className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2 transition-colors">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-sm font-bold text-slate-900 dark:text-white">
                        <span>{CHANNEL_ICONS[channel] || '🔍'}</span>
                        <span className="uppercase">{channel}</span>
                      </div>
                      <span className="font-mono text-xs text-slate-500 dark:text-slate-400">{stats.total} scans</span>
                    </div>
                    <div className="grid grid-cols-3 gap-2 text-[11px] text-center">
                      <div className="p-1.5 rounded bg-rose-500/10 border border-rose-500/20">
                        <div className="text-rose-600 dark:text-rose-400 font-bold text-base">{stats.critical}</div>
                        <div className="text-rose-500 dark:text-rose-400/80">High</div>
                      </div>
                      <div className="p-1.5 rounded bg-amber-500/10 border border-amber-500/20">
                        <div className="text-amber-600 dark:text-amber-400 font-bold text-base">{stats.medium}</div>
                        <div className="text-amber-500 dark:text-amber-400/80">Medium</div>
                      </div>
                      <div className="p-1.5 rounded bg-emerald-500/10 border border-emerald-500/20">
                        <div className="text-emerald-600 dark:text-emerald-400 font-bold text-base">{stats.safe}</div>
                        <div className="text-emerald-500 dark:text-emerald-400/80">Low</div>
                      </div>
                    </div>
                    <div className="text-[11px] text-slate-400 dark:text-slate-500 font-mono text-right">
                      Avg score: {stats.avgScore}/100
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Full Scan Log */}
          {totalScans === 0 ? (
            <div className="p-12 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-center space-y-2 shadow-sm">
              <div className="text-3xl">📊</div>
              <div className="text-base font-semibold text-slate-900 dark:text-white">No Scan Data Yet</div>
              <p className="text-xs text-slate-400 dark:text-slate-500 max-w-sm mx-auto">
                Analyze URLs, messages, emails, phone numbers, or APKs to populate this threat report.
              </p>
            </div>
          ) : (
            <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm transition-colors">
              <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">Full Scan Audit Log</h2>
                <span className="text-xs text-slate-500 font-mono">Last {totalScans} scans</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-50 dark:bg-slate-950/60 border-b border-slate-200 dark:border-slate-800 text-xs uppercase font-semibold text-slate-500 dark:text-slate-400 tracking-wider">
                    <tr>
                      <th className="py-3 px-4">Channel</th>
                      <th className="py-3 px-4">Target</th>
                      <th className="py-3 px-4">Risk Level</th>
                      <th className="py-3 px-4">Score</th>
                      <th className="py-3 px-4 text-right">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 text-slate-700 dark:text-slate-300">
                    {history.map((item) => (
                      <tr key={item.id} className="hover:bg-slate-50 dark:hover:bg-slate-950/40 transition">
                        <td className="py-3 px-4">
                          <span className="px-2.5 py-1 rounded-md text-[11px] font-mono uppercase bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 flex items-center gap-1.5 w-fit">
                            <span>{CHANNEL_ICONS[item.scan_type] || '🔍'}</span>
                            <span>{item.scan_type}</span>
                          </span>
                        </td>
                        <td className="py-3 px-4 max-w-xs font-mono text-xs truncate text-slate-900 dark:text-slate-200 font-medium">{item.target}</td>
                        <td className="py-3 px-4">
                          <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border uppercase ${getRiskBadge(item.risk_level)}`}>
                            {item.risk_level}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span className={`font-mono font-bold text-sm ${
                            item.composite_risk_score >= 70 ? 'text-rose-600 dark:text-rose-400' :
                            item.composite_risk_score >= 40 ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'
                          }`}>{item.composite_risk_score}/100</span>
                        </td>
                        <td className="py-3 px-4 text-right text-xs text-slate-500 font-mono whitespace-nowrap">
                          {new Date(item.timestamp).toLocaleString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Export Notice */}
          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400 flex items-start gap-3 transition-colors">
            <span className="text-slate-400 text-base">ℹ️</span>
            <div>
              <div className="text-slate-700 dark:text-slate-300 font-semibold mb-0.5">Report Data Source</div>
              <p className="leading-relaxed">
                This report is sourced in real time from the ScamBuster database via{' '}
                <code className="text-brand-600 dark:text-brand-400 bg-slate-200 dark:bg-slate-900 px-1 py-0.5 rounded text-[11px]">GET /api/v1/scan/history</code>.
                JSON export via the API endpoint is supported. PDF report generation is planned for a future release.
              </p>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
