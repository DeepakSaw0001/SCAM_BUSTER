import React, { useEffect, useState } from 'react';
import { getScanHistory, ScanHistoryItem } from '../services/api';

export const History: React.FC = () => {
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
      setError(err.message || 'Failed to fetch scan history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const getRiskBadge = (level: string) => {
    switch (level) {
      case 'DANGEROUS':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'SUSPICIOUS':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'SAFE':
      default:
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
    }
  };

  return (
    <div className="max-w-5xl mx-auto py-10 px-4">
      <div className="flex items-center justify-between mb-2">
        <h1 className="text-3xl font-extrabold text-white">Scan History & Audit Log</h1>
        <button
          onClick={fetchHistory}
          disabled={loading}
          className="px-4 py-2 rounded-xl bg-dark-900 border border-slate-800 hover:border-slate-700 text-xs font-semibold text-slate-300 hover:text-white transition flex items-center gap-2"
        >
          <svg
            className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="2"
              d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
            />
          </svg>
          <span>Refresh</span>
        </button>
      </div>
      <p className="text-slate-400 mb-8">
        Persistent audit trail of all inspected links, text messages, emails, phone numbers, and Android packages.
      </p>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800 text-rose-300 text-xs font-mono mb-6">
          ⚠️ {error}
        </div>
      )}

      {loading ? (
        <div className="p-12 rounded-2xl bg-dark-900 border border-slate-800 text-center text-slate-400 space-y-3">
          <div className="animate-spin w-8 h-8 border-2 border-brand-500 border-t-transparent rounded-full mx-auto" />
          <div className="text-sm">Loading scan audit logs...</div>
        </div>
      ) : history.length === 0 ? (
        <div className="p-12 rounded-2xl bg-dark-900 border border-slate-800 text-center text-slate-400 space-y-2">
          <div className="text-3xl">🛡️</div>
          <div className="text-base font-semibold text-white">No Previous Scans Found</div>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            Once you submit links, messages, emails, numbers, or APKs for analysis, your persistent scan records will appear here.
          </p>
        </div>
      ) : (
        <div className="rounded-2xl bg-dark-900 border border-slate-800 overflow-hidden shadow-2xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-dark-950/60 border-b border-slate-800 text-xs uppercase font-semibold text-slate-400 tracking-wider">
                <tr>
                  <th className="py-3.5 px-4">Channel</th>
                  <th className="py-3.5 px-4">Target Inspected</th>
                  <th className="py-3.5 px-4">Risk Level</th>
                  <th className="py-3.5 px-4">Score</th>
                  <th className="py-3.5 px-4 text-right">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {history.map((item) => (
                  <tr key={item.id} className="hover:bg-dark-950/40 transition">
                    <td className="py-3.5 px-4">
                      <span className="px-2.5 py-1 rounded-md text-[11px] font-mono uppercase bg-slate-800 text-slate-300">
                        {item.scan_type}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 max-w-xs font-mono text-xs truncate text-slate-200">
                      {item.target}
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-xs font-bold border uppercase ${getRiskBadge(
                          item.risk_level
                        )}`}
                      >
                        {item.risk_level}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`font-extrabold text-sm ${
                          item.composite_risk_score >= 70
                            ? 'text-rose-400'
                            : item.composite_risk_score >= 35
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {item.composite_risk_score}
                      </span>
                      <span className="text-xs text-slate-500">/100</span>
                    </td>
                    <td className="py-3.5 px-4 text-right text-xs text-slate-500 font-mono">
                      {new Date(item.timestamp).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
