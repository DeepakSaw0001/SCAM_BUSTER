import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { getScanHistory, ScanHistoryItem } from '../services/api';

export const Dashboard: React.FC = () => {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getScanHistory(50)
      .then((data) => setHistory(data))
      .catch(() => setHistory([]))
      .finally(() => setLoading(false));
  }, []);

  const totalScans = history.length;
  const dangerousCount = history.filter((h) => h.risk_level === 'DANGEROUS').length;
  const suspiciousCount = history.filter((h) => h.risk_level === 'SUSPICIOUS').length;
  const safeCount = history.filter((h) => h.risk_level === 'SAFE').length;

  const channelCounts = history.reduce<Record<string, number>>((acc, item) => {
    acc[item.scan_type] = (acc[item.scan_type] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="max-w-5xl mx-auto py-10 px-4 space-y-8">
      <div>
        <h1 className="text-3xl font-extrabold text-white mb-2">Threat Intelligence Dashboard</h1>
        <p className="text-slate-400">
          Aggregated cybersecurity metrics, active threat signals, and real-time risk fusion telemetry.
        </p>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="p-5 rounded-2xl bg-dark-900 border border-slate-800 shadow-lg">
          <div className="text-xs text-slate-400 uppercase font-semibold">Total Scans</div>
          <div className="text-3xl font-extrabold text-white mt-1">{totalScans}</div>
          <div className="text-[11px] text-slate-500 mt-1">Multi-channel inspections</div>
        </div>

        <div className="p-5 rounded-2xl bg-dark-900 border border-slate-800 shadow-lg">
          <div className="text-xs text-slate-400 uppercase font-semibold">Dangerous Threats</div>
          <div className="text-3xl font-extrabold text-rose-400 mt-1">{dangerousCount}</div>
          <div className="text-[11px] text-rose-400/70 mt-1">Immediate defense block</div>
        </div>

        <div className="p-5 rounded-2xl bg-dark-900 border border-slate-800 shadow-lg">
          <div className="text-xs text-slate-400 uppercase font-semibold">Suspicious Signals</div>
          <div className="text-3xl font-extrabold text-amber-400 mt-1">{suspiciousCount}</div>
          <div className="text-[11px] text-amber-400/70 mt-1">Elevated risk anomalies</div>
        </div>

        <div className="p-5 rounded-2xl bg-dark-900 border border-slate-800 shadow-lg">
          <div className="text-xs text-slate-400 uppercase font-semibold">Verified Safe</div>
          <div className="text-3xl font-extrabold text-emerald-400 mt-1">{safeCount}</div>
          <div className="text-[11px] text-emerald-400/70 mt-1">Clean baseline verified</div>
        </div>
      </div>

      {/* Channel Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="p-6 rounded-2xl bg-dark-900 border border-slate-800 shadow-lg md:col-span-1 space-y-4">
          <h2 className="text-base font-bold text-white">Detection Vectors</h2>
          <div className="space-y-3">
            {[
              { type: 'url', label: 'URLs & Domains', icon: '🔗' },
              { type: 'text', label: 'SMS & Messages', icon: '💬' },
              { type: 'email', label: 'Emails & BEC', icon: '📧' },
              { type: 'phone', label: 'Caller & Toll Fraud', icon: '📞' },
              { type: 'apk', label: 'APKs & Trojans', icon: '📦' },
            ].map((v) => (
              <div key={v.type} className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-2 text-slate-300">
                  <span>{v.icon}</span>
                  <span>{v.label}</span>
                </span>
                <span className="font-mono px-2 py-0.5 rounded bg-dark-950 border border-slate-800 text-slate-300">
                  {channelCounts[v.type] || 0}
                </span>
              </div>
            ))}
          </div>

          <div className="pt-2">
            <Link
              to="/scan"
              className="block w-full py-2.5 rounded-xl bg-brand-500 hover:bg-brand-400 text-dark-950 font-bold text-xs text-center transition"
            >
              Launch New Scan
            </Link>
          </div>
        </div>

        {/* Recent Threat Stream */}
        <div className="p-6 rounded-2xl bg-dark-900 border border-slate-800 shadow-lg md:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-bold text-white">Recent Telemetry Feed</h2>
            <Link to="/history" className="text-xs text-brand-400 hover:text-brand-300 font-semibold">
              View All History →
            </Link>
          </div>

          {loading ? (
            <div className="py-8 text-center text-xs text-slate-400">Loading live telemetry...</div>
          ) : history.length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-500">
              No telemetry events recorded yet. Run a scan to populate this feed.
            </div>
          ) : (
            <div className="space-y-2">
              {history.slice(0, 5).map((item) => (
                <div
                  key={item.id}
                  className="flex items-center justify-between p-3 rounded-xl bg-dark-950 border border-slate-800 text-xs"
                >
                  <div className="flex items-center gap-2.5 max-w-sm truncate">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-800 text-slate-300">
                      {item.scan_type}
                    </span>
                    <span className="font-mono text-slate-200 truncate">{item.target}</span>
                  </div>

                  <div className="flex items-center gap-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        item.risk_level === 'DANGEROUS'
                          ? 'text-rose-400 bg-rose-500/10'
                          : item.risk_level === 'SUSPICIOUS'
                          ? 'text-amber-400 bg-amber-500/10'
                          : 'text-emerald-400 bg-emerald-500/10'
                      }`}
                    >
                      {item.risk_level} ({item.composite_risk_score}/100)
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
