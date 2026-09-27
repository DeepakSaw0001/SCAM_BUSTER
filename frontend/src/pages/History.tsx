import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { getScanHistory, deleteScanApi, ScanHistoryItem } from '../services/api';
import { useAuth } from '../context/AuthContext';

export const History: React.FC = () => {
  const { user, isAuthenticated, openAuthModal } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const [activeTab, setActiveTab] = useState<'all' | 'my'>(() => {
    return searchParams.get('filter') === 'my' ? 'my' : 'all';
  });

  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const items = await getScanHistory(50, activeTab === 'my');
      setHistory(items);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch scan history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (searchParams.get('filter') === 'my') {
      setActiveTab('my');
    }
  }, [searchParams]);

  useEffect(() => {
    fetchHistory();
  }, [activeTab, isAuthenticated]);

  const handleTabChange = (tab: 'all' | 'my') => {
    setActiveTab(tab);
    setSearchParams(tab === 'my' ? { filter: 'my' } : {});
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm('Are you sure you want to delete this scan record?')) {
      return;
    }
    setDeletingId(id);
    try {
      await deleteScanApi(id);
      setHistory((prev) => prev.filter((item) => item.id !== id));
    } catch (err: any) {
      alert(err.message || 'Failed to delete scan record');
    } finally {
      setDeletingId(null);
    }
  };

  const getRiskBadge = (level: string) => {
    const l = (level || '').toUpperCase();
    if (['DANGEROUS', 'CRITICAL', 'HIGH'].includes(l)) {
      return 'bg-rose-500/20 text-rose-600 dark:text-rose-300 border-rose-500/40';
    }
    if (['SUSPICIOUS', 'MEDIUM'].includes(l)) {
      return 'bg-amber-500/20 text-amber-600 dark:text-amber-300 border-amber-500/40';
    }
    return 'bg-emerald-500/20 text-emerald-600 dark:text-emerald-300 border-emerald-500/40';
  };

  return (
    <div className="max-w-5xl mx-auto py-10 px-4 space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-extrabold text-slate-900 dark:text-white">Scan History & Audit Log</h1>
          <p className="text-slate-500 dark:text-slate-400 mt-1 text-sm">
            MongoDB Atlas persistent audit trail of inspected URLs, text messages, emails, phone numbers, and APKs.
          </p>
        </div>

        <button
          onClick={fetchHistory}
          disabled={loading}
          className="px-4 py-2 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 text-xs font-semibold text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition flex items-center gap-2 shadow-sm shrink-0"
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

      {/* Filter Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-2">
        <button
          type="button"
          onClick={() => handleTabChange('all')}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-2 ${
            activeTab === 'all'
              ? 'bg-brand-500/10 text-brand-600 dark:text-brand-400 border border-brand-500/30'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
          }`}
        >
          <span>🌐</span> Global Audit Feed
        </button>
        <button
          type="button"
          onClick={() => handleTabChange('my')}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-2 ${
            activeTab === 'my'
              ? 'bg-brand-500/10 text-brand-600 dark:text-brand-400 border border-brand-500/30'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
          }`}
        >
          <span>👤</span> My Scans {isAuthenticated && user && <span className="text-[10px] opacity-75">({user.email.split('@')[0]})</span>}
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-700 dark:text-rose-300 text-xs font-mono">
          ⚠️ {error}
        </div>
      )}

      {/* Guest Warning for "My Scans" */}
      {activeTab === 'my' && !isAuthenticated ? (
        <div className="p-10 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-center space-y-4 shadow-sm">
          <div className="text-3xl">🔐</div>
          <h2 className="text-lg font-bold text-slate-900 dark:text-white">Sign In to View Your Scans</h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 max-w-md mx-auto">
            You are currently browsing anonymously. Sign in to automatically link, organize, and view your private scan history across sessions.
          </p>
          <button
            type="button"
            onClick={() => openAuthModal('login')}
            className="px-5 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-500 text-white font-bold text-xs shadow-md shadow-brand-500/20 transition"
          >
            Sign In / Register
          </button>
        </div>
      ) : loading ? (
        <div className="p-12 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-center text-slate-500 dark:text-slate-400 space-y-3 shadow-sm">
          <div className="animate-spin w-8 h-8 border-2 border-brand-500 border-t-transparent rounded-full mx-auto" />
          <div className="text-sm">Loading MongoDB scan audit records...</div>
        </div>
      ) : history.length === 0 ? (
        <div className="p-12 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-center text-slate-500 dark:text-slate-400 space-y-2 shadow-sm">
          <div className="text-3xl">🛡️</div>
          <div className="text-base font-semibold text-slate-900 dark:text-white">
            {activeTab === 'my' ? 'No Scans Linked to Your Account' : 'No Previous Scans Found'}
          </div>
          <p className="text-xs text-slate-400 dark:text-slate-500 max-w-sm mx-auto">
            {activeTab === 'my'
              ? 'Submit any link, text, email, phone number, or APK while signed in to see your records here.'
              : 'Once you submit items for security analysis, your persistent records in MongoDB will appear here.'}
          </p>
        </div>
      ) : (
        <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 dark:bg-slate-950/60 border-b border-slate-200 dark:border-slate-800 text-xs uppercase font-semibold text-slate-500 dark:text-slate-400 tracking-wider">
                <tr>
                  <th className="py-3.5 px-4">Channel</th>
                  <th className="py-3.5 px-4">Target Inspected</th>
                  <th className="py-3.5 px-4">Risk Level</th>
                  <th className="py-3.5 px-4">Score</th>
                  <th className="py-3.5 px-4 text-right">Timestamp</th>
                  <th className="py-3.5 px-4 text-center">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 text-slate-700 dark:text-slate-300">
                {history.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-50 dark:hover:bg-slate-950/40 transition">
                    <td className="py-3.5 px-4">
                      <span className="px-2.5 py-1 rounded-md text-[11px] font-mono uppercase bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                        {item.scan_type}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 max-w-xs font-mono text-xs truncate text-slate-900 dark:text-slate-200 font-medium">
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
                            ? 'text-rose-600 dark:text-rose-400'
                            : item.composite_risk_score >= 35
                            ? 'text-amber-600 dark:text-amber-400'
                            : 'text-emerald-600 dark:text-emerald-400'
                        }`}
                      >
                        {item.composite_risk_score}
                      </span>
                      <span className="text-xs text-slate-400 dark:text-slate-500">/100</span>
                    </td>
                    <td className="py-3.5 px-4 text-right text-xs text-slate-500 font-mono">
                      {new Date(item.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-4 text-center">
                      <button
                        type="button"
                        onClick={(e) => handleDelete(item.id, e)}
                        disabled={deletingId === item.id}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-rose-600 dark:hover:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/40 transition"
                        title="Delete scan record"
                      >
                        {deletingId === item.id ? (
                          <div className="w-3.5 h-3.5 border-2 border-rose-500 border-t-transparent rounded-full animate-spin" />
                        ) : (
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        )}
                      </button>
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

export default History;
