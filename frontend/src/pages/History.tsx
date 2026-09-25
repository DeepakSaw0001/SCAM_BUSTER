import React from 'react';

export const History: React.FC = () => {
  return (
    <div className="max-w-5xl mx-auto py-10 px-4">
      <h1 className="text-3xl font-bold text-white mb-2">Scan History</h1>
      <p className="text-slate-400 mb-8">Audit log of all analyzed links, messages, and files.</p>

      <div className="p-8 rounded-xl bg-dark-900 border border-slate-800 text-center text-slate-400">
        No previous scans found. Once you submit scans, your history will appear here.
      </div>
    </div>
  );
};
