import React from 'react';
import { Link } from 'react-router-dom';

export const ScanPhone: React.FC = () => {
  return (
    <div className="max-w-3xl mx-auto py-10 px-4">
      <div className="flex items-center gap-2 text-sm text-slate-400 mb-4">
        <Link to="/scan" className="hover:text-slate-200">Scanner</Link>
        <span>/</span>
        <span className="text-brand-400">Phone Analysis</span>
      </div>
      <h1 className="text-3xl font-bold text-white mb-2">Phone Number Scanner</h1>
      <p className="text-slate-400 mb-6">
        Checks suspicious caller numbers, toll-fraud prefixes, and spoofing signatures.
      </p>

      <div className="p-6 rounded-xl bg-dark-900 border border-slate-800 space-y-4">
        <div className="text-sm font-medium text-slate-300">Phone Number</div>
        <input
          type="text"
          placeholder="+1 (800) 555-0199"
          className="w-full px-4 py-2.5 rounded-lg bg-dark-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none text-sm"
          disabled
        />
        <p className="text-xs text-amber-400/90">
          ⚠️ Phase 01 Foundation active. Interactive scan engines will be wired in Phase 02.
        </p>
      </div>
    </div>
  );
};
