import React from 'react';
import { Link } from 'react-router-dom';

export const ScanMessage: React.FC = () => {
  return (
    <div className="max-w-3xl mx-auto py-10 px-4">
      <div className="flex items-center gap-2 text-sm text-slate-400 mb-4">
        <Link to="/scan" className="hover:text-slate-200">Scanner</Link>
        <span>/</span>
        <span className="text-brand-400">Message Analysis</span>
      </div>
      <h1 className="text-3xl font-bold text-white mb-2">SMS & Text Scam Scanner</h1>
      <p className="text-slate-400 mb-6">
        Evaluates suspicious SMS, WhatsApp, and chat messages using TF-IDF feature extraction and Logistic Regression.
      </p>

      <div className="p-6 rounded-xl bg-dark-900 border border-slate-800 space-y-4">
        <div className="text-sm font-medium text-slate-300">Message Content</div>
        <textarea
          rows={4}
          placeholder="Paste suspicious text message here..."
          className="w-full px-4 py-2.5 rounded-lg bg-dark-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm"
          disabled
        />
        <button
          type="button"
          className="px-5 py-2.5 rounded-lg bg-brand-600/50 text-dark-950 font-bold text-sm cursor-not-allowed"
          disabled
        >
          Analyze Text
        </button>
        <p className="text-xs text-amber-400/90">
          ⚠️ Phase 01 Foundation active. Interactive scan engines will be wired in Phase 02.
        </p>
      </div>
    </div>
  );
};
