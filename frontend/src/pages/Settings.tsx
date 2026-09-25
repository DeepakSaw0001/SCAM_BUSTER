import React from 'react';

export const Settings: React.FC = () => {
  return (
    <div className="max-w-4xl mx-auto py-10 px-4">
      <h1 className="text-3xl font-bold text-white mb-2">Platform Settings</h1>
      <p className="text-slate-400 mb-8">Manage API keys, heuristic analyzer thresholds, and notification alerts.</p>

      <div className="p-6 rounded-xl bg-dark-900 border border-slate-800 space-y-4">
        <h2 className="text-base font-semibold text-white">Threat Engine Configuration</h2>
        <div className="flex items-center justify-between py-2 border-b border-slate-800 text-sm">
          <span className="text-slate-300">Heuristic Cyber-Rule Sensitivity</span>
          <span className="text-brand-400 font-semibold">Standard</span>
        </div>
        <div className="flex items-center justify-between py-2 border-b border-slate-800 text-sm">
          <span className="text-slate-300">Machine Learning Confidence Threshold</span>
          <span className="text-brand-400 font-semibold">0.70</span>
        </div>
        <div className="flex items-center justify-between py-2 text-sm">
          <span className="text-slate-300">MongoDB Persistence Sync</span>
          <span className="text-emerald-400 font-semibold">Active</span>
        </div>
      </div>
    </div>
  );
};
