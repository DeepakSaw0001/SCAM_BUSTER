import React from 'react';

export const Dashboard: React.FC = () => {
  return (
    <div className="max-w-5xl mx-auto py-10 px-4">
      <h1 className="text-3xl font-bold text-white mb-2">Threat Intelligence Dashboard</h1>
      <p className="text-slate-400 mb-8">Aggregated metrics, active threat campaigns, and risk fusion telemetry.</p>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
        <div className="p-5 rounded-xl bg-dark-900 border border-slate-800">
          <div className="text-xs text-slate-400 uppercase font-semibold">Total Scans</div>
          <div className="text-2xl font-bold text-white mt-1">0</div>
        </div>
        <div className="p-5 rounded-xl bg-dark-900 border border-slate-800">
          <div className="text-xs text-slate-400 uppercase font-semibold">Threats Blocked</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1">0</div>
        </div>
        <div className="p-5 rounded-xl bg-dark-900 border border-slate-800">
          <div className="text-xs text-slate-400 uppercase font-semibold">ML Inference Uptime</div>
          <div className="text-2xl font-bold text-brand-400 mt-1">100%</div>
        </div>
      </div>

      <div className="p-8 rounded-xl bg-dark-900 border border-slate-800 text-center text-slate-400">
        Dashboard telemetry visualizations will be populated as scans are recorded in MongoDB.
      </div>
    </div>
  );
};
