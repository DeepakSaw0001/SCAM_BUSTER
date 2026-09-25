import React from 'react';

export const Reports: React.FC = () => {
  return (
    <div className="max-w-5xl mx-auto py-10 px-4">
      <h1 className="text-3xl font-bold text-white mb-2">Threat Reports</h1>
      <p className="text-slate-400 mb-8">Exportable compliance and cybersecurity incident reports.</p>

      <div className="p-8 rounded-xl bg-dark-900 border border-slate-800 text-center text-slate-400">
        Reporting module will be enabled in Phase 02 with PDF / JSON threat report generation.
      </div>
    </div>
  );
};
