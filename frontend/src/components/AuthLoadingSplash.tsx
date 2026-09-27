import React from 'react';

export const AuthLoadingSplash: React.FC = () => {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center p-6 relative overflow-hidden font-sans">
      {/* Background glow */}
      <div className="absolute w-[500px] h-[300px] bg-brand-500/10 rounded-full blur-[100px] pointer-events-none" />

      <div className="relative z-10 flex flex-col items-center text-center space-y-4 max-w-sm">
        <div className="relative">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-brand-600 to-emerald-500 flex items-center justify-center text-3xl shadow-xl shadow-brand-500/30 animate-pulse">
            🛡️
          </div>
          <div className="absolute -inset-2 rounded-2xl border border-brand-500/30 animate-ping opacity-30" />
        </div>

        <div className="space-y-1">
          <h2 className="text-lg font-bold text-white tracking-tight">
            ScamBuster Security Matrix
          </h2>
          <p className="text-xs text-slate-400 font-mono">
            Verifying cryptographic token & session credentials...
          </p>
        </div>

        <div className="w-48 h-1.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
          <div className="h-full bg-gradient-to-r from-brand-500 to-emerald-400 rounded-full animate-[shimmer_1.5s_infinite]" />
        </div>

        <div className="text-[11px] text-slate-500 font-mono">
          Connecting to MongoDB Atlas Cluster...
        </div>
      </div>
    </div>
  );
};
