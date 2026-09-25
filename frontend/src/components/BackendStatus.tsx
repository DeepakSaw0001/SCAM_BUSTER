import React from 'react';
import { useBackendHealth } from '../hooks/useBackendHealth';

export const BackendStatus: React.FC = () => {
  const { status, refresh } = useBackendHealth();

  return (
    <div className="inline-flex items-center gap-2.5 px-3.5 py-1.5 rounded-full text-xs font-medium border bg-dark-900 border-slate-800 shadow-sm">
      <span className="relative flex h-2 w-2">
        {status === 'loading' && (
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
        )}
        {status === 'connected' && (
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
        )}
        <span
          className={`relative inline-flex rounded-full h-2 w-2 ${
            status === 'loading'
              ? 'bg-amber-400'
              : status === 'connected'
              ? 'bg-emerald-500'
              : 'bg-rose-500'
          }`}
        ></span>
      </span>

      <span className="text-slate-300">
        Backend Status:{' '}
        <strong
          className={
            status === 'loading'
              ? 'text-amber-400'
              : status === 'connected'
              ? 'text-emerald-400 font-semibold'
              : 'text-rose-400 font-semibold'
          }
        >
          {status === 'loading' && 'Checking...'}
          {status === 'connected' && 'Connected'}
          {status === 'unavailable' && 'Unavailable'}
        </strong>
      </span>

      <button
        onClick={refresh}
        className="ml-1 text-slate-500 hover:text-slate-300 transition-colors"
        title="Check connection again"
        type="button"
      >
        ↻
      </button>
    </div>
  );
};
