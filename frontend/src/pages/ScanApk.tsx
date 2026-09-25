import React from 'react';
import { Link } from 'react-router-dom';

export const ScanApk: React.FC = () => {
  return (
    <div className="max-w-3xl mx-auto py-10 px-4">
      <div className="flex items-center gap-2 text-sm text-slate-400 mb-4">
        <Link to="/scan" className="hover:text-slate-200">Scanner</Link>
        <span>/</span>
        <span className="text-brand-400">APK Analysis</span>
      </div>
      <h1 className="text-3xl font-bold text-white mb-2">Android APK Scanner</h1>
      <p className="text-slate-400 mb-6">
        Inspects application manifests, dangerous permissions, and suspicious background capabilities.
      </p>

      <div className="p-10 rounded-xl bg-dark-900 border border-dashed border-slate-700 text-center space-y-3">
        <div className="text-4xl">📦</div>
        <div className="text-sm font-medium text-slate-300">Drag & Drop .apk file here</div>
        <p className="text-xs text-amber-400/90">
          ⚠️ Phase 01 Foundation active. Interactive scan engines will be wired in Phase 02.
        </p>
      </div>
    </div>
  );
};
