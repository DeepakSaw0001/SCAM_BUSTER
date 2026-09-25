import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { scanApk, ScanResult } from '../services/api';
import { ScanResultCard } from '../components/ScanResultCard';

const COMMON_PERMISSIONS = [
  'android.permission.BIND_ACCESSIBILITY_SERVICE',
  'android.permission.SYSTEM_ALERT_WINDOW',
  'android.permission.RECEIVE_SMS',
  'android.permission.READ_SMS',
  'android.permission.SEND_SMS',
  'android.permission.REQUEST_INSTALL_PACKAGES',
  'android.permission.BIND_DEVICE_ADMIN',
  'android.permission.INTERNET',
  'android.permission.RECORD_AUDIO',
  'android.permission.CAMERA',
  'android.permission.READ_CONTACTS',
  'android.permission.ACCESS_FINE_LOCATION',
  'android.permission.ACCESS_BACKGROUND_LOCATION',
  'android.permission.READ_CALL_LOG',
];

const DEMO_APKS = [
  {
    label: 'Banking Trojan (Anatsa/SharkBot Pattern)',
    package_name: 'com.google.android.update.security',
    app_name: 'Google Play Protect Updater',
    permissions: [
      'android.permission.BIND_ACCESSIBILITY_SERVICE',
      'android.permission.SYSTEM_ALERT_WINDOW',
      'android.permission.RECEIVE_SMS',
      'android.permission.INTERNET',
      'android.permission.REQUEST_INSTALL_PACKAGES',
    ],
  },
  {
    label: 'Spyware / Surveillance Tool',
    package_name: 'com.battery.saver.turbo',
    app_name: 'Turbo Battery Saver',
    permissions: [
      'android.permission.RECORD_AUDIO',
      'android.permission.CAMERA',
      'android.permission.READ_CONTACTS',
      'android.permission.ACCESS_BACKGROUND_LOCATION',
      'android.permission.INTERNET',
    ],
  },
  {
    label: 'Benign Open Source Utility',
    package_name: 'org.foss.notes',
    app_name: 'FOSS Notepad',
    permissions: [
      'android.permission.INTERNET',
    ],
  },
];

export const ScanApk: React.FC = () => {
  const [packageName, setPackageName] = useState('');
  const [appName, setAppName] = useState('');
  const [selectedPermissions, setSelectedPermissions] = useState<string[]>([]);
  const [customPerm, setCustomPerm] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  const togglePermission = (perm: string) => {
    setSelectedPermissions((prev) =>
      prev.includes(perm) ? prev.filter((p) => p !== perm) : [...prev, perm]
    );
  };

  const handleAddCustom = (e: React.FormEvent) => {
    e.preventDefault();
    if (!customPerm.trim()) return;
    const formatted = customPerm.trim().startsWith('android.permission.')
      ? customPerm.trim()
      : `android.permission.${customPerm.trim()}`;

    if (!selectedPermissions.includes(formatted)) {
      setSelectedPermissions((prev) => [...prev, formatted]);
    }
    setCustomPerm('');
  };

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!packageName.trim() || selectedPermissions.length === 0) return;

    setLoading(true);
    setError(null);
    try {
      const res = await scanApk({
        package_name: packageName.trim(),
        app_name: appName.trim() || undefined,
        permissions: selectedPermissions,
      });
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze APK');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-10 px-4">
      <div className="flex items-center gap-2 text-sm text-slate-400 mb-4">
        <Link to="/scan" className="hover:text-slate-200">Scanner</Link>
        <span>/</span>
        <span className="text-brand-400">APK Analysis</span>
      </div>
      <h1 className="text-3xl font-extrabold text-white mb-2">Android APK & Manifest Security Scanner</h1>
      <p className="text-slate-400 mb-6">
        Analyzes Android package manifests and dangerous permission combinations mapped against the MITRE ATT&CK Mobile threat matrix to detect banking trojans, droppers, and spyware.
      </p>

      {/* Presets */}
      <div className="p-4 rounded-xl bg-dark-900 border border-slate-800 mb-6">
        <div className="text-xs text-slate-400 mb-2">Load Preconfigured Malware / Benign Profiles:</div>
        <div className="flex flex-wrap gap-2">
          {DEMO_APKS.map((demo, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => {
                setPackageName(demo.package_name);
                setAppName(demo.app_name);
                setSelectedPermissions(demo.permissions);
              }}
              className="px-3 py-1.5 rounded-lg bg-dark-950 border border-slate-800 hover:border-brand-500/50 text-xs text-slate-300 hover:text-white transition"
            >
              {demo.label}
            </button>
          ))}
        </div>
      </div>

      {/* Form */}
      <form onSubmit={handleScan} className="p-6 rounded-2xl bg-dark-900 border border-slate-800 shadow-xl space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Package Name (e.g. com.example.app) *
            </label>
            <input
              type="text"
              value={packageName}
              onChange={(e) => setPackageName(e.target.value)}
              placeholder="e.g. com.google.android.update.security"
              className="w-full px-4 py-2.5 rounded-xl bg-dark-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm font-mono"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Application Label / Display Name (Optional)
            </label>
            <input
              type="text"
              value={appName}
              onChange={(e) => setAppName(e.target.value)}
              placeholder="e.g. System Security Updater"
              className="w-full px-4 py-2.5 rounded-xl bg-dark-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm"
            />
          </div>
        </div>

        {/* Permissions Selector */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-semibold text-slate-300">
              Requested Permissions ({selectedPermissions.length} selected) *
            </label>
            <button
              type="button"
              onClick={() => setSelectedPermissions([])}
              className="text-xs text-slate-500 hover:text-slate-300"
            >
              Clear All
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-60 overflow-y-auto p-3 rounded-xl bg-dark-950 border border-slate-800">
            {COMMON_PERMISSIONS.map((perm) => {
              const checked = selectedPermissions.includes(perm);
              const shortName = perm.replace('android.permission.', '');
              const isCritical = ['BIND_ACCESSIBILITY_SERVICE', 'SYSTEM_ALERT_WINDOW', 'BIND_DEVICE_ADMIN'].includes(shortName);

              return (
                <label
                  key={perm}
                  className={`flex items-center gap-2 p-2 rounded-lg cursor-pointer text-xs transition border ${
                    checked
                      ? isCritical
                        ? 'bg-rose-950/30 border-rose-800 text-rose-300'
                        : 'bg-brand-500/10 border-brand-500/40 text-brand-300'
                      : 'border-transparent text-slate-400 hover:bg-dark-900'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => togglePermission(perm)}
                    className="accent-brand-500"
                  />
                  <span className="font-mono truncate">{shortName}</span>
                </label>
              );
            })}
          </div>
        </div>

        {/* Add custom permission */}
        <div className="flex gap-2">
          <input
            type="text"
            value={customPerm}
            onChange={(e) => setCustomPerm(e.target.value)}
            placeholder="Add custom permission (e.g. RECORD_AUDIO)..."
            className="flex-1 px-4 py-2 rounded-lg bg-dark-950 border border-slate-700 text-xs font-mono text-white placeholder-slate-500"
          />
          <button
            type="button"
            onClick={handleAddCustom}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-white"
          >
            Add
          </button>
        </div>

        <button
          type="submit"
          disabled={loading || !packageName.trim() || selectedPermissions.length === 0}
          className="w-full sm:w-auto px-6 py-3 rounded-xl bg-brand-500 hover:bg-brand-400 text-dark-950 font-bold text-sm transition shadow-lg shadow-brand-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
        >
          {loading ? (
            <>
              <svg className="animate-spin h-4 w-4 text-dark-950" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
              </svg>
              <span>Analyzing Manifest...</span>
            </>
          ) : (
            <span>Scan APK Manifest</span>
          )}
        </button>

        {error && (
          <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800 text-rose-300 text-xs font-mono">
            ⚠️ {error}
          </div>
        )}
      </form>

      {/* Result Display */}
      {result && <ScanResultCard result={result} />}
    </div>
  );
};
