import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { scanApk, uploadApk, ScanResult } from '../services/api';
import { ThreatIntelligencePanel } from '../components/ThreatIntelligencePanel';
import { MLArchitectureAttribution } from '../components/MLArchitectureAttribution';

const CATEGORY_OPTIONS = [
  { value: '', label: 'Auto-Detect / Unspecified' },
  { value: 'calculator', label: 'Calculator' },
  { value: 'camera', label: 'Camera / Photography' },
  { value: 'messaging', label: 'Messaging / Chat' },
  { value: 'social', label: 'Social Media / Video Calling' },
  { value: 'banking', label: 'Banking / Finance' },
  { value: 'productivity', label: 'Productivity / Office' },
  { value: 'game', label: 'Games' },
  { value: 'education', label: 'Education' },
  { value: 'utility', label: 'System Utility / Cleaner' },
  { value: 'health', label: 'Health & Fitness' },
  { value: 'shopping', label: 'Shopping / Retail' },
  { value: 'navigation', label: 'Navigation / Maps' },
];

const DEMO_APKS = [
  {
    label: 'Banking Trojan (Anatsa/SharkBot Pattern)',
    package_name: 'com.google.android.update.security',
    app_name: 'Google Play Protect Updater',
    category: 'utility',
    permissions: [
      'android.permission.BIND_ACCESSIBILITY_SERVICE',
      'android.permission.SYSTEM_ALERT_WINDOW',
      'android.permission.RECEIVE_SMS',
      'android.permission.INTERNET',
      'android.permission.REQUEST_INSTALL_PACKAGES',
    ],
  },
  {
    label: 'Privacy Risk: Suspicious Calculator',
    package_name: 'com.cool.scientific.calculator',
    app_name: 'Pro Scientific Calculator',
    category: 'calculator',
    permissions: [
      'android.permission.RECORD_AUDIO',
      'android.permission.CAMERA',
      'android.permission.READ_CONTACTS',
      'android.permission.READ_SMS',
      'android.permission.ACCESS_FINE_LOCATION',
      'android.permission.INTERNET',
    ],
  },
  {
    label: 'Legitimate Video Calling App (Expected)',
    package_name: 'com.safe.videocall',
    app_name: 'QuickCall Messenger',
    category: 'social',
    permissions: [
      'android.permission.CAMERA',
      'android.permission.RECORD_AUDIO',
      'android.permission.INTERNET',
      'android.permission.MODIFY_AUDIO_SETTINGS',
      'android.permission.FOREGROUND_SERVICE',
    ],
  },
  {
    label: 'Surveillance / Stalkerware Tool',
    package_name: 'com.battery.saver.turbo',
    app_name: 'Turbo Battery Saver',
    category: 'utility',
    permissions: [
      'android.permission.RECORD_AUDIO',
      'android.permission.CAMERA',
      'android.permission.READ_CONTACTS',
      'android.permission.ACCESS_FINE_LOCATION',
      'android.permission.ACCESS_BACKGROUND_LOCATION',
      'android.permission.INTERNET',
    ],
  },
  {
    label: 'SMS Toll Fraud / Spammer',
    package_name: 'com.fast.cleaner.pro',
    app_name: 'Ultra Memory Cleaner',
    category: 'utility',
    permissions: [
      'android.permission.SEND_SMS',
      'android.permission.RECEIVE_BOOT_COMPLETED',
      'android.permission.READ_PHONE_STATE',
      'android.permission.INTERNET',
    ],
  },
  {
    label: 'Benign Open Source Utility',
    package_name: 'org.foss.notes',
    app_name: 'FOSS Notepad',
    category: 'productivity',
    permissions: [
      'android.permission.INTERNET',
    ],
  },
];

export const ScanApk: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'upload' | 'preset'>('upload');
  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [declaredCategory, setDeclaredCategory] = useState<string>('');

  // Preset / Simulation state
  const [packageName, setPackageName] = useState('');
  const [appName, setAppName] = useState('');
  const [selectedPermissions, setSelectedPermissions] = useState<string[]>([]);

  // Permissions table filtering and expansion
  const [permFilter, setPermFilter] = useState<'all' | 'sensitive' | 'correlated'>('all');
  const [expandedPerms, setExpandedPerms] = useState<Record<string, boolean>>({});

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  const toggleExpandPerm = (perm: string) => {
    setExpandedPerms(prev => ({ ...prev, [perm]: !prev[perm] }));
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const handleScanUpload = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!file) return;

    setLoading(true);
    setError(null);
    try {
      const res = await uploadApk(file, declaredCategory || undefined);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze APK file.');
    } finally {
      setLoading(false);
    }
  };

  const handleScanPreset = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!packageName.trim() || selectedPermissions.length === 0) return;

    setLoading(true);
    setError(null);
    try {
      const res = await scanApk({
        package_name: packageName.trim(),
        app_name: appName.trim() || undefined,
        permissions: selectedPermissions,
        category: declaredCategory || undefined,
      });
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze APK specifications.');
    } finally {
      setLoading(false);
    }
  };

  const getRiskBadgeColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'critical':
      case 'dangerous':
        return 'bg-rose-500/20 text-rose-700 dark:text-rose-400 border-rose-500/30';
      case 'high':
        return 'bg-amber-500/20 text-amber-700 dark:text-amber-400 border-amber-500/30';
      case 'medium':
      case 'suspicious':
        return 'bg-yellow-500/20 text-yellow-700 dark:text-yellow-400 border-yellow-500/30';
      case 'low':
      case 'safe':
        return 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-400 border-emerald-500/30';
      case 'very_low':
        return 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/20';
      default:
        return 'bg-slate-500/20 text-slate-700 dark:text-slate-400 border-slate-500/30';
    }
  };

  const getSensitivityBadge = (sens: string) => {
    switch (sens?.toLowerCase()) {
      case 'very_high':
        return 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border-rose-500/30';
      case 'high':
        return 'bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-500/30';
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-700 dark:text-yellow-300 border-yellow-500/30';
      case 'low':
      default:
        return 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-400 border border-slate-200 dark:border-slate-700';
    }
  };

  const permDetails = result?.detection?.permissions;
  const certDetails = result?.detection?.certificate;
  const compDetails = result?.detection?.components;
  const techDetails = result?.technical_details;
  const rawPrivacy = result?.privacy_analysis;
  const privacyAnalysis: any = rawPrivacy ? {
    ...rawPrivacy,
    total_permissions: rawPrivacy.total_permissions ?? rawPrivacy.total_requested_count ?? 0,
    sensitive_permissions_count: rawPrivacy.sensitive_permissions_count ?? 0,
    high_impact_capabilities_count: rawPrivacy.high_impact_capabilities_count ?? rawPrivacy.high_impact_count ?? (rawPrivacy.high_impact_capabilities?.length || 0),
    context_mismatch_level: rawPrivacy.context_mismatch_level ?? rawPrivacy.context_analysis?.mismatch_level ?? 'NONE',
    declared_category: rawPrivacy.declared_category ?? rawPrivacy.context_analysis?.declared_category ?? '',
    context_mismatch_explanation: rawPrivacy.context_mismatch_explanation ?? rawPrivacy.context_analysis?.explanation ?? '',
    combination_risks: rawPrivacy.combination_risks ?? rawPrivacy.combination_findings ?? [],
    permissions: rawPrivacy.permissions ?? rawPrivacy.permissions_detail ?? [],
  } : null;

  // Filter permissions
  const rawPermList: any[] = privacyAnalysis?.permissions || [];
  const filteredPerms = rawPermList.filter((p: any) => {
    if (permFilter === 'sensitive') {
      return p.sensitivity === 'HIGH' || p.sensitivity === 'VERY_HIGH';
    }
    if (permFilter === 'correlated') {
      return p.api_correlation_status === 'CORRELATED' || p.status === 'CORRELATED';
    }
    return true;
  });

  return (
    <div className="max-w-4xl mx-auto py-10 px-4">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400 mb-4">
        <Link to="/scan" className="hover:text-slate-700 dark:hover:text-slate-200">Scanner</Link>
        <span>/</span>
        <span className="text-brand-500 dark:text-brand-400 font-semibold">Android APK & Privacy Scanner</span>
      </div>

      <div className="mb-6">
        <h1 className="text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight flex items-center gap-3">
          <span className="p-2 rounded-xl bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20">
            🤖
          </span>
          Android APK Malware & Privacy Analyzer
        </h1>
        <p className="text-slate-600 dark:text-slate-400 mt-2 text-sm">
          Performs static security and privacy analysis of Android APK packages. Inspects sensitive permissions,
          contextual category alignment, multi-permission capability combinations, and DEX bytecode API correlations.
        </p>
      </div>

      {/* Security & Non-Execution Guarantee */}
      <div className="p-4 rounded-xl bg-slate-100/80 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 text-xs text-slate-700 dark:text-slate-300 flex items-start gap-3 mb-6">
        <span className="text-base">🛡️</span>
        <div>
          <strong className="text-slate-900 dark:text-slate-100 font-semibold block mb-0.5">Strict Static Analysis Guarantee:</strong>
          ScamBuster analyzes APK binaries strictly in isolated memory using static decompilation. We never install,
          execute, or launch Android applications, and we never access your personal device hardware, contacts, or SMS.
        </div>
      </div>

      {/* Declared Category Selector */}
      <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm mb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <label className="text-xs font-semibold text-slate-800 dark:text-slate-200 block">Declared Application Category (Optional Context)</label>
          <span className="text-[11px] text-slate-500 dark:text-slate-400">
            Helps evaluate if requested permissions match declared functionality (e.g. Camera for Video Calling vs Calculator).
          </span>
        </div>
        <select
          value={declaredCategory}
          onChange={(e) => setDeclaredCategory(e.target.value)}
          className="px-3 py-2 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-xs text-slate-900 dark:text-white focus:outline-none focus:border-brand-500"
        >
          {CATEGORY_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-4 border-b border-slate-200 dark:border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('upload')}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-2 ${
            activeTab === 'upload'
              ? 'bg-brand-500 text-slate-950 shadow-md shadow-brand-500/20'
              : 'bg-slate-100 dark:bg-slate-900 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white border border-slate-200 dark:border-slate-800'
          }`}
        >
          <span>📦</span> Upload APK Binary
        </button>
        <button
          onClick={() => setActiveTab('preset')}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center gap-2 ${
            activeTab === 'preset'
              ? 'bg-brand-500 text-slate-950 shadow-md shadow-brand-500/20'
              : 'bg-slate-100 dark:bg-slate-900 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white border border-slate-200 dark:border-slate-800'
          }`}
        >
          <span>⚡</span> Quick Test Presets
        </button>
      </div>

      {/* Mode 1: APK File Upload */}
      {activeTab === 'upload' && (
        <form onSubmit={handleScanUpload} className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-5">
          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            className={`border-2 border-dashed rounded-2xl p-8 text-center transition flex flex-col items-center justify-center cursor-pointer ${
              dragOver
                ? 'border-brand-500 bg-brand-500/10'
                : 'border-slate-300 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-950/60 hover:border-slate-400 dark:hover:border-slate-600'
            }`}
          >
            <input
              type="file"
              accept=".apk,.zip"
              onChange={handleFileChange}
              className="hidden"
              id="apk-file-input"
            />
            <label htmlFor="apk-file-input" className="cursor-pointer flex flex-col items-center">
              <div className="p-4 rounded-full bg-slate-200 dark:bg-slate-800/80 text-3xl mb-3 shadow-inner">
                🤖
              </div>
              <span className="text-sm font-semibold text-slate-800 dark:text-slate-200">
                {file ? file.name : 'Drag & Drop your Android APK here'}
              </span>
              <span className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                {file ? `${(file.size / (1024 * 1024)).toFixed(2)} MB` : 'or click to browse from your device (.apk)'}
              </span>
              <span className="text-[11px] text-slate-500 dark:text-slate-400 mt-3">
                Maximum file size: 50MB • Protected against ZIP-bombs & traversal
              </span>
            </label>
          </div>

          <div className="flex items-center justify-between pt-2">
            <button
              type="submit"
              disabled={loading || !file}
              className="px-8 py-3 rounded-xl bg-brand-500 hover:bg-brand-400 text-slate-950 font-bold text-sm transition shadow-lg shadow-brand-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <svg className="animate-spin h-4 w-4 text-slate-950" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                  </svg>
                  <span>Decompressing & Inspecting APK...</span>
                </>
              ) : (
                <span>Analyze APK File</span>
              )}
            </button>
            <span className="text-xs text-slate-500 dark:text-slate-400">
              Powered by pyaxmlparser + DEX Code Scanner + Privacy Engine
            </span>
          </div>

          {error && (
            <div className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-700 dark:text-rose-300 text-xs font-mono">
              ⚠️ {error}
            </div>
          )}
        </form>
      )}

      {/* Mode 2: Quick Test Presets */}
      {activeTab === 'preset' && (
        <form onSubmit={handleScanPreset} className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-5">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {DEMO_APKS.map((demo, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setPackageName(demo.package_name);
                  setAppName(demo.app_name);
                  setSelectedPermissions(demo.permissions);
                  setDeclaredCategory(demo.category);
                }}
                className="text-left p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 hover:border-brand-500/40 text-xs transition group"
              >
                <div className="flex items-center justify-between">
                  <div className="font-semibold text-slate-800 dark:text-slate-200 group-hover:text-brand-500 dark:group-hover:text-brand-400">{demo.label}</div>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-400 uppercase">
                    {demo.category}
                  </span>
                </div>
                <div className="text-slate-500 dark:text-slate-400 text-[11px] font-mono mt-0.5">{demo.package_name}</div>
                <div className="text-slate-500 dark:text-slate-400 text-[11px] mt-1.5">{demo.permissions.length} permissions</div>
              </button>
            ))}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            <div>
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Package Name</label>
              <input
                type="text"
                value={packageName}
                onChange={(e) => setPackageName(e.target.value)}
                placeholder="e.g. com.example.app"
                className="w-full px-4 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white font-mono text-xs focus:outline-none focus:border-brand-500"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">App Name</label>
              <input
                type="text"
                value={appName}
                onChange={(e) => setAppName(e.target.value)}
                placeholder="e.g. System Security"
                className="w-full px-4 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white text-xs focus:outline-none focus:border-brand-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
              Permissions Selected ({selectedPermissions.length})
            </label>
            <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex flex-wrap gap-1.5 max-h-32 overflow-y-auto font-mono text-[11px]">
              {selectedPermissions.map((p, idx) => (
                <span key={idx} className="px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800/80 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-700">
                  {p.replace('android.permission.', '')}
                </span>
              ))}
            </div>
          </div>

          <button
            type="submit"
            disabled={loading || !packageName.trim()}
            className="w-full sm:w-auto px-8 py-3 rounded-xl bg-brand-500 hover:bg-brand-400 text-slate-950 font-bold text-sm transition shadow-lg shadow-brand-500/20 disabled:opacity-50"
          >
            {loading ? 'Analyzing...' : 'Analyze Preset Specifications'}
          </button>

          {error && (
            <div className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-700 dark:text-rose-300 text-xs font-mono">
              ⚠️ {error}
            </div>
          )}
        </form>
      )}

      {/* Result Display */}
      {result && (
        <div className="mt-8 space-y-6">
          {/* Main Risk Card */}
          <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-200 dark:border-slate-800">
              <div>
                <div className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400 font-semibold mb-1">
                  APK Security Analysis
                </div>
                <div className="text-xl font-bold text-slate-900 dark:text-white tracking-wide">
                  {techDetails?.application_label || techDetails?.package_name || result.target}
                </div>
                <div className="text-xs font-mono text-slate-500 dark:text-slate-400 mt-1">
                  {techDetails?.package_name} • v{techDetails?.version_name || '1.0'} (SDK {techDetails?.target_sdk || 'N/A'})
                </div>
              </div>

              <div className="flex items-center gap-4">
                <div className="text-right">
                  <div className="text-xs text-slate-500 dark:text-slate-400">Risk Score</div>
                  <div className="text-3xl font-extrabold text-slate-900 dark:text-white">
                    {result.composite_risk_score}
                    <span className="text-sm text-slate-500 font-normal"> / 100</span>
                  </div>
                </div>
                <div className={`px-4 py-2 rounded-xl text-sm font-bold uppercase tracking-wider border ${getRiskBadgeColor(result.risk_level)}`}>
                  {result.risk_level.replace('_', ' ')}
                </div>
              </div>
            </div>

            {/* Matrix of Detection Sources */}
            <div className="py-5 border-b border-slate-200 dark:border-slate-800 grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <div className="text-xs text-slate-500 dark:text-slate-400 mb-1">Manifest Analysis</div>
                <div className="text-sm font-semibold text-slate-900 dark:text-white">
                  {permDetails?.total_count || 0} Permissions
                </div>
                <div className="text-[11px] text-amber-600 dark:text-amber-400 mt-0.5">
                  {permDetails?.dangerous_count || 0} Dangerous / {permDetails?.special_count || 0} Special
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <div className="text-xs text-slate-500 dark:text-slate-400 mb-1">DEX Bytecode</div>
                <div className="text-sm font-semibold text-slate-900 dark:text-white">
                  {techDetails?.dex_count || 1} DEX Files
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                  DynLoading: {techDetails?.dynamic_loading_count || 0}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <div className="text-xs text-slate-500 dark:text-slate-400 mb-1">ML Classifier</div>
                <div className="text-sm font-semibold text-slate-900 dark:text-white">
                  {Math.round((result.detection?.ml?.model_score || 0) * 100)}% Probability
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                  {result.detection?.ml?.prediction || 'Clean'}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <div className="text-xs text-slate-500 dark:text-slate-400 mb-1">Certificate</div>
                <div className="text-sm font-semibold text-slate-900 dark:text-white truncate">
                  {certDetails?.is_debug_certificate ? '⚠️ Debug Key' : 'Signed'}
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 truncate">
                  {certDetails?.sha256_fingerprint ? `${certDetails.sha256_fingerprint.slice(0, 10)}...` : 'N/A'}
                </div>
              </div>
            </div>

            {/* Dynamic ML Algorithm & Architecture Attribution */}
            <div className="pt-5 border-b border-slate-200 dark:border-slate-800 pb-5">
              <MLArchitectureAttribution
                mlMetadata={result.ml_metadata}
                scanType="apk"
                heuristicScore={result.heuristic_score}
              />
            </div>

            {/* Summary & Recommendations */}
            <div className="pt-5 space-y-4">
              <div className="p-4 rounded-xl bg-slate-50/70 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 text-sm">
                <div className="text-xs uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider mb-1">
                  Analysis Summary
                </div>
                <p className="text-slate-800 dark:text-slate-200 leading-relaxed">{result.summary}</p>
              </div>

              {result.recommendation && (
                <div className="p-4 rounded-xl bg-brand-500/10 border border-brand-500/20 text-sm">
                  <div className="text-xs uppercase font-bold text-brand-600 dark:text-brand-400 tracking-wider mb-1 flex items-center gap-1.5">
                    <span>🛡️</span> Recommendation & Defensive Guidance
                  </div>
                  <p className="text-brand-800 dark:text-brand-200 leading-relaxed">{result.recommendation}</p>
                </div>
              )}
            </div>
          </div>

          {/* Threat Intelligence & Reputation Correlation */}
          {(result.threat_intelligence || result.threat_graph) && (
            <ThreatIntelligencePanel
              threatIntelligence={result.threat_intelligence as any}
              threatGraph={result.threat_graph as any}
            />
          )}

          {/* DEDICATED PHASE 08 SECTION: PRIVACY & PERMISSION ANALYSIS */}
          {privacyAnalysis && (
            <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-purple-500/30 shadow-sm space-y-6">
              {/* Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-purple-500/20 text-purple-600 dark:text-purple-300 border border-purple-500/30 text-2xl">
                    🔒
                  </div>
                  <div>
                    <h2 className="text-lg font-bold text-slate-900 dark:text-white tracking-tight">
                      PRIVACY & PERMISSION ANALYSIS
                    </h2>
                    <p className="text-xs text-slate-600 dark:text-slate-400">
                      Evaluates requested capabilities, contextual expectation, multi-permission attack surfaces, and static bytecode references.
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase tracking-wider font-semibold">Privacy Attention</div>
                    <div className="text-2xl font-extrabold text-slate-900 dark:text-white">
                      {privacyAnalysis.privacy_score}
                      <span className="text-xs text-slate-500 font-normal"> / 100</span>
                    </div>
                  </div>
                  <div className={`px-3 py-1.5 rounded-xl text-xs font-bold uppercase tracking-wider border ${getRiskBadgeColor(privacyAnalysis.privacy_risk_level)}`}>
                    {privacyAnalysis.privacy_risk_level?.replace('_', ' ')}
                  </div>
                </div>
              </div>

              {/* KPI Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-center">
                  <div className="text-xs text-slate-500 dark:text-slate-400">Requested Permissions</div>
                  <div className="text-xl font-bold text-slate-900 dark:text-white mt-1">
                    {privacyAnalysis.total_permissions}
                  </div>
                  <div className="text-[10px] text-slate-500 dark:text-slate-400 mt-0.5">Declared in Manifest</div>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-center">
                  <div className="text-xs text-slate-500 dark:text-slate-400">Sensitive Permissions</div>
                  <div className="text-xl font-bold text-amber-600 dark:text-amber-400 mt-1">
                    {privacyAnalysis.sensitive_permissions_count}
                  </div>
                  <div className="text-[10px] text-slate-500 dark:text-slate-400 mt-0.5">High/Very-High Tier</div>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-center">
                  <div className="text-xs text-slate-500 dark:text-slate-400">High-Impact Capabilities</div>
                  <div className="text-xl font-bold text-rose-600 dark:text-rose-400 mt-1">
                    {privacyAnalysis.high_impact_capabilities_count}
                  </div>
                  <div className="text-[10px] text-slate-500 dark:text-slate-400 mt-0.5">Accessibility, SMS, etc.</div>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-center">
                  <div className="text-xs text-slate-500 dark:text-slate-400">Context Mismatch</div>
                  <div className="text-xl font-bold mt-1">
                    <span className={
                      privacyAnalysis.context_mismatch_level === 'HIGH' ? 'text-rose-600 dark:text-rose-400' :
                      privacyAnalysis.context_mismatch_level === 'MEDIUM' ? 'text-yellow-600 dark:text-yellow-400' :
                      privacyAnalysis.context_mismatch_level === 'LOW' ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-600 dark:text-slate-400'
                    }>
                      {privacyAnalysis.context_mismatch_level || 'UNKNOWN'}
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-500 dark:text-slate-400 mt-0.5 capitalize">
                    {privacyAnalysis.declared_category || 'Unspecified'}
                  </div>
                </div>
              </div>

              {/* High-Impact Capabilities Banner */}
              {privacyAnalysis.high_impact_capabilities && privacyAnalysis.high_impact_capabilities.length > 0 && (
                <div className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/30 border border-rose-200 dark:border-rose-800/50">
                  <div className="text-xs uppercase font-bold text-rose-700 dark:text-rose-300 tracking-wider mb-2 flex items-center gap-1.5">
                    <span>⚠️</span> Elevated High-Impact Capabilities Detected
                  </div>
                  <p className="text-xs text-slate-700 dark:text-slate-300 mb-3">
                    These permissions confer deep administrative, screen interaction, or background data access capabilities that warrant strict user scrutiny:
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {privacyAnalysis.high_impact_capabilities.map((cap: string, idx: number) => (
                      <span key={idx} className="px-2.5 py-1 rounded-lg bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/30 text-xs font-semibold flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-rose-500"></span>
                        {cap}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Context Analysis Box */}
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs">
                <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-200 dark:border-slate-800">
                  <div className="font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                    <span>🧭</span> Contextual Alignment Analysis
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${
                    privacyAnalysis.context_mismatch_level === 'HIGH' ? 'bg-rose-500/20 text-rose-700 dark:text-rose-400 border-rose-500/30' :
                    privacyAnalysis.context_mismatch_level === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-700 dark:text-yellow-400 border-yellow-500/30' :
                    privacyAnalysis.context_mismatch_level === 'LOW' ? 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-400 border-emerald-500/30' :
                    'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-400 border border-slate-200 dark:border-slate-700'
                  }`}>
                    Mismatch: {privacyAnalysis.context_mismatch_level || 'UNKNOWN'}
                  </span>
                </div>
                <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                  {privacyAnalysis.context_mismatch_explanation}
                </p>
              </div>

              {/* Multi-Permission Combinations */}
              {privacyAnalysis.combination_risks && privacyAnalysis.combination_risks.length > 0 && (
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs space-y-2.5">
                  <div className="font-bold text-amber-700 dark:text-amber-300 uppercase tracking-wider flex items-center gap-1.5">
                    <span>⚡</span> Multi-Permission Capability Combinations ({privacyAnalysis.combination_risks.length})
                  </div>
                  <div className="space-y-2">
                    {privacyAnalysis.combination_risks.map((comb: any, idx: number) => (
                      <div key={idx} className="p-3 rounded-lg bg-white dark:bg-slate-900 border border-amber-500/30">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-amber-800 dark:text-amber-200">{comb.name}</span>
                          <span className="text-[10px] uppercase font-bold text-amber-700 dark:text-amber-400">{comb.severity}</span>
                        </div>
                        <p className="text-slate-700 dark:text-slate-300 text-[11px] mt-1">{comb.concern || comb.privacy_concern || comb.description}</p>
                        <div className="flex flex-wrap gap-1 mt-2">
                          {comb.matched_permissions?.map((p: string, pIdx: number) => (
                            <span key={pIdx} className="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-400 text-[10px] font-mono border border-slate-200 dark:border-slate-700">
                              {p.replace('android.permission.', '')}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Bytecode API Correlation Summary */}
              {privacyAnalysis.api_correlations && privacyAnalysis.api_correlations.length > 0 && (
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs">
                  <div className="font-bold text-purple-700 dark:text-purple-300 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <span>🔗</span> Static Bytecode API Correlations Detected ({privacyAnalysis.api_correlations.length})
                  </div>
                  <p className="text-slate-600 dark:text-slate-400 text-[11px] mb-3">
                    ScamBuster identified actual Dalvik/DEX API references in the application bytecode corresponding to requested permissions:
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {privacyAnalysis.api_correlations.map((cor: any, idx: number) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-white dark:bg-slate-900 border border-purple-500/20 text-[11px]">
                        <div className="flex items-center justify-between text-purple-700 dark:text-purple-200 font-mono font-semibold">
                          <span>{cor.permission?.replace('android.permission.', '')}</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-700 dark:text-purple-300">
                            {cor.category || 'API'}
                          </span>
                        </div>
                        <div className="text-slate-500 dark:text-slate-400 text-[10px] mt-1 truncate font-mono">
                          API: {cor.correlated_apis?.[0] || cor.matched_apis?.[0] || cor.status || 'Reference verified'}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Permission Details Table */}
              <div className="space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <h3 className="text-xs uppercase font-bold text-slate-800 dark:text-slate-300 tracking-wider">
                    Permission Inventory & Sensitivity ({rawPermList.length})
                  </h3>
                  <div className="flex gap-1.5 text-[11px]">
                    <button
                      onClick={() => setPermFilter('all')}
                      className={`px-2.5 py-1 rounded-lg transition ${
                        permFilter === 'all'
                          ? 'bg-purple-600 text-white font-semibold'
                          : 'bg-slate-100 dark:bg-slate-950 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white border border-slate-200 dark:border-slate-800'
                      }`}
                    >
                      All ({rawPermList.length})
                    </button>
                    <button
                      onClick={() => setPermFilter('sensitive')}
                      className={`px-2.5 py-1 rounded-lg transition ${
                        permFilter === 'sensitive'
                          ? 'bg-purple-600 text-white font-semibold'
                          : 'bg-slate-100 dark:bg-slate-950 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white border border-slate-200 dark:border-slate-800'
                      }`}
                    >
                      Sensitive ({privacyAnalysis.sensitive_permissions_count})
                    </button>
                    <button
                      onClick={() => setPermFilter('correlated')}
                      className={`px-2.5 py-1 rounded-lg transition ${
                        permFilter === 'correlated'
                          ? 'bg-purple-600 text-white font-semibold'
                          : 'bg-slate-100 dark:bg-slate-950 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white border border-slate-200 dark:border-slate-800'
                      }`}
                    >
                      Correlated in DEX ({privacyAnalysis.api_correlations?.length || 0})
                    </button>
                  </div>
                </div>

                <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 shadow-sm">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/80 text-slate-600 dark:text-slate-400 text-[11px] uppercase tracking-wider">
                        <th className="py-2.5 px-3">Permission</th>
                        <th className="py-2.5 px-3">Category</th>
                        <th className="py-2.5 px-3">Sensitivity</th>
                        <th className="py-2.5 px-3">Bytecode Reference</th>
                        <th className="py-2.5 px-3 text-right">Details</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-800/60 font-mono text-[11px]">
                      {filteredPerms.map((perm: any, idx: number) => {
                        const isExpanded = expandedPerms[perm.permission];
                        return (
                          <React.Fragment key={idx}>
                            <tr className="hover:bg-slate-50 dark:hover:bg-slate-900/50 transition">
                              <td className="py-2.5 px-3 text-slate-900 dark:text-slate-200 font-semibold truncate max-w-xs">
                                {perm.permission.replace('android.permission.', '')}
                              </td>
                              <td className="py-2.5 px-3 text-slate-600 dark:text-slate-400 font-sans">
                                {perm.category}
                              </td>
                              <td className="py-2.5 px-3 font-sans">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSensitivityBadge(perm.sensitivity)}`}>
                                  {perm.sensitivity}
                                </span>
                              </td>
                              <td className="py-2.5 px-3 font-sans">
                                {perm.api_correlation_status === 'CORRELATED' ? (
                                  <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 text-[10px] font-semibold">
                                    ✓ Correlated
                                  </span>
                                ) : (
                                  <span className="text-slate-400 dark:text-slate-500 text-[10px]">
                                    Not detected
                                  </span>
                                )}
                              </td>
                              <td className="py-2.5 px-3 text-right font-sans">
                                <button
                                  onClick={() => toggleExpandPerm(perm.permission)}
                                  className="text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300 text-[11px] underline"
                                >
                                  {isExpanded ? 'Hide' : 'Why it matters'}
                                </button>
                              </td>
                            </tr>
                            {isExpanded && (
                              <tr className="bg-slate-50/80 dark:bg-slate-900/80">
                                <td colSpan={5} className="p-3 text-xs font-sans text-slate-700 dark:text-slate-300 space-y-1.5">
                                  <div className="text-[11px] text-purple-700 dark:text-purple-300 font-semibold">
                                    💡 Why this permission matters:
                                  </div>
                                  <p className="text-slate-700 dark:text-slate-300 leading-relaxed text-[11px]">
                                    {perm.why_it_matters || 'No specific privacy impact documented for this permission.'}
                                  </p>
                                  <div className="flex items-center gap-3 text-[10px] text-slate-500 dark:text-slate-400 pt-1 font-mono">
                                    <span>Full: {perm.permission}</span>
                                    <span>•</span>
                                    <span>Protection: {perm.protection_level || 'normal'}</span>
                                    <span>•</span>
                                    <span>Runtime: {perm.runtime_permission ? 'Yes (Prompt at runtime)' : 'No (Install-time)'}</span>
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Actionable User Guidance */}
              {privacyAnalysis.guidance && privacyAnalysis.guidance.length > 0 && (
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs space-y-2">
                  <div className="font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                    <span>📋</span> Actionable Privacy & Security Advice
                  </div>
                  <ul className="space-y-1 text-slate-700 dark:text-slate-300 text-[11px]">
                    {privacyAnalysis.guidance.map((item: string, idx: number) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-purple-500 mt-0.5">•</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* MANDATORY STATIC ANALYSIS LIMITATION DISCLAIMER */}
              <div className="p-4 rounded-xl bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 text-[11px] text-slate-600 dark:text-slate-400 space-y-1">
                <div className="font-semibold text-slate-800 dark:text-slate-300 flex items-center gap-1.5">
                  <span>ℹ️</span> Critical Technical Limitation Notice
                </div>
                <p className="leading-relaxed">
                  {privacyAnalysis.limitation_disclaimer ||
                    'Static APK analysis determines requested permissions and static bytecode references. It does not prove that the application executed sensitive code or accessed private data at runtime. Permission requested ≠ malicious activity.'}
                </p>
              </div>
            </div>
          )}

          {/* Contributing Reasons & Evidence */}
          {result.reasons && result.reasons.length > 0 && (
            <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
              <h4 className="text-xs uppercase font-bold text-slate-600 dark:text-slate-400 tracking-wider mb-3">
                Risk Engine Contributing Evidence & Signals
              </h4>
              <ul className="space-y-2">
                {result.reasons.map((reason, idx) => (
                  <li key={idx} className="text-xs text-slate-700 dark:text-slate-300 flex items-start gap-2">
                    <span className="text-brand-500 mt-0.5">•</span>
                    <span>{reason}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Heuristic Indicators */}
          {result.indicators.length > 0 && (
            <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
              <h4 className="text-xs uppercase font-bold text-slate-600 dark:text-slate-400 tracking-wider mb-3">
                Triggered Threat & Privacy Indicators ({result.indicators.length})
              </h4>
              <div className="space-y-2">
                {result.indicators.map((ind, idx) => (
                  <div key={idx} className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 flex items-start justify-between gap-3">
                    <div>
                      <div className="text-xs font-semibold text-slate-900 dark:text-slate-200">{ind.name}</div>
                      <div className="text-[11px] text-slate-600 dark:text-slate-400 mt-0.5">{ind.description}</div>
                      {ind.evidence && (
                        <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 mt-1">
                          Evidence: {ind.evidence}
                        </div>
                      )}
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${
                      (ind?.severity || '').toLowerCase() === 'critical' ? 'bg-rose-500/20 text-rose-700 dark:text-rose-400 border-rose-500/30' :
                      (ind?.severity || '').toLowerCase() === 'high' ? 'bg-amber-500/20 text-amber-700 dark:text-amber-400 border-amber-500/30' :
                      (ind?.severity || '').toLowerCase() === 'medium' ? 'bg-yellow-500/20 text-yellow-700 dark:text-yellow-400 border-yellow-500/30' :
                      'bg-slate-200 dark:bg-slate-500/20 text-slate-700 dark:text-slate-400 border-slate-300 dark:border-slate-500/30'
                    }`}>
                      {ind?.severity || 'INFO'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Technical Details Accordion */}
          {techDetails && (
            <details className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm group">
              <summary className="text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 cursor-pointer select-none">
                ▸ View Full Technical Details (Hashes, Components, ABIs)
              </summary>
              <div className="mt-4 p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2 text-xs font-mono text-slate-700 dark:text-slate-300">
                <div>SHA-256: <span className="text-slate-900 dark:text-slate-100">{techDetails.sha256}</span></div>
                <div>SHA-1: <span className="text-slate-900 dark:text-slate-100">{techDetails.sha1}</span></div>
                <div>Components: {compDetails?.activities || 0} Activities, {compDetails?.services || 0} Services, {compDetails?.receivers || 0} Receivers, {compDetails?.exported_count || 0} Exported</div>
                <div>Native Libraries: {techDetails.native_library_count || 0} (.so files) [ABIs: {techDetails.native_abis?.join(', ') || 'None'}]</div>
              </div>
            </details>
          )}
        </div>
      )}
    </div>
  );
};

export default ScanApk;
