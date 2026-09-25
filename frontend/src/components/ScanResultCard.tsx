import React from 'react';
import { ScanResult } from '../services/api';

interface ScanResultCardProps {
  result: ScanResult;
}

export const ScanResultCard: React.FC<ScanResultCardProps> = ({ result }) => {
  const getBadgeStyle = (level: string) => {
    switch (level) {
      case 'DANGEROUS':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'SUSPICIOUS':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'SAFE':
      default:
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 70) return 'text-rose-400';
    if (score >= 35) return 'text-amber-400';
    return 'text-emerald-400';
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-950 text-rose-300 border-rose-700';
      case 'HIGH':
        return 'bg-orange-950 text-orange-300 border-orange-700';
      case 'MEDIUM':
        return 'bg-amber-950 text-amber-300 border-amber-700';
      case 'LOW':
        return 'bg-blue-950 text-blue-300 border-blue-700';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="mt-8 rounded-2xl bg-dark-900 border border-slate-800 p-6 shadow-2xl space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <span
              className={`px-3 py-1 rounded-full text-xs font-bold border uppercase tracking-wider ${getBadgeStyle(
                result.risk_level
              )}`}
            >
              {result.risk_level} THREAT LEVEL
            </span>
            <span className="text-xs text-slate-500 font-mono">ID: {result.id.slice(0, 8)}...</span>
          </div>
          <h2 className="text-xl font-bold text-white mt-2">Analysis Findings</h2>
          <p className="text-xs text-slate-400 font-mono break-all mt-1">Target: {result.target}</p>
        </div>

        {/* Score Ring */}
        <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-dark-950 border border-slate-800">
          <div className="text-right">
            <div className="text-xs uppercase font-semibold text-slate-400">Risk Score</div>
            <div className={`text-3xl font-extrabold ${getScoreColor(result.composite_risk_score)}`}>
              {result.composite_risk_score}
              <span className="text-sm font-normal text-slate-500">/100</span>
            </div>
          </div>
        </div>
      </div>

      {/* Executive Summary */}
      <div className="p-4 rounded-xl bg-dark-950 border border-slate-800">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
          Executive Summary
        </h3>
        <p className="text-sm text-slate-200 leading-relaxed">{result.summary}</p>
      </div>

      {/* ML & Heuristic Dual Assessment */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Cybersecurity Heuristic Score */}
        <div className="p-4 rounded-xl bg-dark-950 border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400 font-medium">Cyber Heuristic Engine</div>
          <div className="text-2xl font-bold text-white">
            {result.heuristic_score} <span className="text-xs font-normal text-slate-500">score</span>
          </div>
          <div className="text-xs text-slate-400">
            {result.indicators.length} threat indicator{result.indicators.length !== 1 ? 's' : ''} detected
          </div>
        </div>

        {/* Machine Learning Classifier */}
        <div className="p-4 rounded-xl bg-dark-950 border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400 font-medium">Machine Learning Inference</div>
          {result.ml_metadata ? (
            <>
              <div className="text-2xl font-bold text-brand-400 capitalize">
                {result.ml_metadata.prediction || 'Evaluated'}
                {result.ml_metadata.probability && (
                  <span className="text-xs font-normal text-slate-400 ml-2">
                    ({Math.round((result.ml_metadata.target_probability ?? result.ml_metadata.probability) * 100)}% confidence)
                  </span>
                )}
              </div>
              <div className="text-xs text-slate-400 font-mono">
                {result.ml_metadata.model_name} (v{result.ml_metadata.model_version})
              </div>
            </>
          ) : (
            <>
              <div className="text-lg font-bold text-slate-300">Deterministic Signature Engine</div>
              <div className="text-xs text-slate-500">MITRE ATT&CK & Telecom Fraud Matrix</div>
            </>
          )}
        </div>
      </div>

      {/* Threat Indicators */}
      <div>
        <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
          <span>Threat Indicators</span>
          <span className="px-2 py-0.5 rounded-full text-xs bg-slate-800 text-slate-300">
            {result.indicators.length}
          </span>
        </h3>

        {result.indicators.length === 0 ? (
          <div className="p-4 rounded-xl bg-dark-950 border border-slate-800 text-sm text-slate-400">
            No malicious signatures or anomalies were triggered for this scan.
          </div>
        ) : (
          <div className="space-y-3">
            {result.indicators.map((ind, idx) => (
              <div
                key={idx}
                className="p-4 rounded-xl bg-dark-950 border border-slate-800/80 space-y-2 hover:border-slate-700 transition"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-sm text-slate-200">{ind.name}</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-bold border ${getSeverityBadge(
                      ind.severity
                    )}`}
                  >
                    {ind.severity}
                  </span>
                </div>
                <p className="text-xs text-slate-400">{ind.description}</p>
                {ind.evidence && (
                  <div className="p-2 rounded bg-dark-900 border border-slate-800 text-xs font-mono text-slate-300">
                    <span className="text-slate-500 mr-2">Evidence:</span>
                    {ind.evidence}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Actionable Recommendations */}
      <div>
        <h3 className="text-sm font-semibold text-white mb-3">Actionable Defense Recommendations</h3>
        <ul className="space-y-2">
          {result.recommendations.map((rec, idx) => (
            <li
              key={idx}
              className="flex items-start gap-2.5 text-xs text-slate-300 p-3 rounded-lg bg-dark-950 border border-slate-800/80"
            >
              <span className="text-brand-400 font-bold">✓</span>
              <span>{rec}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};
