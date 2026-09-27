import React, { useState } from 'react';

interface ThreatReportItem {
  provider: string;
  verdict: string;
  confidence: number;
  status: string;
  categories: string[];
  checked_at: string;
  freshness: string;
  data_age_seconds?: number;
  reference_id?: string;
  details?: Record<string, any>;
  error_message?: string;
}

interface CorrelatedIndicator {
  indicator: {
    type: string;
    value: string;
    normalized_value: string;
    is_private_or_bogon?: boolean;
    sha256_fingerprint?: string;
  };
  aggregate_verdict: string;
  aggregate_confidence: number;
  is_corroborated: boolean;
  has_conflicts: boolean;
  is_conflicting?: boolean;
  conflicting?: boolean;
  categories: string[];
  reports_count: number;
  reports: ThreatReportItem[];
  provenance: Record<string, any>;
  summary_explanation: string;
}

interface ThreatGraphData {
  nodes: Array<{
    id: string;
    type: string;
    label: string;
    risk_level: string;
    details?: Record<string, any>;
  }>;
  edges: Array<{
    source: string;
    target: string;
    relation: string;
    relationship?: string;
  }>;
}

interface ThreatIntelligencePanelProps {
  threatIntelligence?: any;
  threatGraph?: ThreatGraphData | null;
}

export const ThreatIntelligencePanel: React.FC<ThreatIntelligencePanelProps> = ({
  threatIntelligence,
  threatGraph,
}) => {
  const [activeTab, setActiveTab] = useState<'indicators' | 'graph'>('indicators');
  const [expandedIndicator, setExpandedIndicator] = useState<string | null>(null);

  // Safely extract the raw indicators dictionary regardless of wrapping
  const rawIndicatorsMap: Record<string, any> = (() => {
    if (!threatIntelligence || typeof threatIntelligence !== 'object') return {};
    if (threatIntelligence.indicators && typeof threatIntelligence.indicators === 'object' && !Array.isArray(threatIntelligence.indicators)) {
      return threatIntelligence.indicators;
    }
    return threatIntelligence;
  })();

  // Filter out any metadata fields (like booleans, strings, counts) so we ONLY process actual indicator objects
  const indicatorsList: Array<[string, CorrelatedIndicator]> = Object.entries(rawIndicatorsMap)
    .filter(([, val]) => {
      if (!val || typeof val !== 'object') return false;
      return 'indicator' in val || 'aggregate_verdict' in val || 'reports' in val || 'reports_count' in val;
    }) as Array<[string, CorrelatedIndicator]>;

  const nodes = Array.isArray(threatGraph?.nodes) ? threatGraph.nodes : [];
  const edges = Array.isArray(threatGraph?.edges) ? threatGraph.edges : [];

  if (indicatorsList.length === 0 && nodes.length === 0 && edges.length === 0) {
    return (
      <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-3 shadow-sm transition-colors">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-lg">🛡️</span>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">
              Threat Intelligence & Reputation Correlation
            </h3>
          </div>
          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
            OFFLINE RESILIENT
          </span>
        </div>
        <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
          No external reputation flags found. ScamBuster evaluated this target using local lexical heuristics,
          domain DNS attributes, and behavioral ML scoring.
        </p>
        <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 text-[11px] text-slate-600 dark:text-slate-400 flex items-center gap-2 font-mono">
          <span className="text-blue-600 dark:text-blue-400 font-bold">ℹ POLICY:</span>
          <span>UNKNOWN ≠ SAFE. Target is evaluated independently via unified multi-layer risk analysis.</span>
        </div>
      </div>
    );
  }

  const totalReports = indicatorsList.reduce((acc, [, val]) => {
    const count = val?.reports_count ?? (Array.isArray(val?.reports) ? val.reports.length : 0);
    return acc + (typeof count === 'number' ? count : 0);
  }, 0);

  const anyMalicious = indicatorsList.some(([, val]) => {
    const verdict = String(val?.aggregate_verdict || '').toLowerCase();
    return verdict === 'malicious' || verdict === 'high' || verdict === 'critical';
  });

  const anyConflicts =
    Boolean(threatIntelligence?.conflicting || threatIntelligence?.is_conflicting) ||
    indicatorsList.some(([, val]) => Boolean(val?.has_conflicts || val?.is_conflicting));

  const getVerdictBadge = (verdict?: string) => {
    const v = String(verdict || 'unknown').toLowerCase();
    switch (v) {
      case 'malicious':
        return 'bg-rose-500/20 text-rose-600 dark:text-rose-300 border-rose-500/40';
      case 'suspicious':
        return 'bg-amber-500/20 text-amber-600 dark:text-amber-300 border-amber-500/40';
      case 'benign':
      case 'safe':
        return 'bg-emerald-500/20 text-emerald-600 dark:text-emerald-300 border-emerald-500/40';
      case 'unknown':
      default:
        return 'bg-blue-500/20 text-blue-600 dark:text-blue-300 border-blue-500/40';
    }
  };

  const getNodeColor = (riskLevel?: string) => {
    const r = String(riskLevel || 'unknown').toLowerCase();
    if (r === 'critical' || r === 'high') return 'border-rose-500/60 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-200';
    if (r === 'medium') return 'border-amber-500/60 bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-200';
    if (r === 'low' || r === 'very_low') return 'border-emerald-500/60 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-200';
    return 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300';
  };

  return (
    <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 space-y-6 shadow-sm transition-colors">
      {/* Header & Tabs */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-xl">🌐</span>
            <h2 className="text-lg font-bold text-slate-900 dark:text-white tracking-wide">
              Threat Intelligence & Reputation Correlation
            </h2>
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-purple-100 dark:bg-purple-950 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800">
              Phase 11
            </span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Normalized correlation across local verified feeds, threat catalogs, and reputation adapters.
          </p>
        </div>

        {/* View Switcher */}
        <div className="flex items-center gap-2 p-1 rounded-xl bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
          <button
            type="button"
            onClick={() => setActiveTab('indicators')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === 'indicators'
                ? 'bg-brand-500 text-slate-950 shadow font-bold'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            Indicators ({indicatorsList.length})
          </button>
          {threatGraph && (threatGraph.nodes || []).length > 0 && (
            <button
              type="button"
              onClick={() => setActiveTab('graph')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                activeTab === 'graph'
                  ? 'bg-brand-500 text-slate-950 shadow font-bold'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              Threat Graph ({(threatGraph.nodes || []).length} nodes)
            </button>
          )}
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
          <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">Analyzed Indicators</div>
          <div className="text-lg font-bold text-slate-900 dark:text-white mt-1">{indicatorsList.length}</div>
          <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5 font-mono">Deduplicated & Normalized</div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
          <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">Source Reports</div>
          <div className="text-lg font-bold text-slate-900 dark:text-white mt-1">{totalReports}</div>
          <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5 font-mono">Multi-Source Feeds</div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
          <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">Intelligence Status</div>
          <div className={`text-sm font-bold mt-1 uppercase ${anyMalicious ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
            {anyMalicious ? 'Flagged Malicious' : 'No Critical Flags'}
          </div>
          <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5 font-mono">
            {anyConflicts ? '⚠️ Conflicting Reports' : 'Consistent Verdicts'}
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
          <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">Privacy Model</div>
          <div className="text-sm font-bold mt-1 text-purple-600 dark:text-purple-400">Zero Content Leak</div>
          <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5 font-mono">SHA-256 Key Hashing</div>
        </div>
      </div>

      {/* Conflict Banner if Detected */}
      {anyConflicts && (
        <div className="p-4 rounded-xl bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800/80 space-y-2">
          <div className="flex items-center gap-2 text-amber-700 dark:text-amber-300 font-bold text-xs uppercase tracking-wider">
            <span>⚠️</span> Conflicting Intelligence Reports Detected
          </div>
          <p className="text-xs text-amber-800 dark:text-amber-200/90 leading-relaxed">
            Independent reputation sources yielded divergent assessments for one or more indicators.
            ScamBuster preserves both reports transparently and instructs the Risk Engine to prioritize
            conservative safety protections.
          </p>
        </div>
      )}

      {/* Indicators View */}
      {activeTab === 'indicators' && (
        <div className="space-y-4">
          {indicatorsList.map(([key, item], idx) => {
            const isExpanded = expandedIndicator === key || (expandedIndicator === null && idx === 0);
            const indicatorVal = item?.indicator?.normalized_value || item?.indicator?.value || key;
            const reports = Array.isArray(item?.reports) ? item.reports : [];
            const categories = Array.isArray(item?.categories) ? item.categories : [];
            const reportsCount = item?.reports_count ?? reports.length;
            const aggregateVerdict = item?.aggregate_verdict || 'UNKNOWN';
            const aggregateConfidence = item?.aggregate_confidence ?? 0;

            return (
              <div
                key={key}
                className="rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 overflow-hidden transition"
              >
                {/* Indicator Card Header */}
                <div
                  onClick={() => setExpandedIndicator(isExpanded ? '' : key)}
                  className="p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 cursor-pointer hover:bg-slate-100/60 dark:hover:bg-slate-800/30 transition"
                >
                  <div className="space-y-1 max-w-full overflow-hidden">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-700 font-mono">
                        {item?.indicator?.type || 'INDICATOR'}
                      </span>
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border uppercase ${getVerdictBadge(aggregateVerdict)}`}>
                        {aggregateVerdict}
                      </span>
                      {item?.is_corroborated && (
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800">
                          ✓ Corroborated ({reportsCount} sources)
                        </span>
                      )}
                      {item?.has_conflicts && (
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800">
                          ⚠️ Conflicting
                        </span>
                      )}
                    </div>
                    <div className="text-sm font-mono font-semibold text-slate-800 dark:text-slate-200 truncate mt-1" title={indicatorVal}>
                      {indicatorVal}
                    </div>
                  </div>

                  <div className="flex items-center gap-3 text-right">
                    <div className="text-right">
                      <div className="text-[10px] uppercase text-slate-400 dark:text-slate-500">Confidence</div>
                      <div className="text-xs font-bold text-slate-700 dark:text-slate-300">
                        {Math.round(aggregateConfidence * 100)}%
                      </div>
                    </div>
                    <span className="text-slate-400 dark:text-slate-500 text-sm">
                      {isExpanded ? '▲' : '▼'}
                    </span>
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="p-4 border-t border-slate-200 dark:border-slate-800/80 space-y-4 bg-white dark:bg-slate-900/50">
                    {/* Summary Explanation */}
                    {item?.summary_explanation && (
                      <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                        <span className="text-brand-600 dark:text-brand-400 font-bold mr-1">EXPLANATION:</span>
                        {item.summary_explanation}
                      </div>
                    )}

                    {/* Threat Categories */}
                    {categories.length > 0 && (
                      <div>
                        <div className="text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-400 font-semibold mb-1.5">
                          Threat Categories
                        </div>
                        <div className="flex items-center gap-1.5 flex-wrap">
                          {categories.map((cat, i) => (
                            <span
                              key={i}
                              className="px-2 py-0.5 rounded bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800 text-[11px] font-mono"
                            >
                              {cat}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Source Reports Provenance Table */}
                    <div>
                      <div className="text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-400 font-semibold mb-2">
                        Source Evidence Provenance ({reports.length} report{reports.length !== 1 ? 's' : ''})
                      </div>
                      <div className="space-y-2">
                        {reports.map((report, rIdx) => (
                          <div
                            key={rIdx}
                            className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/90 text-xs space-y-1.5"
                          >
                            <div className="flex items-center justify-between flex-wrap gap-2">
                              <span className="font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                                <span className="text-brand-600 dark:text-brand-400">●</span> {report?.provider || 'Unknown'}
                              </span>
                              <div className="flex items-center gap-2">
                                <span className={`px-2 py-0.2 rounded text-[10px] font-bold border uppercase ${getVerdictBadge(report?.verdict)}`}>
                                  {report?.verdict || 'UNKNOWN'}
                                </span>
                                <span className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">
                                  {Math.round((report?.confidence ?? 0) * 100)}% conf
                                </span>
                              </div>
                            </div>

                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                              <div>
                                <span className="text-slate-400 dark:text-slate-600 block text-[9px]">FRESHNESS</span>
                                <span className="text-slate-700 dark:text-slate-300">{report?.freshness || 'N/A'}</span>
                              </div>
                              <div>
                                <span className="text-slate-400 dark:text-slate-600 block text-[9px]">CHECKED AT</span>
                                <span className="text-slate-700 dark:text-slate-300 truncate block">{(report?.checked_at || '').slice(0, 19) || 'N/A'}</span>
                              </div>
                              <div>
                                <span className="text-slate-400 dark:text-slate-600 block text-[9px]">STATUS</span>
                                <span className="text-slate-700 dark:text-slate-300">{report?.status || 'COMPLETED'}</span>
                              </div>
                              <div>
                                <span className="text-slate-400 dark:text-slate-600 block text-[9px]">REF ID</span>
                                <span className="text-slate-700 dark:text-slate-300 truncate block">{report?.reference_id || 'LOCAL-CATALOG'}</span>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Threat Relationship Graph View */}
      {activeTab === 'graph' && threatGraph && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-slate-200 dark:border-slate-800">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300 flex items-center gap-2">
                <span>🕸️</span> Correlated Indicator Relationship Map
              </span>
              <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">
                {(threatGraph.nodes || []).length} Nodes • {(threatGraph.edges || []).length} Edges
              </span>
            </div>

            {/* Visual Node Cards Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              {(threatGraph.nodes || []).map((node) => (
                <div
                  key={node.id}
                  className={`p-3 rounded-xl border text-xs space-y-1.5 transition ${getNodeColor(node.risk_level)}`}
                >
                  <div className="flex items-center justify-between gap-1">
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-mono uppercase font-bold bg-white/80 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300">
                      {node.type || 'NODE'}
                    </span>
                    <span className="text-[10px] font-bold uppercase tracking-wide">
                      {node.risk_level || 'UNKNOWN'}
                    </span>
                  </div>
                  <div className="font-bold text-slate-900 dark:text-slate-100 font-mono truncate" title={node.label}>
                    {node.label || node.id}
                  </div>
                  <div className="text-[10px] text-slate-500 dark:text-slate-400 font-mono truncate">
                    ID: {node.id}
                  </div>
                </div>
              ))}
            </div>

            {/* Edge Relational Links */}
            {(threatGraph.edges || []).length > 0 && (
              <div className="space-y-2 pt-2 border-t border-slate-200 dark:border-slate-800">
                <div className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Correlation Edges
                </div>
                <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                  {(threatGraph.edges || []).map((edge, eIdx) => (
                    <div
                      key={eIdx}
                      className="p-2 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-[11px] font-mono flex items-center justify-between gap-2"
                    >
                      <span className="text-slate-700 dark:text-slate-300 truncate max-w-xs">{edge.source}</span>
                      <span className="px-2 py-0.5 rounded bg-brand-100 dark:bg-brand-950 text-brand-700 dark:text-brand-300 border border-brand-200 dark:border-brand-800 text-[10px] font-bold">
                        {edge.relation || edge.relationship || 'connects_to'}
                      </span>
                      <span className="text-slate-700 dark:text-slate-300 truncate max-w-xs">{edge.target}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Privacy & Provenance Disclosure Footer */}
      <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 text-[11px] text-slate-500 dark:text-slate-400 flex items-start gap-2.5">
        <span className="text-brand-600 dark:text-brand-400 text-sm mt-0.5">🔒</span>
        <div className="space-y-0.5">
          <span className="font-semibold text-slate-800 dark:text-slate-200">Zero Content Leakage Guarantee:</span>
          <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
            ScamBuster queries configured threat sources using normalized technical indicators only (domains, URLs, IP addresses, and file SHA-256 hashes).
            Passwords, authentication tokens, OTPs, and private message contents are NEVER sent to third-party services.
          </p>
        </div>
      </div>
    </div>
  );
};
