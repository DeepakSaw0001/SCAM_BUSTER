import RiskBadge, { RiskScore } from './RiskBadge';

export default function AnalysisResult({ result, inputType }) {
  if (!result) return null;

  return (
    <div className="result card" style={{ animationDelay: '0.1s' }}>
      <div className="result__header">
        <RiskScore score={result.riskScore} level={result.riskLevel} />
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
            <h2 style={{ fontSize: '1.15rem', fontWeight: 700 }}>Analysis Result</h2>
            <RiskBadge level={result.riskLevel} />
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)' }}>
            {inputType.toUpperCase()} analysis • Risk score: {result.riskScore}/100
            {result.metadata && ` • ${result.metadata.analysisTimeMs}ms`}
          </p>
        </div>
      </div>

      {/* Detection Reasons */}
      {result.reasons && result.reasons.length > 0 && (
        <div className="result__reasons">
          <h3 className="result__section-title">Detection Reasons</h3>
          <div className="result__list">
            {result.reasons.map((reason, i) => (
              <div key={i} className="result__list-item">
                <span className="result__list-icon" style={{ color: 'var(--color-risk-high)' }}>⚠</span>
                <span>{reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Security Indicators */}
      {result.indicators && result.indicators.length > 0 && (
        <div style={{ marginBottom: '20px' }}>
          <h3 className="result__section-title">Security Indicators</h3>
          {result.indicators.map((ind, i) => (
            <div key={i} className={`indicator indicator--${ind.severity}`}>
              <div className="indicator__name">{ind.name}</div>
              <div className="indicator__desc">{ind.description}</div>
            </div>
          ))}
        </div>
      )}

      {/* Recommendations */}
      {result.recommendations && result.recommendations.length > 0 && (
        <div className="result__recommendations">
          <h3 className="result__section-title">Recommendations</h3>
          <div className="result__list">
            {result.recommendations.map((rec, i) => (
              <div key={i} className="result__list-item">
                <span className="result__list-icon" style={{ color: 'var(--color-brand)' }}>→</span>
                <span>{rec}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
