export default function RiskBadge({ level }) {
  const classMap = {
    CRITICAL: 'risk-badge--critical',
    HIGH: 'risk-badge--high',
    MEDIUM: 'risk-badge--medium',
    LOW: 'risk-badge--low',
    SAFE: 'risk-badge--safe',
  };

  return (
    <span className={`risk-badge ${classMap[level] || ''}`}>
      {level}
    </span>
  );
}

export function RiskScore({ score, level }) {
  const classMap = {
    CRITICAL: 'risk-score--critical',
    HIGH: 'risk-score--high',
    MEDIUM: 'risk-score--medium',
    LOW: 'risk-score--low',
    SAFE: 'risk-score--safe',
  };

  return (
    <div className={`risk-score ${classMap[level] || ''}`}>
      {score}
    </div>
  );
}
