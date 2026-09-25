import { useState, useEffect } from 'react';
import { api } from '../services/api';
import RiskBadge from '../components/RiskBadge';

export default function History() {
  const [analyses, setAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const res = await api.getHistory();
        setAnalyses(res.data.analyses);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    fetchHistory();
  }, []);

  const typeIcons = { url: '🔗', email: '📧', message: '💬', phone: '📱' };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-header__title">Analysis History</h1>
        <p className="page-header__subtitle">Review past scam analysis results</p>
      </div>

      {loading && (
        <div className="loading-container">
          <div className="spinner spinner--lg" />
          <span>Loading history...</span>
        </div>
      )}

      {error && (
        <div className="card" style={{ textAlign: 'center', padding: '40px' }}>
          <p style={{ fontSize: '1.5rem', marginBottom: '8px' }}>📡</p>
          <p style={{ fontWeight: 600, marginBottom: '4px' }}>Cannot Load History</p>
          <p style={{ fontSize: '0.9rem', color: 'var(--color-text-secondary)' }}>{error}</p>
          <p style={{ fontSize: '0.8rem', color: 'var(--color-text-tertiary)', marginTop: '8px' }}>
            History requires MongoDB to be running. Analyses are still functional without it.
          </p>
        </div>
      )}

      {!loading && !error && analyses.length === 0 && (
        <div className="card" style={{ textAlign: 'center', padding: '60px 20px' }}>
          <p style={{ fontSize: '2rem', marginBottom: '12px' }}>🔍</p>
          <p style={{ fontWeight: 600, fontSize: '1.1rem', marginBottom: '4px' }}>No Analyses Yet</p>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.9rem' }}>
            Submit your first analysis to see results here.
          </p>
        </div>
      )}

      {!loading && analyses.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {analyses.map((analysis) => (
            <div key={analysis._id} className="card card--interactive" style={{ padding: '16px 20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, minWidth: 0 }}>
                  <span style={{ fontSize: '1.3rem' }}>{typeIcons[analysis.inputType] || '❓'}</span>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontWeight: 600, fontSize: '0.9rem', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '400px' }}>
                      {analysis.inputValue}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--color-text-tertiary)' }}>
                      {analysis.inputType.toUpperCase()} • {new Date(analysis.createdAt).toLocaleString()}
                    </div>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span style={{ fontWeight: 700, fontSize: '0.9rem' }}>{analysis.result?.riskScore}/100</span>
                  <RiskBadge level={analysis.result?.riskLevel} />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
