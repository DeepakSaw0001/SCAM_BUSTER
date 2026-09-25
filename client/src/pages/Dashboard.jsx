import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';

export default function Dashboard() {
  const [backendStatus, setBackendStatus] = useState(null);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await api.healthCheck();
        setBackendStatus(res.data);
      } catch {
        setBackendStatus(null);
      } finally {
        setChecking(false);
      }
    };
    checkHealth();
  }, []);

  return (
    <div>
      <div className="page-header">
        <h1 className="page-header__title">Dashboard</h1>
        <p className="page-header__subtitle">
          Welcome to ScamBuster — your AI-powered scam detection assistant
        </p>
      </div>

      {/* Quick Stats */}
      <div className="stats-grid">
        <div className="card stat-card">
          <div className="stat-card__label">System Status</div>
          <div className="stat-card__value" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {checking ? (
              <div className="spinner" />
            ) : (
              <>
                <span className={`status-dot ${backendStatus ? 'status-dot--online' : 'status-dot--offline'}`} />
                <span style={{ fontSize: '1rem' }}>{backendStatus ? 'Online' : 'Offline'}</span>
              </>
            )}
          </div>
          {backendStatus && (
            <div className="stat-card__sub">v{backendStatus.version}</div>
          )}
        </div>

        <div className="card stat-card">
          <div className="stat-card__label">Analysis Types</div>
          <div className="stat-card__value">4</div>
          <div className="stat-card__sub">URL, Email, Message, Phone</div>
        </div>

        <div className="card stat-card">
          <div className="stat-card__label">Engine</div>
          <div className="stat-card__value" style={{ fontSize: '1rem' }}>Heuristic v1</div>
          <div className="stat-card__sub">Rule-based detection</div>
        </div>

        <div className="card stat-card">
          <div className="stat-card__label">Detection Rules</div>
          <div className="stat-card__value">30+</div>
          <div className="stat-card__sub">Across all analyzers</div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="card" style={{ marginBottom: '24px' }}>
        <h2 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '16px' }}>Quick Actions</h2>
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          <Link to="/analyze" className="btn btn--primary btn--lg">
            🔍 Start Analysis
          </Link>
          <Link to="/history" className="btn btn--secondary btn--lg">
            📋 View History
          </Link>
          <Link to="/about" className="btn btn--secondary btn--lg">
            ℹ️ Learn More
          </Link>
        </div>
      </div>

      {/* What can ScamBuster detect */}
      <div className="card">
        <h2 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '16px' }}>What ScamBuster Detects</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
          {[
            { icon: '🔗', title: 'Suspicious URLs', desc: 'Phishing links, malicious domains, URL obfuscation' },
            { icon: '📧', title: 'Scam Emails', desc: 'Phishing emails, sender spoofing, social engineering' },
            { icon: '💬', title: 'Scam Messages', desc: 'SMS fraud, urgency tactics, financial lures' },
            { icon: '📱', title: 'Fraudulent Numbers', desc: 'Premium-rate numbers, known scam prefixes' },
          ].map((item, i) => (
            <div
              key={i}
              style={{
                padding: '16px',
                borderRadius: 'var(--radius-md)',
                background: 'var(--color-bg-tertiary)',
                transition: 'transform var(--transition-fast)',
              }}
            >
              <div style={{ fontSize: '1.5rem', marginBottom: '8px' }}>{item.icon}</div>
              <div style={{ fontWeight: 600, marginBottom: '4px' }}>{item.title}</div>
              <div style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)' }}>{item.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
