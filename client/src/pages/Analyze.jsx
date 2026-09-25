import { useState } from 'react';
import { api } from '../services/api';
import AnalysisResult from '../components/AnalysisResult';

const INPUT_TYPES = [
  { key: 'url', label: '🔗 URL', placeholder: 'Enter a suspicious URL (e.g., http://secure-bank-login.xyz/verify)' },
  { key: 'email', label: '📧 Email', placeholder: 'Paste the suspicious email content here...' },
  { key: 'message', label: '💬 Message', placeholder: 'Paste the suspicious message or SMS text...' },
  { key: 'phone', label: '📱 Phone', placeholder: 'Enter the phone number (e.g., +1-900-555-0123)' },
];

export default function Analyze() {
  const [inputType, setInputType] = useState('url');
  const [inputValue, setInputValue] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const currentType = INPUT_TYPES.find((t) => t.key === inputType);
  const isLongInput = inputType === 'email' || inputType === 'message';

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!inputValue.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await api.submitAnalysis(inputType, inputValue.trim());
      setResult(res.data.result);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setInputValue('');
    setResult(null);
    setError(null);
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-header__title">Analyze</h1>
        <p className="page-header__subtitle">
          Submit suspicious content for scam detection analysis
        </p>
      </div>

      <div className="card" style={{ marginBottom: '24px' }}>
        <form className="analysis-form" onSubmit={handleSubmit}>
          {/* Input type selector */}
          <div className="form-group">
            <label className="form-label">Analysis Type</label>
            <div className="analysis-form__type-selector">
              {INPUT_TYPES.map((type) => (
                <button
                  key={type.key}
                  type="button"
                  className={`type-btn ${inputType === type.key ? 'type-btn--active' : ''}`}
                  onClick={() => { setInputType(type.key); setResult(null); setError(null); }}
                >
                  {type.label}
                </button>
              ))}
            </div>
          </div>

          {/* Input field */}
          <div className="form-group">
            <label className="form-label" htmlFor="analysis-input">
              {currentType.label.split(' ').slice(1).join(' ')} to Analyze
            </label>
            {isLongInput ? (
              <textarea
                id="analysis-input"
                className="input textarea"
                placeholder={currentType.placeholder}
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                rows={6}
                maxLength={10000}
              />
            ) : (
              <input
                id="analysis-input"
                className="input"
                type="text"
                placeholder={currentType.placeholder}
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                maxLength={2000}
              />
            )}
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '6px' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--color-text-tertiary)' }}>
                {inputValue.length} / {isLongInput ? '10,000' : '2,000'} characters
              </span>
            </div>
          </div>

          {/* Action buttons */}
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              type="submit"
              className="btn btn--primary btn--lg"
              disabled={loading || !inputValue.trim()}
            >
              {loading ? (
                <>
                  <div className="spinner" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} />
                  Analyzing...
                </>
              ) : (
                '🛡️ Analyze'
              )}
            </button>
            {(inputValue || result) && (
              <button type="button" className="btn btn--secondary btn--lg" onClick={handleClear}>
                Clear
              </button>
            )}
          </div>
        </form>
      </div>

      {/* Error */}
      {error && (
        <div className="card" style={{
          borderColor: 'var(--color-risk-critical)',
          background: 'var(--color-risk-critical-bg)',
          marginBottom: '24px',
        }}>
          <p style={{ color: 'var(--color-risk-critical)', fontWeight: 600 }}>⚠ Analysis Error</p>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.9rem', marginTop: '4px' }}>{error}</p>
        </div>
      )}

      {/* Result */}
      {result && <AnalysisResult result={result} inputType={inputType} />}
    </div>
  );
}
