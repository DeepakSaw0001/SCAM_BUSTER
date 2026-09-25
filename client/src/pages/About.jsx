export default function About() {
  return (
    <div>
      <div className="page-header">
        <h1 className="page-header__title">About ScamBuster</h1>
        <p className="page-header__subtitle">
          AI-powered cybersecurity tool for detecting and explaining potential scams
        </p>
      </div>

      <div className="card" style={{ marginBottom: '24px' }}>
        <h2 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '12px' }}>What is ScamBuster?</h2>
        <p style={{ color: 'var(--color-text-secondary)', lineHeight: 1.7, marginBottom: '16px' }}>
          ScamBuster is a cybersecurity and AI/ML web application designed to help users identify
          potential scams, phishing attempts, malicious URLs, suspicious messages, and fraudulent
          phone numbers. It analyzes submitted content using heuristic rules and pattern matching
          to provide clear risk assessments with explainable results.
        </p>
        <p style={{ color: 'var(--color-text-secondary)', lineHeight: 1.7 }}>
          Unlike opaque security tools that simply say "blocked" or "safe," ScamBuster provides
          detailed reasons for its assessment, security indicators with severity levels, and
          actionable recommendations — making cybersecurity accessible and understandable.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px', marginBottom: '24px' }}>
        <div className="card">
          <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '12px' }}>🔧 Technology Stack</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '0.9rem', color: 'var(--color-text-secondary)' }}>
            <div><strong>Frontend:</strong> React, Vite, React Router</div>
            <div><strong>Backend:</strong> Node.js, Express</div>
            <div><strong>Database:</strong> MongoDB</div>
            <div><strong>Security:</strong> Helmet, CORS, Rate Limiting</div>
            <div><strong>AI/ML Engine:</strong> Heuristic v1 (rule-based)</div>
          </div>
        </div>

        <div className="card">
          <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '12px' }}>🎯 Detection Capabilities</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '0.9rem', color: 'var(--color-text-secondary)' }}>
            <div>• URL structure & phishing pattern analysis</div>
            <div>• Social engineering language detection</div>
            <div>• Email header anomaly detection</div>
            <div>• Phone number risk assessment</div>
            <div>• Brand impersonation detection</div>
            <div>• Credential harvesting identification</div>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: '24px' }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '12px' }}>🚀 Planned Enhancements</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '12px', fontSize: '0.9rem', color: 'var(--color-text-secondary)' }}>
          <div>• ML-based text classification model</div>
          <div>• VirusTotal API integration</div>
          <div>• Google Safe Browsing integration</div>
          <div>• WHOIS domain analysis</div>
          <div>• APK/file scanning support</div>
          <div>• User authentication & accounts</div>
          <div>• Real-time threat intelligence feeds</div>
          <div>• Browser extension</div>
        </div>
      </div>

      <div className="card">
        <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '8px' }}>📝 Project Information</h3>
        <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.9rem' }}>
          ScamBuster is a final-year engineering project combining Cybersecurity and AI/ML
          concepts to create a practical, demonstrable tool for scam detection and analysis.
        </p>
      </div>
    </div>
  );
}
