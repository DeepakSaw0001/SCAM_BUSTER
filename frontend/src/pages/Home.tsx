import React from 'react';
import { Link } from 'react-router-dom';

export const Home: React.FC = () => {
  return (
    <div className="max-w-4xl mx-auto py-12 px-4 sm:px-6">
      <div className="text-center space-y-4">
        <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight text-slate-900 dark:text-white">
          AI-Assisted Cybersecurity <span className="text-brand-600 dark:text-brand-500">Scam Detection</span>
        </h1>
        <p className="text-lg text-slate-600 dark:text-slate-400 max-w-2xl mx-auto">
          ScamBuster combines heuristic cybersecurity analysis with real machine learning classifiers to detect modern digital threats.
        </p>

        <div className="pt-6 flex flex-wrap justify-center gap-4">
          <Link
            to="/scan"
            className="px-6 py-3 rounded-lg bg-brand-600 hover:bg-brand-500 text-white font-bold transition shadow-lg shadow-brand-600/20"
          >
            Analyze Threats
          </Link>
          <Link
            to="/dashboard"
            className="px-6 py-3 rounded-lg bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-800 dark:text-white font-semibold transition border border-slate-300 dark:border-slate-700 shadow-sm"
          >
            View Dashboard
          </Link>
        </div>
      </div>

      <div className="mt-16 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {[
          { title: 'Phishing URLs', path: '/scan/url', icon: '🔗', desc: 'Structural analysis & ML Random Forest classifier.' },
          { title: 'SMS & Text Scams', path: '/scan/message', icon: '💬', desc: 'TF-IDF NLP vectorization & Logistic Regression.' },
          { title: 'Phishing Emails', path: '/scan/email', icon: '📧', desc: 'Header verification, SPF/DKIM & content analysis.' },
          { title: 'Phone Numbers', path: '/scan/phone', icon: '📞', desc: 'Carrier lookup, high-risk prefix & reputation check.' },
          { title: 'Malicious APKs', path: '/scan/apk', icon: '📦', desc: 'Permission auditing & suspicious capability analysis.' },
          { title: 'Risk Fusion', path: '/dashboard', icon: '⚡', desc: 'Correlated multi-vector explainable threat score.' },
        ].map((item) => (
          <Link
            key={item.path}
            to={item.path}
            className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm hover:border-brand-500/50 dark:hover:border-brand-500/50 transition group"
          >
            <div className="text-2xl mb-2">{item.icon}</div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-white group-hover:text-brand-600 dark:group-hover:text-brand-400 transition">
              {item.title}
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{item.desc}</p>
          </Link>
        ))}
      </div>
    </div>
  );
};
