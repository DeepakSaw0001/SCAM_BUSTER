import React from 'react';
import { Link } from 'react-router-dom';

export const Scan: React.FC = () => {
  const scanners = [
    { title: 'URL Scanner', path: '/scan/url', icon: '🔗', desc: 'Scan links for phishing and malicious host patterns.' },
    { title: 'Message / SMS Scanner', path: '/scan/message', icon: '💬', desc: 'Classify suspicious text messages using NLP.' },
    { title: 'Email Scanner', path: '/scan/email', icon: '📧', desc: 'Analyze email headers, sender reputation, and body.' },
    { title: 'Phone Number Scanner', path: '/scan/phone', icon: '📞', desc: 'Check phone numbers against known fraud patterns.' },
    { title: 'APK File Scanner', path: '/scan/apk', icon: '📦', desc: 'Inspect Android application packages for malicious permissions.' },
  ];

  return (
    <div className="max-w-4xl mx-auto py-10 px-4">
      <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2">Threat Scanner Hub</h1>
      <p className="text-slate-500 dark:text-slate-400 mb-8">Select a vector to analyze or verify threat indicators.</p>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {scanners.map((s) => (
          <Link
            key={s.path}
            to={s.path}
            className="p-6 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm hover:border-brand-500/50 dark:hover:border-brand-500/50 transition flex items-start gap-4 group"
          >
            <div className="text-3xl p-2 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">{s.icon}</div>
            <div>
              <h2 className="text-lg font-semibold text-slate-900 dark:text-white group-hover:text-brand-600 dark:group-hover:text-brand-400 transition">{s.title}</h2>
              <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">{s.desc}</p>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
};
