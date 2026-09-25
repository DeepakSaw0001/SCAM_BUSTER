import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { scanEmail, ScanResult } from '../services/api';
import { ScanResultCard } from '../components/ScanResultCard';

const DEMO_EMAILS = [
  {
    label: 'Brand Spoof + Executable Attachment',
    sender: 'PayPal Security Support <service@freemail-secure.xyz>',
    subject: 'URGENT: Your account access has been restricted - Review Attached Statement',
    body: 'Dear customer,\n\nWe detected unauthorized login attempts from an unknown device. Please review the attached security invoice and confirm your account information immediately to lift restrictions.\n\nThank you,\nPayPal Customer Protection Team',
    replyTo: 'harvester@evil-server.top',
    attachments: 'Security_Update_Invoice.pdf.exe',
  },
  {
    label: 'Invoice Wire Transfer Scam (BEC)',
    sender: 'CEO Office <ceo-updates@corporate-exec.com>',
    subject: 'Overdue Vendor Settlement - Immediate Wire Payment Required',
    body: 'Please process the pending remittance wire transfer of $45,800 to our new supplier account today before close of business. Do not call, I am in meetings all day.',
    replyTo: 'finance-wire@exec-redirect.com',
    attachments: 'Wire_Instructions.docm',
  },
  {
    label: 'Benign Company Newsletter',
    sender: 'Engineering Digest <digest@techupdates.io>',
    subject: 'Weekly Tech Digest #142: Architecture & Best Practices',
    body: 'Hello Engineers! In this issue, we explore distributed systems reliability and modern cybersecurity frameworks. Enjoy the read!',
    replyTo: 'digest@techupdates.io',
    attachments: '',
  },
];

export const ScanEmail: React.FC = () => {
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [replyTo, setReplyTo] = useState('');
  const [attachmentsText, setAttachmentsText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!sender.trim() || !body.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const attachments = attachmentsText
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);

      const res = await scanEmail({
        sender: sender.trim(),
        subject: subject.trim(),
        body: body.trim(),
        reply_to: replyTo.trim() || undefined,
        attachments: attachments.length > 0 ? attachments : undefined,
      });
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze email');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-10 px-4">
      <div className="flex items-center gap-2 text-sm text-slate-400 mb-4">
        <Link to="/scan" className="hover:text-slate-200">Scanner</Link>
        <span>/</span>
        <span className="text-brand-400">Email Analysis</span>
      </div>
      <h1 className="text-3xl font-extrabold text-white mb-2">Phishing Email & BEC Scanner</h1>
      <p className="text-slate-400 mb-6">
        Evaluates sender address discrepancies, display name spoofing, dangerous attachment payloads, and Business Email Compromise (BEC) wire fraud language.
      </p>

      {/* Form */}
      <form onSubmit={handleScan} className="p-6 rounded-2xl bg-dark-900 border border-slate-800 shadow-xl space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Sender (From header) *
            </label>
            <input
              type="text"
              value={sender}
              onChange={(e) => setSender(e.target.value)}
              placeholder="e.g. Bank Support <alerts@bank-alerts.xyz>"
              className="w-full px-4 py-2.5 rounded-xl bg-dark-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm font-mono"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Reply-To Header (Optional)
            </label>
            <input
              type="text"
              value={replyTo}
              onChange={(e) => setReplyTo(e.target.value)}
              placeholder="e.g. reply@external-inbox.com"
              className="w-full px-4 py-2.5 rounded-xl bg-dark-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm font-mono"
            />
          </div>
        </div>

        <div>
          <label className="block text-xs font-semibold text-slate-300 mb-1">
            Subject Line
          </label>
          <input
            type="text"
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            placeholder="e.g. Action Required: Your payment is overdue"
            className="w-full px-4 py-2.5 rounded-xl bg-dark-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm"
          />
        </div>

        <div>
          <label className="block text-xs font-semibold text-slate-300 mb-1">
            Email Body Content *
          </label>
          <textarea
            rows={5}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder="Paste raw email body content..."
            className="w-full px-4 py-3 rounded-xl bg-dark-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm leading-relaxed"
            required
          />
        </div>

        <div>
          <label className="block text-xs font-semibold text-slate-300 mb-1">
            Attachment Filenames (comma separated)
          </label>
          <input
            type="text"
            value={attachmentsText}
            onChange={(e) => setAttachmentsText(e.target.value)}
            placeholder="e.g. invoice_march.pdf.exe, wire_receipt.xlsm"
            className="w-full px-4 py-2.5 rounded-xl bg-dark-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 text-sm font-mono"
          />
        </div>

        <button
          type="submit"
          disabled={loading || !sender.trim() || !body.trim()}
          className="w-full sm:w-auto px-6 py-3 rounded-xl bg-brand-500 hover:bg-brand-400 text-dark-950 font-bold text-sm transition shadow-lg shadow-brand-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
        >
          {loading ? (
            <>
              <svg className="animate-spin h-4 w-4 text-dark-950" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
              </svg>
              <span>Analyzing Email...</span>
            </>
          ) : (
            <span>Scan Email</span>
          )}
        </button>

        {/* Demo Chips */}
        <div className="pt-2">
          <div className="text-xs text-slate-400 mb-2">Quick Test Presets:</div>
          <div className="flex flex-wrap gap-2">
            {DEMO_EMAILS.map((demo, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setSender(demo.sender);
                  setSubject(demo.subject);
                  setBody(demo.body);
                  setReplyTo(demo.replyTo);
                  setAttachmentsText(demo.attachments);
                }}
                className="px-3 py-1.5 rounded-lg bg-dark-950 border border-slate-800 hover:border-brand-500/50 text-xs text-slate-300 hover:text-white transition"
              >
                {demo.label}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800 text-rose-300 text-xs font-mono">
            ⚠️ {error}
          </div>
        )}
      </form>

      {/* Result Display */}
      {result && <ScanResultCard result={result} />}
    </div>
  );
};
