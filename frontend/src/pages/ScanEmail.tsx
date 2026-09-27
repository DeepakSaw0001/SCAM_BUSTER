import React, { useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { scanEmail, uploadEmail, ScanResult, ThreatIndicator } from '../services/api';
import { ThreatIntelligencePanel } from '../components/ThreatIntelligencePanel';
import { MLArchitectureAttribution } from '../components/MLArchitectureAttribution';

type InputMode = 'raw' | 'structured' | 'upload';
type ScannerState = 'idle' | 'loading' | 'success' | 'error';

const DEMO_PRESETS = [
  {
    label: 'Deceptive Anchor Link Phishing',
    raw_email: `From: "Chase Security Alert" <alerts@chase-notification-center.com>
Reply-To: security-verify@external-divert.xyz
Authentication-Results: mx.google.com; spf=fail; dkim=fail
Subject: URGENT: Unauthorized transaction detected - Verify your identity immediately
Content-Type: text/html

<html>
  <body>
    <p>Dear Customer,</p>
    <p>An unauthorized login was detected from a foreign IP address. Your account has been temporarily restricted.</p>
    <p>To avoid permanent suspension within 24 hours, click below to verify your login credentials:</p>
    <p><a href="http://chase-security-verify.ru/login">https://www.chase.com/verify-identity</a></p>
    <p>Chase Bank Customer Protection</p>
  </body>
</html>`,
  },
  {
    label: 'Double Extension Attachment (.pdf.exe)',
    raw_email: `From: "Vendor Billing Dept" <invoices@accounting-vendor.net>
Reply-To: phisher@harvest-network.org
Subject: Outstanding Invoice Settlement #INV-92842
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY_INV"

--BOUNDARY_INV
Content-Type: text/plain; charset=UTF-8

Dear Accounting,

Please find the revised payment invoice attached. Kindly wire funds immediately before end of business today.

Regards,
Billing Dept

--BOUNDARY_INV
Content-Type: application/octet-stream; name="Invoice_92842.pdf.exe"
Content-Disposition: attachment; filename="Invoice_92842.pdf.exe"

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAa...
--BOUNDARY_INV--`,
  },
  {
    label: 'CEO Wire Transfer Fraud (BEC)',
    raw_email: `From: "CEO Office" <ceo-updates@corporate-exec.com>
Reply-To: finance-wire-transfer@external-redirect.com
Subject: Urgent: Overdue Vendor Wire Payment
Content-Type: text/plain

Hi team,

I need an urgent wire transfer of $58,400 processed for our offshore cloud infrastructure supplier before 3:00 PM today.
Please confirm when the funds have been dispatched. I am in back-to-back board meetings all afternoon, so do not call.

Thanks,
Chief Executive Officer`,
  },
  {
    label: 'Legitimate Engineering Newsletter',
    raw_email: `From: "DevOps Weekly" <newsletter@devops-weekly.io>
Reply-To: newsletter@devops-weekly.io
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass
Subject: DevOps Weekly #312: Infrastructure as Code & Container Security
Content-Type: text/plain

Hello Engineers!

In this edition, we explore automated container hardening, zero-trust network configurations, and distributed telemetry best practices.

Read the full community report on our blog: https://devops-weekly.io/blog/hardening

Happy engineering!`,
  },
];

export const ScanEmail: React.FC = () => {
  const [inputMode, setInputMode] = useState<InputMode>('raw');
  const [rawEmail, setRawEmail] = useState('');

  // Structured fields
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [replyTo, setReplyTo] = useState('');
  const [attachmentsText, setAttachmentsText] = useState('');

  // Upload file
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [scannerState, setScannerState] = useState<ScannerState>('idle');
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();

    setScannerState('loading');
    setError(null);

    try {
      let res: ScanResult;

      if (inputMode === 'upload') {
        if (!selectedFile) {
          throw new Error('Please select an .eml file to upload.');
        }
        res = await uploadEmail(selectedFile);
      } else if (inputMode === 'raw') {
        if (!rawEmail.trim()) {
          throw new Error('Please paste raw email content or headers.');
        }
        res = await scanEmail({ raw_email: rawEmail.trim() });
      } else {
        if (!sender.trim() || !body.trim()) {
          throw new Error('Sender and email body are required.');
        }
        const attachments = attachmentsText
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);

        res = await scanEmail({
          sender: sender.trim(),
          subject: subject.trim(),
          body: body.trim(),
          reply_to: replyTo.trim() || undefined,
          attachments: attachments.length > 0 ? attachments : undefined,
        });
      }

      setResult(res);
      setScannerState('success');
    } catch (err: any) {
      setError(err.message || 'Failed to analyze email');
      setScannerState('error');
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (file.size > 5 * 1024 * 1024) {
        setError('Selected file exceeds maximum 5MB size limit.');
        return;
      }
      setSelectedFile(file);
      setError(null);
    }
  };

  const getRiskColor = (level?: string) => {
    switch (level?.toLowerCase()) {
      case 'critical':
        return 'text-rose-400';
      case 'high':
        return 'text-orange-400';
      case 'medium':
        return 'text-amber-400';
      case 'low':
        return 'text-blue-400';
      case 'very_low':
        return 'text-emerald-400';
      default:
        return 'text-slate-400';
    }
  };

  const getRiskBg = (level?: string) => {
    switch (level?.toLowerCase()) {
      case 'critical':
        return 'bg-rose-500/10 border-rose-500/30';
      case 'high':
        return 'bg-orange-500/10 border-orange-500/30';
      case 'medium':
        return 'bg-amber-500/10 border-amber-500/30';
      case 'low':
        return 'bg-blue-500/10 border-blue-500/30';
      case 'very_low':
        return 'bg-emerald-500/10 border-emerald-500/30';
      default:
        return 'bg-slate-500/10 border-slate-500/30';
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch ((severity || '').toUpperCase()) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border-rose-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-700 dark:text-orange-300 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-500/40';
      case 'LOW':
        return 'bg-blue-500/20 text-blue-700 dark:text-blue-300 border-blue-500/40';
      default:
        return 'bg-slate-500/20 text-slate-700 dark:text-slate-300 border-slate-500/40';
    }
  };

  return (
    <div className="max-w-5xl mx-auto py-10 px-4">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400 mb-4">
        <Link to="/scan" className="hover:text-slate-700 dark:hover:text-slate-200">Scanner Hub</Link>
        <span>/</span>
        <span className="text-brand-500 dark:text-brand-400 font-semibold">Email Phishing Analysis</span>
      </div>

      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight">
            Email Scam & Phishing Detection
          </h1>
          <p className="text-slate-600 dark:text-slate-400 mt-2 text-sm max-w-2xl leading-relaxed">
            Multi-layered email security inspection: parses RFC-822 MIME headers, evaluates SPF/DKIM/DMARC records, detects deceptive hyperlinks (anchor mismatches), inspects attachment formats, and executes statistical NLP classification.
          </p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-xs text-slate-600 dark:text-slate-400 shadow-sm">
          <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
          <span>Zero Outbound Fetches • SSRF Immune</span>
        </div>
      </div>

      {/* Mode Switcher */}
      <div className="flex rounded-xl bg-slate-100 dark:bg-slate-900 p-1 border border-slate-200 dark:border-slate-800 mb-6 max-w-md">
        <button
          type="button"
          onClick={() => { setInputMode('raw'); setError(null); }}
          className={`flex-1 py-2 text-xs font-semibold rounded-lg transition ${
            inputMode === 'raw'
              ? 'bg-brand-500 text-slate-950 shadow-md font-bold'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
          }`}
        >
          Paste Raw Email
        </button>
        <button
          type="button"
          onClick={() => { setInputMode('structured'); setError(null); }}
          className={`flex-1 py-2 text-xs font-semibold rounded-lg transition ${
            inputMode === 'structured'
              ? 'bg-brand-500 text-slate-950 shadow-md font-bold'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
          }`}
        >
          Structured Fields
        </button>
        <button
          type="button"
          onClick={() => { setInputMode('upload'); setError(null); }}
          className={`flex-1 py-2 text-xs font-semibold rounded-lg transition ${
            inputMode === 'upload'
              ? 'bg-brand-500 text-slate-950 shadow-md font-bold'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
          }`}
        >
          Upload .eml
        </button>
      </div>

      {/* Form Container */}
      <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 shadow-sm mb-8">
        <form onSubmit={handleScan} className="space-y-5">
          {inputMode === 'raw' && (
            <div>
              <div className="flex justify-between items-center mb-1.5">
                <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                  Raw RFC-822 / MIME Email Content *
                </label>
                <span className="text-[11px] text-slate-500 dark:text-slate-400">
                  {rawEmail.length.toLocaleString()} characters
                </span>
              </div>
              <textarea
                rows={8}
                value={rawEmail}
                onChange={(e) => setRawEmail(e.target.value)}
                placeholder="From: security@trustedbank.com&#10;Reply-To: phisher@untrusted-domain.com&#10;Subject: Urgent Security Notice&#10;&#10;Dear customer, please verify your credentials immediately..."
                className="w-full px-4 py-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-brand-500 text-xs font-mono leading-relaxed"
                required
              />
            </div>
          )}

          {inputMode === 'structured' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    From Header (Sender) *
                  </label>
                  <input
                    type="text"
                    value={sender}
                    onChange={(e) => setSender(e.target.value)}
                    placeholder="e.g. Chase Bank <alerts@chase-service.xyz>"
                    className="w-full px-4 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-brand-500 text-xs font-mono"
                    required
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Reply-To Header (Optional)
                  </label>
                  <input
                    type="text"
                    value={replyTo}
                    onChange={(e) => setReplyTo(e.target.value)}
                    placeholder="e.g. phisher@harvest-mail.net"
                    className="w-full px-4 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-brand-500 text-xs font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Subject Line
                </label>
                <input
                  type="text"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  placeholder="e.g. URGENT: Your account has been temporarily restricted"
                  className="w-full px-4 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-brand-500 text-xs"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Email Body Content *
                </label>
                <textarea
                  rows={5}
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  placeholder="Paste plain text or HTML email body here..."
                  className="w-full px-4 py-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-brand-500 text-xs leading-relaxed"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Attachment Filenames (comma-separated metadata)
                </label>
                <input
                  type="text"
                  value={attachmentsText}
                  onChange={(e) => setAttachmentsText(e.target.value)}
                  placeholder="e.g. Statement_Sept2026.pdf.exe, PaymentReceipt.scr"
                  className="w-full px-4 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-brand-500 text-xs font-mono"
                />
              </div>
            </div>
          )}

          {inputMode === 'upload' && (
            <div className="border-2 border-dashed border-slate-300 dark:border-slate-700 hover:border-brand-500/50 rounded-2xl p-8 text-center transition bg-slate-50/50 dark:bg-slate-950/50">
              <input
                ref={fileInputRef}
                type="file"
                accept=".eml,message/rfc822,text/plain"
                onChange={handleFileChange}
                className="hidden"
              />
              <div className="flex flex-col items-center justify-center space-y-3">
                <div className="h-12 w-12 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 flex items-center justify-center text-slate-600 dark:text-slate-300 text-xl shadow-sm">
                  ✉️
                </div>
                <div>
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    className="text-brand-600 dark:text-brand-400 hover:underline font-semibold text-sm cursor-pointer"
                  >
                    Select an .eml email file
                  </button>
                  <p className="text-slate-500 dark:text-slate-400 text-xs mt-1">
                    Standard RFC-822 export from Outlook, Thunderbird, or Apple Mail (Max 5MB)
                  </p>
                </div>
                {selectedFile && (
                  <div className="px-4 py-2 rounded-lg bg-white dark:bg-slate-900 border border-brand-500/40 text-brand-600 dark:text-brand-300 text-xs font-mono flex items-center gap-2">
                    <span>📄 {selectedFile.name}</span>
                    <span className="text-slate-500 dark:text-slate-400">
                      ({(selectedFile.size / 1024).toFixed(1)} KB)
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Action Row */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2">
            <button
              type="submit"
              disabled={scannerState === 'loading'}
              className="w-full sm:w-auto px-7 py-3 rounded-xl bg-brand-500 hover:bg-brand-400 text-slate-950 font-bold text-xs uppercase tracking-wider transition shadow-lg shadow-brand-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {scannerState === 'loading' ? (
                <>
                  <svg className="animate-spin h-4 w-4 text-slate-950" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                  </svg>
                  <span>Executing Pipeline...</span>
                </>
              ) : (
                <span>Analyze Email Threat</span>
              )}
            </button>

            {/* Presets */}
            {inputMode === 'raw' && (
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[11px] text-slate-500 dark:text-slate-400 font-medium">Quick Presets:</span>
                {DEMO_PRESETS.map((demo, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => {
                      setRawEmail(demo.raw_email);
                      setError(null);
                    }}
                    className="px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 hover:border-brand-500/40 text-[11px] text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition"
                  >
                    {demo.label}
                  </button>
                ))}
              </div>
            )}
          </div>

          {error && (
            <div className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800/80 text-rose-700 dark:text-rose-300 text-xs font-mono flex items-center gap-2">
              <span>⚠️</span>
              <span>{error}</span>
            </div>
          )}
        </form>
      </div>

      {/* Result Display Section */}
      {result && (
        <div className="space-y-6">
          {/* Main Risk Overview Banner */}
          <div className={`p-6 rounded-2xl border ${getRiskBg(result.risk_level)} shadow-sm`}>
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-slate-200 dark:border-slate-800/60">
              <div className="flex items-center gap-5">
                <div className="relative flex items-center justify-center">
                  <div className="h-20 w-20 rounded-2xl bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex flex-col items-center justify-center shadow-inner">
                    <span className={`text-3xl font-extrabold ${getRiskColor(result.risk_level)}`}>
                      {result.composite_risk_score}
                    </span>
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
                      / 100
                    </span>
                  </div>
                </div>

                <div>
                  <div className="flex items-center gap-2.5">
                    <span className={`px-2.5 py-0.5 rounded-full text-xs font-extrabold uppercase tracking-wide border ${getSeverityBadge(result.risk_level)}`}>
                      {result.risk_level}
                    </span>
                    {result.confidence !== undefined && (
                      <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                        Confidence: {(result.confidence * 100).toFixed(0)}%
                      </span>
                    )}
                  </div>
                  <h2 className="text-lg font-bold text-slate-900 dark:text-white mt-1.5">{result.summary}</h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400 font-mono mt-1">{result.target}</p>
                </div>
              </div>

              {result.category && result.category.length > 0 && (
                <div className="flex flex-wrap md:flex-col items-end gap-1.5">
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
                    Threat Taxonomy
                  </span>
                  <div className="flex flex-wrap gap-1.5 justify-end">
                    {result.category.map((cat, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 text-[11px] font-mono"
                      >
                        {cat}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Recommendation */}
            <div className="mt-5 p-4 rounded-xl bg-white/80 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800">
              <div className="text-xs font-bold uppercase tracking-wider text-brand-500 dark:text-brand-400 mb-1">
                Security Recommendation
              </div>
              <p className="text-sm text-slate-800 dark:text-slate-200 leading-relaxed font-medium">
                {result.recommendation || result.recommendations[0]}
              </p>
            </div>
          </div>

          {/* Detection Sources Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
              <div className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                Header Rules
              </div>
              <div className="text-xl font-bold text-slate-900 dark:text-white mt-1">
                {result.detection?.rules.risk_score ?? result.heuristic_score ?? 0}
                <span className="text-xs text-slate-500 dark:text-slate-400 font-normal"> / 100</span>
              </div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                {result.indicators.length} rule indicators
              </div>
            </div>

            <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
              <div className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                NLP ML Model
              </div>
              <div className="text-xl font-bold text-slate-900 dark:text-white mt-1">
                {result.detection?.ml
                  ? `${(result.detection.ml.model_probability !== undefined ? result.detection.ml.model_probability * 100 : result.detection.ml.model_score * 100).toFixed(0)}%`
                  : 'N/A'}
              </div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 capitalize">
                {result.detection?.ml?.prediction ?? 'Unavailable'}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
              <div className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                Embedded URLs
              </div>
              <div className="text-xl font-bold text-slate-900 dark:text-white mt-1">
                {result.detection?.embedded_urls?.length ?? 0}
              </div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                {result.detection?.embedded_urls?.filter((u) => u.risk_score >= 60).length ?? 0} high risk
              </div>
            </div>

            <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
              <div className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                Attachments
              </div>
              <div className="text-xl font-bold text-slate-900 dark:text-white mt-1">
                {result.detection?.attachments?.length ?? 0}
              </div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                {result.detection?.attachments?.filter((a) => a.is_suspicious_extension || a.is_double_extension).length ?? 0} suspicious
              </div>
            </div>
          </div>

          {/* Dynamic ML Algorithm & Architecture Attribution */}
          <MLArchitectureAttribution
            mlMetadata={result.ml_metadata}
            scanType="email"
            heuristicScore={result.heuristic_score}
          />

          {/* Why Was This Flagged? */}
          {result.reasons && result.reasons.length > 0 && (
            <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider mb-4 flex items-center gap-2">
                <span>🔍</span>
                <span>Why Was This Email Flagged?</span>
              </h3>
              <ul className="space-y-2.5">
                {result.reasons.map((reason, idx) => (
                  <li key={idx} className="flex items-start gap-2.5 text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                    <span className="text-amber-500 font-bold">•</span>
                    <span>{reason}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Triggered Threat Indicators */}
          {result.indicators.length > 0 && (
            <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider mb-4">
                Triggered Heuristic Security Indicators ({result.indicators.length})
              </h3>
              <div className="space-y-3">
                {result.indicators.map((ind: ThreatIndicator, idx: number) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-3"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(ind.severity)}`}>
                          {ind.severity}
                        </span>
                        <span className="font-semibold text-slate-900 dark:text-white text-xs">{ind.name}</span>
                      </div>
                      <p className="text-slate-600 dark:text-slate-400 text-xs mt-1">{ind.description}</p>
                      {ind.evidence && (
                        <div className="text-[11px] text-amber-600 dark:text-amber-300/80 font-mono mt-1">
                          Evidence: {ind.evidence}
                        </div>
                      )}
                    </div>
                    {ind.rule_id && (
                      <span className="text-[10px] text-slate-400 dark:text-slate-600 font-mono shrink-0">
                        {ind.rule_id}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Threat Intelligence & Reputation Correlation */}
          {(result.threat_intelligence || result.threat_graph) && (
            <ThreatIntelligencePanel
              threatIntelligence={result.threat_intelligence as any}
              threatGraph={result.threat_graph as any}
            />
          )}

          {/* PHASE 10: Social Engineering Intelligence */}
          {result.social_engineering && (result.social_engineering.findings?.length || 0) > 0 && (
            <div className="p-6 rounded-2xl bg-white dark:bg-slate-950 border border-amber-500/30 shadow-sm space-y-5">
              <div className="flex items-center justify-between pb-4 border-b border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-amber-500/20 text-amber-600 dark:text-amber-300 border border-amber-500/30 text-xl">🎭</div>
                  <div>
                    <h3 className="text-base font-bold text-slate-900 dark:text-white">SOCIAL ENGINEERING INTELLIGENCE</h3>
                    <p className="text-xs text-slate-600 dark:text-slate-400">Deception taxonomy, sender consistency, and manipulation vector analysis.</p>
                  </div>
                </div>
                {result.social_engineering.detected_categories && result.social_engineering.detected_categories.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 justify-end">
                    {result.social_engineering.detected_categories.slice(0, 3).map((cat, i) => (
                      <span key={i} className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-500/30 uppercase">
                        {cat.replace(/_/g, ' ')}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Sender Consistency Analysis */}
              {result.social_engineering.sender_analysis && (
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-2">
                  <h4 className="text-xs uppercase font-bold text-slate-600 dark:text-slate-400 tracking-wider flex items-center gap-2">
                    <span>📧</span> Sender Authentication & Consistency
                  </h4>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs font-mono">
                    {result.social_engineering.sender_analysis.from_domain && (
                      <div className="p-2 rounded bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                        <div className="text-slate-500 dark:text-slate-400">From Domain</div>
                        <div className="text-slate-900 dark:text-white font-semibold truncate">{result.social_engineering.sender_analysis.from_domain}</div>
                      </div>
                    )}
                    {result.social_engineering.sender_analysis.reply_to_domain && (
                      <div className="p-2 rounded bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                        <div className="text-slate-500 dark:text-slate-400">Reply-To Domain</div>
                        <div className={`font-semibold truncate ${result.social_engineering.sender_analysis.reply_to_domain !== result.social_engineering.sender_analysis.from_domain ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
                          {result.social_engineering.sender_analysis.reply_to_domain}
                        </div>
                      </div>
                    )}
                    {result.social_engineering.sender_analysis.consistency_verdict && (
                      <div className="p-2 rounded bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                        <div className="text-slate-500 dark:text-slate-400">Consistency</div>
                        <div className={`font-bold uppercase ${
                          result.social_engineering.sender_analysis.consistency_verdict === 'consistent' ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400'
                        }`}>{result.social_engineering.sender_analysis.consistency_verdict}</div>
                      </div>
                    )}
                  </div>
                  {result.social_engineering.sender_analysis.anomalies && result.social_engineering.sender_analysis.anomalies.length > 0 && (
                    <ul className="space-y-1 text-xs text-rose-600 dark:text-rose-300 pt-1">
                      {result.social_engineering.sender_analysis.anomalies.map((a: string, i: number) => (
                        <li key={i} className="flex items-start gap-2"><span>⚠</span><span>{a}</span></li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {/* SE Finding Cards */}
              {result.social_engineering.findings && result.social_engineering.findings.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs uppercase font-bold text-slate-600 dark:text-slate-400 tracking-wider">Detected Manipulation Vectors</h4>
                  {result.social_engineering.findings.map((finding, i) => (
                    <div key={i} className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-1.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-semibold text-xs text-slate-900 dark:text-slate-100">{finding.name}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${
                          finding.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border-rose-500/30' :
                          finding.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-700 dark:text-orange-300 border-orange-500/30' :
                          finding.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-500/30' :
                          'bg-slate-200 dark:bg-slate-700/30 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700'
                        }`}>{finding.severity}</span>
                      </div>
                      <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">{finding.why_it_matters}</p>
                      {finding.evidence && (
                        <div className="p-1.5 rounded bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 text-[11px] font-mono text-slate-700 dark:text-slate-300">
                          <span className="text-slate-500 mr-1">Evidence:</span>{finding.evidence}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Link Analysis Breakdown */}
          {result.detection?.embedded_urls && result.detection.embedded_urls.length > 0 && (
            <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider mb-4 flex items-center gap-2">
                <span>🔗</span>
                <span>Hyperlink Security & Anchor Mismatch Analysis ({result.detection.embedded_urls.length})</span>
              </h3>
              <div className="space-y-3">
                {result.detection.embedded_urls.map((link, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex flex-col md:flex-row justify-between gap-3 text-xs"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500 dark:text-slate-400">Displayed:</span>
                        <span className="font-mono text-slate-900 dark:text-white font-semibold">
                          {link.displayed_text || link.url}
                        </span>
                        {link.is_anchor_mismatch && (
                          <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/40 text-[10px] font-bold">
                            ⚠️ DECEPTIVE MISMATCH
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 text-[11px]">
                        <span className="text-slate-500 dark:text-slate-400">Actual Destination:</span>
                        <span className="font-mono text-slate-700 dark:text-slate-300 break-all">{link.url}</span>
                      </div>
                      {link.mismatch_details && (
                        <div className="text-[11px] text-rose-600 dark:text-rose-400 font-mono">
                          {link.mismatch_details}
                        </div>
                      )}
                    </div>
                    <div className="text-right shrink-0">
                      <span className={`font-bold font-mono ${getRiskColor(link.risk_level)}`}>
                        Risk {link.risk_score}/100
                      </span>
                      <div className="text-[10px] text-slate-500 dark:text-slate-400 uppercase">{link.risk_level}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Attachments Breakdown */}
          {result.detection?.attachments && result.detection.attachments.length > 0 && (
            <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider mb-4 flex items-center gap-2">
                <span>📎</span>
                <span>Attachment Metadata Inspection ({result.detection.attachments.length})</span>
              </h3>
              <div className="space-y-2">
                {result.detection.attachments.map((att, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs"
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-base">
                        {att.is_suspicious_extension || att.is_double_extension ? '⚠️' : '📄'}
                      </span>
                      <div>
                        <div className="font-mono text-slate-900 dark:text-white font-semibold">{att.filename}</div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400">
                          Extension: {att.extension || 'none'} • MIME: {att.mime_type}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {att.is_double_extension && (
                        <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/40 text-[10px] font-bold">
                          DOUBLE EXTENSION
                        </span>
                      )}
                      {att.is_suspicious_extension && (
                        <span className="px-2 py-0.5 rounded bg-orange-500/20 text-orange-700 dark:text-orange-300 border border-orange-500/40 text-[10px] font-bold">
                          HIGH RISK FORMAT
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Collapsible Technical Details */}
          <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm overflow-hidden">
            <button
              type="button"
              onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
              className="w-full px-6 py-4 flex items-center justify-between text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider hover:bg-slate-50 dark:hover:bg-slate-950/50 transition"
            >
              <span>Technical & Diagnostic Details</span>
              <span>{showTechnicalDetails ? '▲ Hide' : '▼ Expand'}</span>
            </button>

            {showTechnicalDetails && (
              <div className="p-6 border-t border-slate-200 dark:border-slate-800 space-y-4 bg-slate-50/50 dark:bg-slate-950/40 text-xs">
                {/* Header Auth Table */}
                {result.technical_details?.email_metadata?.auth_results && (
                  <div>
                    <h4 className="text-slate-600 dark:text-slate-400 font-semibold mb-2">Reported Header Authentication Checks</h4>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      {Object.entries(result.technical_details.email_metadata.auth_results).map(([mech, data]: [string, any]) => (
                        <div key={mech} className="p-3 rounded-lg bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 font-mono">
                          <div className="text-slate-500 dark:text-slate-400 uppercase text-[10px]">{mech} Status</div>
                          <div className={`font-bold mt-1 ${data?.status === 'pass' ? 'text-emerald-600 dark:text-emerald-400' : data?.status === 'fail' ? 'text-rose-600 dark:text-rose-400' : 'text-slate-700 dark:text-slate-300'}`}>
                            {data?.status || 'unknown'}
                          </div>
                          {data?.details && (
                            <div className="text-[10px] text-slate-500 dark:text-slate-400 mt-1 truncate">{data.details}</div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* ML Diagnostics */}
                {result.detection?.ml && (
                  <div>
                    <h4 className="text-slate-600 dark:text-slate-400 font-semibold mb-2">NLP Classifier Signals</h4>
                    <div className="p-3.5 rounded-lg bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2 font-mono">
                      <div className="flex justify-between">
                        <span className="text-slate-500 dark:text-slate-400">Model Pipeline:</span>
                        <span className="text-slate-900 dark:text-white">{result.detection.ml.model_version}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500 dark:text-slate-400">Predicted Threat Probability:</span>
                        <span className="text-slate-900 dark:text-white">
                          {(result.detection.ml.model_probability !== undefined ? result.detection.ml.model_probability * 100 : result.detection.ml.model_score * 100).toFixed(2)}%
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500 dark:text-slate-400">Active TF-IDF Vocabulary:</span>
                        <span className="text-slate-900 dark:text-white">{result.detection.ml.features_used} tokens</span>
                      </div>
                      {result.detection.ml.top_contributing_features && result.detection.ml.top_contributing_features.length > 0 && (
                        <div className="pt-2 border-t border-slate-200 dark:border-slate-800">
                          <span className="text-slate-500 dark:text-slate-400 block mb-1">Top Phishing Vocabulary Tokens:</span>
                          <div className="flex flex-wrap gap-1.5">
                            {result.detection.ml.top_contributing_features.map((f, i) => (
                              <span key={i} className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-amber-700 dark:text-amber-300 text-[10px]">
                                {f.feature} (+{(f.weight ?? f.value ?? 0).toFixed(3)})
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
