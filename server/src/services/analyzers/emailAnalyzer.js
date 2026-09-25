/**
 * Email Analyzer — combines URL + message analysis with email-specific checks.
 *
 * Future: SPF/DKIM/DMARC header analysis, sender reputation lookup.
 */

const messageAnalyzer = require('./messageAnalyzer');

const SUSPICIOUS_SENDER_PATTERNS = [
  'noreply@', 'no-reply@', 'support@', 'admin@', 'security@',
  'helpdesk@', 'service@', 'info@',
];

const analyze = async (input) => {
  // Run message analysis on the full email content
  const messageResult = await messageAnalyzer.analyze(input);
  const text = input.toLowerCase();

  let bonusScore = 0;
  const extraReasons = [];
  const extraIndicators = [];

  // Check for spoofed "From" headers in raw email text
  const fromMatch = text.match(/from:\s*.*?<([^>]+)>/);
  if (fromMatch) {
    const senderEmail = fromMatch[1].toLowerCase();
    // Free email used as corporate sender
    const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com'];
    const senderDomain = senderEmail.split('@')[1];
    if (freeProviders.includes(senderDomain)) {
      bonusScore += 10;
      extraReasons.push('Sender uses a free email provider (unusual for official communication)');
      extraIndicators.push({ name: 'Free email provider', description: `Sent from ${senderDomain}`, severity: 'medium' });
    }
  }

  // Check for reply-to mismatch
  const replyToMatch = text.match(/reply-to:\s*.*?<([^>]+)>/);
  if (fromMatch && replyToMatch && fromMatch[1] !== replyToMatch[1]) {
    bonusScore += 15;
    extraReasons.push('Reply-To address differs from the From address');
    extraIndicators.push({ name: 'Reply-To mismatch', description: 'Responses would go to a different address than the apparent sender', severity: 'high' });
  }

  // Check for attachment mentions
  if (text.includes('attachment') || text.includes('attached file') || text.includes('open the attached')) {
    bonusScore += 8;
    extraReasons.push('Email references attachments (potential malware vector)');
    extraIndicators.push({ name: 'Attachment reference', description: 'Email mentions attachments which could contain malware', severity: 'medium' });
  }

  const combinedScore = Math.min(messageResult.riskScore + bonusScore, 100);

  let riskLevel;
  if (combinedScore >= 75) riskLevel = 'CRITICAL';
  else if (combinedScore >= 50) riskLevel = 'HIGH';
  else if (combinedScore >= 25) riskLevel = 'MEDIUM';
  else if (combinedScore >= 10) riskLevel = 'LOW';
  else riskLevel = 'SAFE';

  return {
    riskLevel,
    riskScore: combinedScore,
    reasons: [...messageResult.reasons, ...extraReasons],
    indicators: [...messageResult.indicators, ...extraIndicators],
    recommendations: messageResult.recommendations,
  };
};

module.exports = { analyze };
