/**
 * Message Analyzer — heuristic-based suspicious message detection.
 *
 * Detects social engineering, urgency manipulation, and common scam language.
 * Future: integrate NLP model for sentiment/intent classification.
 */

const URGENCY_PHRASES = [
  'act now', 'immediately', 'urgent', 'expires today', 'last chance',
  'limited time', 'don\'t miss', 'hurry', 'right away', 'within 24 hours',
  'account will be closed', 'suspended', 'verify your identity', 'confirm now',
  'action required', 'respond immediately',
];

const FINANCIAL_LURES = [
  'won a prize', 'lottery', 'inheritance', 'million dollars', 'free gift',
  'cash prize', 'congratulations you', 'claim your', 'selected as winner',
  'beneficiary', 'unclaimed funds', 'wire transfer', 'western union',
  'money gram', 'bitcoin', 'crypto reward',
];

const THREAT_LANGUAGE = [
  'legal action', 'arrested', 'warrant', 'police', 'lawsuit',
  'court order', 'irs', 'tax fraud', 'criminal charges', 'investigation',
  'penalty', 'fine of', 'seized',
];

const CREDENTIAL_REQUESTS = [
  'password', 'ssn', 'social security', 'credit card', 'bank account',
  'pin number', 'security code', 'cvv', 'routing number', 'date of birth',
  'mother\'s maiden', 'verify your account', 'login credentials', 'otp',
];

const IMPERSONATION_PHRASES = [
  'customer service', 'tech support', 'from microsoft', 'from apple',
  'from google', 'from amazon', 'from your bank', 'helpdesk',
  'it department', 'system administrator',
];

const analyze = async (input) => {
  const text = input.toLowerCase();
  const reasons = [];
  const indicators = [];
  let score = 0;

  // Urgency detection
  const urgencyMatches = URGENCY_PHRASES.filter((p) => text.includes(p));
  if (urgencyMatches.length > 0) {
    const points = Math.min(urgencyMatches.length * 10, 25);
    score += points;
    reasons.push(`Contains urgency/pressure language: "${urgencyMatches[0]}"`);
    indicators.push({ name: 'Urgency manipulation', description: `Found ${urgencyMatches.length} urgency phrase(s) designed to pressure quick action`, severity: urgencyMatches.length >= 2 ? 'high' : 'medium' });
  }

  // Financial lure detection
  const financialMatches = FINANCIAL_LURES.filter((p) => text.includes(p));
  if (financialMatches.length > 0) {
    const points = Math.min(financialMatches.length * 12, 30);
    score += points;
    reasons.push('Contains financial lure or too-good-to-be-true promise');
    indicators.push({ name: 'Financial lure', description: `Message references ${financialMatches[0]}`, severity: 'high' });
  }

  // Threat detection
  const threatMatches = THREAT_LANGUAGE.filter((p) => text.includes(p));
  if (threatMatches.length > 0) {
    const points = Math.min(threatMatches.length * 12, 25);
    score += points;
    reasons.push('Contains threatening or intimidating language');
    indicators.push({ name: 'Threat/intimidation', description: 'Uses fear tactics to compel action', severity: 'high' });
  }

  // Credential request detection
  const credMatches = CREDENTIAL_REQUESTS.filter((p) => text.includes(p));
  if (credMatches.length > 0) {
    score += Math.min(credMatches.length * 15, 30);
    reasons.push('Requests sensitive personal information or credentials');
    indicators.push({ name: 'Credential harvesting', description: 'Asks for sensitive data that legitimate organizations would not request via message', severity: 'high' });
  }

  // Impersonation detection
  const impersonationMatches = IMPERSONATION_PHRASES.filter((p) => text.includes(p));
  if (impersonationMatches.length > 0) {
    score += 15;
    reasons.push('Claims to be from a well-known organization or authority');
    indicators.push({ name: 'Impersonation', description: 'Message impersonates a trusted entity', severity: 'medium' });
  }

  // URL in message (embedded links)
  const urlPattern = /https?:\/\/[^\s]+|www\.[^\s]+/g;
  const urls = text.match(urlPattern);
  if (urls && urls.length > 0) {
    score += 10;
    reasons.push(`Contains ${urls.length} embedded link(s)`);
    indicators.push({ name: 'Embedded links', description: 'Messages with links can redirect to malicious sites', severity: 'low' });
  }

  // Excessive caps (shouting)
  const capsRatio = (input.match(/[A-Z]/g) || []).length / Math.max(input.length, 1);
  if (capsRatio > 0.4 && input.length > 20) {
    score += 8;
    reasons.push('Excessive use of capital letters (shouting pattern)');
    indicators.push({ name: 'Excessive caps', description: 'Heavy capitalization is a common social engineering tactic', severity: 'low' });
  }

  // Poor grammar indicators (very basic)
  const grammarIssues = ['kindly do the needful', 'dear customer', 'dear friend', 'dear sir/madam', 'respected sir', 'dear valued'];
  const grammarMatches = grammarIssues.filter((p) => text.includes(p));
  if (grammarMatches.length > 0) {
    score += 10;
    reasons.push('Contains phrasing commonly associated with scam messages');
    indicators.push({ name: 'Scam phrasing', description: 'Uses formulaic language typical of mass scam campaigns', severity: 'medium' });
  }

  score = Math.min(score, 100);

  let riskLevel;
  if (score >= 75) riskLevel = 'CRITICAL';
  else if (score >= 50) riskLevel = 'HIGH';
  else if (score >= 25) riskLevel = 'MEDIUM';
  else if (score >= 10) riskLevel = 'LOW';
  else riskLevel = 'SAFE';

  const recommendations = [];
  if (score >= 50) {
    recommendations.push('Do not respond to this message');
    recommendations.push('Do not click any links or provide personal information');
    recommendations.push('Block the sender');
    recommendations.push('Report the message as spam/scam');
  } else if (score >= 25) {
    recommendations.push('Be cautious — verify the sender independently');
    recommendations.push('Do not share personal information');
  } else {
    recommendations.push('No significant scam indicators detected');
    recommendations.push('Always verify unexpected messages from unknown senders');
  }

  if (reasons.length === 0) {
    reasons.push('No suspicious patterns detected in the message');
  }

  return { riskLevel, riskScore: score, reasons, indicators, recommendations };
};

module.exports = { analyze };
