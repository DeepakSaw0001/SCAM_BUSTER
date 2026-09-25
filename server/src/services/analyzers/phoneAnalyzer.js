/**
 * Phone Number Analyzer — heuristic checks on phone numbers.
 *
 * Future: integrate with phone reputation APIs, carrier lookup, spam databases.
 */

// Country codes known for high scam volume (for awareness, not discrimination)
const HIGH_RISK_PREFIXES = ['+234', '+233', '+91', '+92', '+63', '+1900', '+44070'];
const PREMIUM_RATE_PREFIXES = ['900', '976', '0900', '0906', '0909'];

const analyze = async (input) => {
  const phone = input.replace(/[\s\-\(\)\.]/g, '');
  const reasons = [];
  const indicators = [];
  let score = 0;

  // Check: too short or too long
  const digitsOnly = phone.replace(/\D/g, '');
  if (digitsOnly.length < 7) {
    score += 15;
    reasons.push('Phone number is unusually short');
    indicators.push({ name: 'Short number', description: 'Valid phone numbers typically have at least 7 digits', severity: 'medium' });
  }
  if (digitsOnly.length > 15) {
    score += 15;
    reasons.push('Phone number is unusually long');
    indicators.push({ name: 'Long number', description: 'Number exceeds standard international format length', severity: 'medium' });
  }

  // Check: premium rate number
  const isPremium = PREMIUM_RATE_PREFIXES.some((prefix) => phone.startsWith(prefix) || digitsOnly.startsWith(prefix));
  if (isPremium) {
    score += 30;
    reasons.push('Number appears to be a premium-rate number (calling may incur high charges)');
    indicators.push({ name: 'Premium rate', description: 'Premium-rate numbers charge elevated fees per minute', severity: 'high' });
  }

  // Check: high-risk country prefix
  const highRiskMatch = HIGH_RISK_PREFIXES.find((prefix) => phone.startsWith(prefix));
  if (highRiskMatch) {
    score += 15;
    reasons.push(`Number uses prefix ${highRiskMatch} (frequently associated with scam calls)`);
    indicators.push({ name: 'High-risk prefix', description: 'This country code appears frequently in reported scam calls', severity: 'medium' });
  }

  // Check: contains non-standard characters
  if (/[^0-9+\-\(\)\s\.]/.test(input)) {
    score += 10;
    reasons.push('Number contains unexpected characters');
    indicators.push({ name: 'Non-standard format', description: 'Legitimate phone numbers use only digits and standard separators', severity: 'low' });
  }

  // Check: all same digit (fake/placeholder)
  if (/^(\d)\1{6,}$/.test(digitsOnly)) {
    score += 25;
    reasons.push('Number consists of repeating digits (likely fake)');
    indicators.push({ name: 'Repeating digits', description: 'All-same-digit numbers are typically not valid', severity: 'high' });
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
    recommendations.push('Do not call or text this number');
    recommendations.push('Do not share personal information if contacted from this number');
    recommendations.push('Report the number to your carrier');
  } else if (score >= 25) {
    recommendations.push('Exercise caution when interacting with this number');
    recommendations.push('Verify the caller through official channels');
  } else {
    recommendations.push('No significant risk indicators detected');
    recommendations.push('Always be cautious with unknown callers');
  }

  if (reasons.length === 0) {
    reasons.push('No suspicious indicators found for this phone number');
  }

  return { riskLevel, riskScore: score, reasons, indicators, recommendations };
};

module.exports = { analyze };
