/**
 * URL Analyzer — heuristic-based URL risk assessment.
 *
 * Checks for common phishing/scam URL patterns using rule-based detection.
 * Future: integrate VirusTotal, Google Safe Browsing, WHOIS lookups, ML classifier.
 */

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.work', '.buzz', '.tk', '.ml', '.ga', '.cf', '.gq', '.info', '.click', '.link', '.loan', '.win'];
const TRUSTED_DOMAINS = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com', 'facebook.com', 'twitter.com', 'linkedin.com', 'paypal.com'];
const PHISHING_KEYWORDS = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'bank', 'password', 'signin', 'credential', 'suspend', 'unlock', 'alert'];
const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'shorturl.at'];

const analyze = async (input) => {
  const reasons = [];
  const indicators = [];
  let score = 0;

  let urlObj;
  try {
    // Add protocol if missing so URL constructor works
    const urlStr = input.match(/^https?:\/\//) ? input : `http://${input}`;
    urlObj = new URL(urlStr);
  } catch {
    return {
      riskLevel: 'HIGH',
      riskScore: 70,
      reasons: ['Invalid or malformed URL structure'],
      indicators: [{ name: 'Malformed URL', description: 'The URL could not be parsed, which is itself suspicious', severity: 'high' }],
      recommendations: ['Do not visit this URL', 'Verify the source that sent you this link'],
    };
  }

  const hostname = urlObj.hostname.toLowerCase();
  const fullUrl = input.toLowerCase();

  // Check: IP address instead of domain
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    score += 30;
    reasons.push('URL uses an IP address instead of a domain name');
    indicators.push({ name: 'IP-based URL', description: 'Legitimate sites rarely use raw IP addresses', severity: 'high' });
  }

  // Check: suspicious TLD
  const tld = '.' + hostname.split('.').pop();
  if (SUSPICIOUS_TLDS.includes(tld)) {
    score += 15;
    reasons.push(`Uses suspicious top-level domain (${tld})`);
    indicators.push({ name: 'Suspicious TLD', description: `The domain ends with ${tld}, commonly associated with spam`, severity: 'medium' });
  }

  // Check: excessive subdomains (possible domain spoofing)
  const parts = hostname.split('.');
  if (parts.length > 3) {
    score += 15;
    reasons.push('URL has an unusually high number of subdomains');
    indicators.push({ name: 'Subdomain abuse', description: 'Multiple subdomains can be used to mimic legitimate sites', severity: 'medium' });
  }

  // Check: contains phishing keywords in path/query
  const pathAndQuery = urlObj.pathname + urlObj.search;
  const foundKeywords = PHISHING_KEYWORDS.filter((kw) => pathAndQuery.includes(kw));
  if (foundKeywords.length > 0) {
    score += Math.min(foundKeywords.length * 8, 25);
    reasons.push(`URL path contains suspicious keywords: ${foundKeywords.join(', ')}`);
    indicators.push({ name: 'Phishing keywords', description: 'URL contains terms commonly used in phishing attacks', severity: 'medium' });
  }

  // Check: brand impersonation via subdomain
  const brandInSubdomain = TRUSTED_DOMAINS.some((brand) => {
    const brandName = brand.split('.')[0];
    return hostname.includes(brandName) && !hostname.endsWith(brand);
  });
  if (brandInSubdomain) {
    score += 25;
    reasons.push('URL appears to impersonate a well-known brand');
    indicators.push({ name: 'Brand impersonation', description: 'Domain contains a trusted brand name but is not the official site', severity: 'high' });
  }

  // Check: URL shortener
  if (URL_SHORTENERS.some((s) => hostname.includes(s))) {
    score += 10;
    reasons.push('URL uses a URL shortening service that hides the true destination');
    indicators.push({ name: 'URL shortener', description: 'Shortened URLs can mask malicious destinations', severity: 'low' });
  }

  // Check: no HTTPS
  if (urlObj.protocol === 'http:' && !hostname.includes('localhost')) {
    score += 10;
    reasons.push('URL does not use HTTPS encryption');
    indicators.push({ name: 'No HTTPS', description: 'Lack of encryption increases risk of data interception', severity: 'medium' });
  }

  // Check: very long URL (common in obfuscation)
  if (fullUrl.length > 200) {
    score += 10;
    reasons.push('Unusually long URL, possibly used to hide malicious content');
    indicators.push({ name: 'Long URL', description: 'Excessively long URLs can obfuscate malicious parameters', severity: 'low' });
  }

  // Check: contains @ symbol (credential stuffing in URL)
  if (fullUrl.includes('@')) {
    score += 20;
    reasons.push('URL contains @ symbol, which can trick browsers into ignoring the real domain');
    indicators.push({ name: '@ in URL', description: 'The @ symbol can redirect to a different domain than displayed', severity: 'high' });
  }

  // Check: hex/encoded characters in domain
  if (/%[0-9a-f]{2}/i.test(hostname)) {
    score += 15;
    reasons.push('Domain contains encoded characters (possible obfuscation)');
    indicators.push({ name: 'Encoded domain', description: 'Character encoding in domains is often used to bypass filters', severity: 'medium' });
  }

  // Cap the score
  score = Math.min(score, 100);

  // Determine risk level
  let riskLevel;
  if (score >= 75) riskLevel = 'CRITICAL';
  else if (score >= 50) riskLevel = 'HIGH';
  else if (score >= 25) riskLevel = 'MEDIUM';
  else if (score >= 10) riskLevel = 'LOW';
  else riskLevel = 'SAFE';

  // Generate recommendations
  const recommendations = [];
  if (score >= 50) {
    recommendations.push('Do not click or visit this URL');
    recommendations.push('Do not enter any personal information');
    recommendations.push('Verify the sender through an independent channel');
  } else if (score >= 25) {
    recommendations.push('Exercise caution before visiting this URL');
    recommendations.push('Verify the URL matches the expected destination');
    recommendations.push('Look for the padlock icon in your browser');
  } else if (score >= 10) {
    recommendations.push('This URL shows minor suspicious indicators');
    recommendations.push('Proceed with normal caution');
  } else {
    recommendations.push('No significant threats detected');
    recommendations.push('Always remain vigilant online');
  }

  if (reasons.length === 0) {
    reasons.push('No suspicious indicators detected in URL structure');
  }

  return { riskLevel, riskScore: score, reasons, indicators, recommendations };
};

module.exports = { analyze };
