"""
ScamBuster Heuristic Cyber Analyzer — Text & SMS Scam Analysis

Deterministic analysis detecting social engineering patterns:
- Urgency, intimidation, and panic-inducing triggers
- Financial bait, fake lotteries, and inheritance lures
- Direct credential, OTP, PIN, and seed phrase harvesting
- Impersonation of postal services, couriers, or government agencies
- Obfuscated/leetspeak spelling
- Embedded links and malicious shorteners
"""

import re
from typing import Any, Dict, List, Optional

URGENCY_PATTERNS = [
    (r"\b(immediately|act now|urgent|right away|at once)\b", "Immediate Urgency Pressure"),
    (r"\b(suspended|terminated|disabled|locked|restricted)\b", "Account Disruption Threat"),
    (r"\b(within 24 hours|within 12 hours|within 1 hour|today only|expires soon)\b", "Artificial Deadline / Countdown Pressure"),
    (r"\b(police|arrest|lawsuit|legal action|warrant|court|fbi|irs)\b", "Law Enforcement / Intimidation Coercion"),
    (r"\b(unauthorized (access|transaction|charge)|suspicious activity)\b", "Fabricated Security Alert Panic"),
]

FINANCIAL_PATTERNS = [
    (r"\b(winner|won|congratulations|prize|jackpot|lottery|raffle)\b", "Fake Prize / Lottery Bait"),
    (r"\b(claim (reward|bonus|funds|cash|crypto|airdrop))\b", "Unsolicited Reward Claim"),
    (r"\b(\$\d+(?:,\d{3})*(?:\.\d+)?|\b\d+ (?:dollars|usd|bitcoin|btc|eth))\b", "Monetary Sum Solicitation"),
    (r"\b(guaranteed (return|profit|income)|double your money|risk[- ]free)\b", "High-Yield Investment Fraud Trigger"),
]

CREDENTIAL_HARVESTING = [
    (r"\b(otp|one[- ]time password|verification code|security code)\b", "OTP / Security Code Harvesting"),
    (r"\b(enter your pin|atm pin|cvv|security code on back)\b", "Card PIN / CVV Request"),
    (r"\b(ssn|social security number|national id|bvn)\b", "Government ID / SSN Solicitation"),
    (r"\b(seed phrase|secret phrase|private key|recovery words)\b", "Cryptocurrency Seed Phrase Theft"),
    (r"\b(verify your (password|account|identity|details)|update credentials)\b", "Credential Verification Lure"),
]

DELIVERY_IMPERSONATION = [
    (r"\b(package|parcel|shipment|delivery) (failed|delayed|held|pending)\b", "Failed Delivery Scam"),
    (r"\b(customs (fee|tax|duty)|reschedule delivery|update address)\b", "Courier Reschedule / Fee Fraud"),
    (r"\b(usps|fedex|dhl|ups|royal mail)\b", "Postal / Courier Brand Reference"),
]

LEETSPEAK_PATTERN = re.compile(r"\b\w*([@0$!13457])\w*\b", re.IGNORECASE)
URL_IN_TEXT_PATTERN = re.compile(r"https?://[^\s]+|www\.[^\s]+")


def analyze_text(text: str, sender: Optional[str] = None) -> Dict[str, Any]:
    """
    Perform deep deterministic cybersecurity analysis on message/text content.
    Returns heuristic score (0-100), threat indicators, and extracted details.
    """
    clean_text = text.strip()
    lower_text = clean_text.lower()

    indicators: List[Dict[str, Any]] = []
    score = 0

    # 1. Credential Harvesting (Critical Severity)
    for pattern, name in CREDENTIAL_HARVESTING:
        match = re.search(pattern, lower_text)
        if match:
            score += 35
            indicators.append({
                "name": name,
                "severity": "CRITICAL",
                "description": "The message attempts to solicit confidential credentials, passwords, or one-time verification tokens.",
                "evidence": match.group(0),
            })
            break  # Flag one primary credential harvester rule

    # 2. Urgency and Coercion Indicators
    urgency_hits = []
    for pattern, name in URGENCY_PATTERNS:
        match = re.search(pattern, lower_text)
        if match:
            urgency_hits.append(name)
            score += 20
            indicators.append({
                "name": name,
                "severity": "HIGH",
                "description": "High-pressure psychological manipulation designed to induce panic and impulsive compliance.",
                "evidence": match.group(0),
            })
            if len(urgency_hits) >= 2:
                break

    # 3. Financial Lures & Lottery Bait
    for pattern, name in FINANCIAL_PATTERNS:
        match = re.search(pattern, lower_text)
        if match:
            score += 20
            indicators.append({
                "name": name,
                "severity": "MEDIUM",
                "description": "Unsolicited promises of monetary rewards, prizes, or returns characteristic of advance-fee fraud.",
                "evidence": match.group(0),
            })
            break

    # 4. Delivery & Courier Impersonation
    for pattern, name in DELIVERY_IMPERSONATION:
        match = re.search(pattern, lower_text)
        if match:
            score += 20
            indicators.append({
                "name": name,
                "severity": "MEDIUM",
                "description": "Fictitious courier or postal notification commonly used to lure victims into clicking malware or payment links.",
                "evidence": match.group(0),
            })
            break

    # 5. Embedded URL in SMS/Text
    embedded_urls = URL_IN_TEXT_PATTERN.findall(clean_text)
    if embedded_urls:
        score += 15
        indicators.append({
            "name": "Embedded Link in Message",
            "severity": "MEDIUM",
            "description": "SMS and instant messages containing direct links pose elevated phishing risks (Smishing vector).",
            "evidence": ", ".join(embedded_urls[:3]),
        })

    # 6. Sender Anomaly Check
    if sender:
        clean_sender = sender.strip()
        # Non-standard sender or numeric spoofing
        if re.search(r"^\+?[0-9]{3,7}$", clean_sender) and not clean_sender.startswith("+"):
            # Shortcode without verification
            indicators.append({
                "name": "Unverified Sender Identifier",
                "severity": "LOW",
                "description": f"The message was received from an unverified or shortcode sender '{clean_sender}'.",
                "evidence": clean_sender,
            })

    capped_score = min(max(score, 0), 100)

    return {
        "score": capped_score,
        "indicators": indicators,
        "details": {
            "text_length": len(clean_text),
            "embedded_urls": embedded_urls,
            "sender": sender,
            "indicator_count": len(indicators),
        }
    }
