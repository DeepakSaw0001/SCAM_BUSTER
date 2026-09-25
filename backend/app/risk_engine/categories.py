"""
ScamBuster Risk Engine — Categories

Defines and correlates threat taxonomy categories based on rule findings
and structural evidence.
"""

from typing import List, Set
from app.services.url_rule_detector import RuleFinding

# Primary Risk Categories
CATEGORY_POTENTIAL_PHISHING = "potential_phishing"
CATEGORY_SUSPICIOUS_INFRASTRUCTURE = "suspicious_infrastructure"
CATEGORY_CREDENTIAL_HARVESTING = "credential_harvesting"
CATEGORY_DEFENSE_EVASION = "defense_evasion"
CATEGORY_UNENCRYPTED_TRANSPORT = "unencrypted_transport"
CATEGORY_BENIGN_BASELINE = "benign_baseline"
CATEGORY_INSUFFICIENT_EVIDENCE = "insufficient_evidence"

# Mapping of specific rules to categorized threats
RULE_TO_CATEGORIES = {
    "RULE_IP_HOSTNAME": [CATEGORY_SUSPICIOUS_INFRASTRUCTURE],
    "RULE_SUSPICIOUS_TLD": [CATEGORY_SUSPICIOUS_INFRASTRUCTURE],
    "RULE_NON_STANDARD_PORT": [CATEGORY_SUSPICIOUS_INFRASTRUCTURE],
    "RULE_KEYWORD_PATTERN": [CATEGORY_POTENTIAL_PHISHING, CATEGORY_CREDENTIAL_HARVESTING],
    "RULE_KEYWORD_SINGLE": [CATEGORY_POTENTIAL_PHISHING],
    "RULE_EXCESSIVE_SUBDOMAINS": [CATEGORY_POTENTIAL_PHISHING, CATEGORY_DEFENSE_EVASION],
    "RULE_USERINFO_SPOOFING": [CATEGORY_POTENTIAL_PHISHING, CATEGORY_DEFENSE_EVASION],
    "RULE_ENCODED_OBFUSCATION": [CATEGORY_DEFENSE_EVASION],
    "RULE_PATH_REDIRECT": [CATEGORY_DEFENSE_EVASION],
    "RULE_UNENCRYPTED_HTTP": [CATEGORY_UNENCRYPTED_TRANSPORT],
}


def determine_categories(findings: List[RuleFinding]) -> List[str]:
    """
    Determine threat categories from triggered rule findings.
    """
    if not findings:
        return [CATEGORY_BENIGN_BASELINE]

    assigned: Set[str] = set()
    for finding in findings:
        cats = RULE_TO_CATEGORIES.get(finding.rule_id, [])
        for c in cats:
            assigned.add(c)

    if not assigned:
        return [CATEGORY_BENIGN_BASELINE]

    # Deterministic sorting
    priority_order = [
        CATEGORY_POTENTIAL_PHISHING,
        CATEGORY_CREDENTIAL_HARVESTING,
        CATEGORY_SUSPICIOUS_INFRASTRUCTURE,
        CATEGORY_DEFENSE_EVASION,
        CATEGORY_UNENCRYPTED_TRANSPORT,
    ]
    return sorted(list(assigned), key=lambda x: priority_order.index(x) if x in priority_order else 99)
