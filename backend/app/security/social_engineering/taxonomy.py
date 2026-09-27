"""
ScamBuster — Centralized Social Engineering Taxonomy (Phase 10)

Defines the 21 standardized social engineering and scam categories,
along with analytical severity, educational 'Why This Matters' descriptions,
and actionable, safe recommendations.

Categories describe detected patterns — they are analytical findings,
not automatic proof of fraud.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional


class SocialEngineeringCategory(str, Enum):
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    FINANCIAL_FRAUD = "FINANCIAL_FRAUD"
    OTP_SCAM = "OTP_SCAM"
    PAYMENT_REQUEST = "PAYMENT_REQUEST"
    CREDENTIAL_THEFT = "CREDENTIAL_THEFT"
    IMPERSONATION = "IMPERSONATION"
    URGENCY = "URGENCY"
    FEAR = "FEAR"
    REWARD = "REWARD"
    DELIVERY_SCAM = "DELIVERY_SCAM"
    BANKING_SCAM = "BANKING_SCAM"
    TECH_SUPPORT_SCAM = "TECH_SUPPORT_SCAM"
    INVESTMENT_SCAM = "INVESTMENT_SCAM"
    JOB_SCAM = "JOB_SCAM"
    ROMANCE_SCAM = "ROMANCE_SCAM"
    GOVERNMENT_IMPERSONATION = "GOVERNMENT_IMPERSONATION"
    TAX_SCAM = "TAX_SCAM"
    REFUND_SCAM = "REFUND_SCAM"
    MALICIOUS_DOWNLOAD = "MALICIOUS_DOWNLOAD"
    MALICIOUS_LINK = "MALICIOUS_LINK"
    OTHER = "OTHER"


@dataclass(frozen=True)
class CategoryMetadata:
    category: SocialEngineeringCategory
    display_name: str
    description: str
    default_severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    why_it_matters: str
    safe_recommendations: List[str]


TAXONOMY_REGISTRY: Dict[SocialEngineeringCategory, CategoryMetadata] = {
    SocialEngineeringCategory.ACCOUNT_TAKEOVER: CategoryMetadata(
        category=SocialEngineeringCategory.ACCOUNT_TAKEOVER,
        display_name="Account Takeover Attempt",
        description="Patterns attempting to hijack, lock, or take unauthorized control of user accounts.",
        default_severity="HIGH",
        why_it_matters=(
            "Attackers leverage claims of account compromise or unauthorized changes to trick users "
            "into handing over reset links, recovery tokens, or two-factor codes."
        ),
        safe_recommendations=[
            "Do not click verification or password-reset links inside unexpected messages.",
            "Navigate directly to the service's official website or app to check your account status.",
            "Verify active login sessions from your service security dashboard.",
        ],
    ),
    SocialEngineeringCategory.FINANCIAL_FRAUD: CategoryMetadata(
        category=SocialEngineeringCategory.FINANCIAL_FRAUD,
        display_name="Financial Fraud Solicitation",
        description="Techniques soliciting unauthorized fund transfers, card credentials, or wire transactions.",
        default_severity="HIGH",
        why_it_matters=(
            "Fraudulent payment requests exploit trust, fabricated invoices, or fake account shortages "
            "to divert financial transactions to unauthorized recipients."
        ),
        safe_recommendations=[
            "Never wire money or settle invoices based solely on an unsolicited message.",
            "Verify payment details using independently established official contact numbers.",
            "Review your official bank statements directly rather than trusting in-message links.",
        ],
    ),
    SocialEngineeringCategory.OTP_SCAM: CategoryMetadata(
        category=SocialEngineeringCategory.OTP_SCAM,
        display_name="OTP / Verification Code Solicitation",
        description="Direct or coercive attempts to extract one-time passwords, SMS codes, or authenticators.",
        default_severity="CRITICAL",
        why_it_matters=(
            "One-Time Passwords (OTPs) are the final authentication boundary protecting accounts. "
            "Legitimate organizations generally should not ask you to disclose authentication codes "
            "to another person or submit them on unverified forms."
        ),
        safe_recommendations=[
            "Never share an OTP, SMS code, or authenticator token with anyone, even if they claim to be support.",
            "Legitimate bank or customer representatives will never ask for your one-time verification code.",
            "If someone claims they sent you a code by mistake, do not forward it.",
        ],
    ),
    SocialEngineeringCategory.PAYMENT_REQUEST: CategoryMetadata(
        category=SocialEngineeringCategory.PAYMENT_REQUEST,
        display_name="Unsolicited Payment Request",
        description="Demands for immediate payments via UPI, wire, gift cards, or cryptocurrency.",
        default_severity="MEDIUM",
        why_it_matters=(
            "Scammers frequently use irreversible payment rails like cryptocurrency, gift cards, or "
            "instant peer-to-peer transfers to ensure stolen funds cannot be refunded or recalled."
        ),
        safe_recommendations=[
            "Never purchase gift cards, crypto, or transfer funds to fulfill an unsolicited urgent request.",
            "Verify any invoice or bill through known, verified institutional billing channels.",
        ],
    ),
    SocialEngineeringCategory.CREDENTIAL_THEFT: CategoryMetadata(
        category=SocialEngineeringCategory.CREDENTIAL_THEFT,
        display_name="Credential Harvesting / Phishing",
        description="Efforts to collect login usernames, passwords, security questions, PINs, or CVVs.",
        default_severity="CRITICAL",
        why_it_matters=(
            "Credential theft provides adversaries with persistent unauthorized access to your identity, "
            "emails, financial portals, and sensitive records."
        ),
        safe_recommendations=[
            "Never enter passwords or security answers on pages reached via unexpected message links.",
            "Always verify that the browser address bar matches the exact official domain before logging in.",
            "Enable multi-factor authentication (MFA) using authenticator apps or security keys.",
        ],
    ),
    SocialEngineeringCategory.IMPERSONATION: CategoryMetadata(
        category=SocialEngineeringCategory.IMPERSONATION,
        display_name="Brand or Executive Impersonation",
        description="Falsely adopting the identity, name, or branding of a trusted company, executive, or colleague.",
        default_severity="HIGH",
        why_it_matters=(
            "Adversaries exploit brand loyalty and institutional trust by mimicking well-known companies "
            "or authority figures to bypass natural user skepticism."
        ),
        safe_recommendations=[
            "Check the full email address or phone origin, not just the displayed sender name.",
            "Compare the sender domain against the verified official domain of the brand.",
        ],
    ),
    SocialEngineeringCategory.URGENCY: CategoryMetadata(
        category=SocialEngineeringCategory.URGENCY,
        display_name="Artificial Urgency & Countdown Pressure",
        description="Pressure tactics asserting immediate deadlines (e.g. 'within 2 hours', 'expires today').",
        default_severity="MEDIUM",
        why_it_matters=(
            "Urgency manipulates human cognitive biases, forcing quick decisions before you have time "
            "to reflect, verify facts, or consult trusted sources. Note: urgency alone does not prove fraud."
        ),
        safe_recommendations=[
            "Pause and take a step back when a message insists on immediate compliance.",
            "Legitimate urgent alerts can be reviewed safely by logging into the provider's official portal independently.",
        ],
    ),
    SocialEngineeringCategory.FEAR: CategoryMetadata(
        category=SocialEngineeringCategory.FEAR,
        display_name="Fear, Intimidation & Coercion",
        description="Intimidation through threats of arrest, lawsuits, account termination, or law enforcement action.",
        default_severity="HIGH",
        why_it_matters=(
            "Threats trigger anxiety and compliance. Scammers impersonate police, courts, tax agencies, "
            "or compliance departments to intimidate victims into compliance."
        ),
        safe_recommendations=[
            "Official government bodies and law enforcement rarely demand payments or threaten immediate arrest via SMS or email.",
            "Do not call numbers or click links provided within intimidating messages.",
        ],
    ),
    SocialEngineeringCategory.REWARD: CategoryMetadata(
        category=SocialEngineeringCategory.REWARD,
        display_name="Lottery, Prize & Reward Bait",
        description="Offers of unsolicited winnings, lottery windfalls, free luxury gifts, or bonus grants.",
        default_severity="HIGH",
        why_it_matters=(
            "Advance-fee fraud entices victims with substantial rewards, but demands personal details, "
            "passwords, or upfront 'handling/customs fees' before the fictitious prize can be claimed."
        ),
        safe_recommendations=[
            "If you did not enter a lottery or raffle, you have not won a prize.",
            "Never pay an advance fee or provide bank details to claim an unsolicited windfall.",
        ],
    ),
    SocialEngineeringCategory.DELIVERY_SCAM: CategoryMetadata(
        category=SocialEngineeringCategory.DELIVERY_SCAM,
        display_name="Courier & Postal Delivery Scam",
        description="Notifications of missing package addresses, customs surcharges, or failed shipments.",
        default_severity="HIGH",
        why_it_matters=(
            "Delivery scams take advantage of frequent online shopping habits. Attackers lure victims to "
            "credential-harvesting portals or micro-payment forms that steal credit card data."
        ),
        safe_recommendations=[
            "Track packages only through the official carrier website or app using your original tracking number.",
            "Do not pay small 'redelivery' or 'address update' fees via links in SMS or text messages.",
        ],
    ),
    SocialEngineeringCategory.BANKING_SCAM: CategoryMetadata(
        category=SocialEngineeringCategory.BANKING_SCAM,
        display_name="Banking & Financial Institution Impersonation",
        description="Fabricated security alerts, frozen account notifications, or debit alerts from banks.",
        default_severity="HIGH",
        why_it_matters=(
            "Banking scams exploit fear of financial loss. Victims are directed to counterfeit banking pages "
            "that capture customer IDs, netbanking passwords, and transactional OTPs."
        ),
        safe_recommendations=[
            "Call the official phone number printed on the back of your debit/credit card to confirm alerts.",
            "Banks will never ask for PINs, CVVs, or OTPs over text or email.",
        ],
    ),
    SocialEngineeringCategory.TECH_SUPPORT_SCAM: CategoryMetadata(
        category=SocialEngineeringCategory.TECH_SUPPORT_SCAM,
        display_name="Tech Support & System Virus Bait",
        description="Fabricated virus alerts, expired subscription notices, or toll-free support helplines.",
        default_severity="HIGH",
        why_it_matters=(
            "Tech support scams aim to trick users into calling bogus call centers, installing remote access "
            "tools (RATs), or purchasing expensive fake service renewals."
        ),
        safe_recommendations=[
            "Do not call telephone numbers displayed in unsolicited warning emails or popups.",
            "Never install remote management software (e.g. AnyDesk, TeamViewer) at the request of an unverified caller.",
        ],
    ),
    SocialEngineeringCategory.INVESTMENT_SCAM: CategoryMetadata(
        category=SocialEngineeringCategory.INVESTMENT_SCAM,
        display_name="High-Yield Investment / Crypto Scam",
        description="Promises of guaranteed, risk-free returns, cryptocurrency doubling, or insider trading tips.",
        default_severity="HIGH",
        why_it_matters=(
            "Investment scams present fictitious trading platforms and fabricated dashboards showing quick profits, "
            "only to withhold funds and demand escalating withdrawal fees."
        ),
        safe_recommendations=[
            "Guaranteed high returns with zero risk do not exist in legitimate financial markets.",
            "Verify all investment brokers against regulated national financial registries.",
        ],
    ),
    SocialEngineeringCategory.JOB_SCAM: CategoryMetadata(
        category=SocialEngineeringCategory.JOB_SCAM,
        display_name="Employment & Work-from-Home Scam",
        description="Unsolicited job offers with high pay for minimal work, requiring upfront registration fees.",
        default_severity="MEDIUM",
        why_it_matters=(
            "Fake recruiters collect identity documents for identity theft, or use victims as unwitting "
            "money mules to launder fraudulent funds."
        ),
        safe_recommendations=[
            "Legitimate employers do not ask candidates to pay for background checks or equipment upfront.",
            "Research the hiring organization through verified corporate career pages.",
        ],
    ),
    SocialEngineeringCategory.ROMANCE_SCAM: CategoryMetadata(
        category=SocialEngineeringCategory.ROMANCE_SCAM,
        display_name="Romance & Relationship Manipulation",
        description="Cultivating emotional bonds followed by emergency financial requests or gift solicitations.",
        default_severity="MEDIUM",
        why_it_matters=(
            "Romance fraudsters spend weeks establishing trust before fabricating emergencies (medical bills, "
            "travel costs, customs hold-ups) requiring urgent wire transfers."
        ),
        safe_recommendations=[
            "Never send money, cryptocurrency, or gift cards to someone you have never met in person.",
            "Conduct reverse-image checks on photos shared by individuals met on social platforms.",
        ],
    ),
    SocialEngineeringCategory.GOVERNMENT_IMPERSONATION: CategoryMetadata(
        category=SocialEngineeringCategory.GOVERNMENT_IMPERSONATION,
        display_name="Government Agency Impersonation",
        description="Impersonating statutory regulators, police, customs, court officials, or ministries.",
        default_severity="HIGH",
        why_it_matters=(
            "Government impersonators exploit fear of administrative sanctions, fines, or criminal prosecution "
            "to extract compliance and extortionate payments."
        ),
        safe_recommendations=[
            "Government departments do not initiate enforcement actions or demand fees via WhatsApp or SMS.",
            "Check official government (.gov or official national TLD) portals directly.",
        ],
    ),
    SocialEngineeringCategory.TAX_SCAM: CategoryMetadata(
        category=SocialEngineeringCategory.TAX_SCAM,
        display_name="Tax Authority & Refund Scam",
        description="Fabricated tax rebates, audit notifications, or overdue tax liabilities from revenue agencies.",
        default_severity="HIGH",
        why_it_matters=(
            "Tax scams promise unexpected tax refunds or threaten warrants for unpaid liabilities, "
            "aiming to collect bank credentials or national identity numbers."
        ),
        safe_recommendations=[
            "Log in directly to your official national tax portal to check for legitimate notices.",
            "Tax authorities never demand payment via prepaid cards, wire transfers, or crypto.",
        ],
    ),
    SocialEngineeringCategory.REFUND_SCAM: CategoryMetadata(
        category=SocialEngineeringCategory.REFUND_SCAM,
        display_name="Fake Refund & Overcharge Scam",
        description="Claims of accidental overcharges or entitlement to refunds, requiring processing fees.",
        default_severity="HIGH",
        why_it_matters=(
            "The victim is told an erroneous charge occurred and is instructed to download software or "
            "pay a 'processing fee' to receive their money back."
        ),
        safe_recommendations=[
            "Verify real charges on your card or bank statement before reacting to refund claims.",
            "Do not allow callers to connect remotely to your computer to 'process a refund'.",
        ],
    ),
    SocialEngineeringCategory.MALICIOUS_DOWNLOAD: CategoryMetadata(
        category=SocialEngineeringCategory.MALICIOUS_DOWNLOAD,
        display_name="Malicious Attachment or Executable Lure",
        description="Luring recipients into downloading and running suspicious binaries, APKs, scripts, or archives.",
        default_severity="CRITICAL",
        why_it_matters=(
            "Executable files, malicious mobile APKs, and macro-enabled documents can execute arbitrary code, "
            "install spyware, or compromise your entire device."
        ),
        safe_recommendations=[
            "Do not open unexpected attachments, especially with extensions like .exe, .apk, .scr, or .vbs.",
            "Inspect archive attachments with security tooling before extracting contents.",
        ],
    ),
    SocialEngineeringCategory.MALICIOUS_LINK: CategoryMetadata(
        category=SocialEngineeringCategory.MALICIOUS_LINK,
        display_name="Deceptive or Phishing Hyperlink",
        description="Links directing users to lookalike domains, unverified shorteners, or spoofed destinations.",
        default_severity="HIGH",
        why_it_matters=(
            "Misleading links often appear authentic in text, but direct victims to deceptive credential "
            "harvesters or malware drop sites."
        ),
        safe_recommendations=[
            "Inspect the true destination domain, particularly when displayed text shows a different website.",
            "Avoid entering sensitive data on unverified shortened URLs.",
        ],
    ),
    SocialEngineeringCategory.OTHER: CategoryMetadata(
        category=SocialEngineeringCategory.OTHER,
        display_name="Other Social Engineering Indicator",
        description="Other anomalous behavioral manipulation or unclassified deceptive pattern.",
        default_severity="INFO",
        why_it_matters=(
            "Adversaries continuously innovate new deceptive angles that combine multiple subtle signals."
        ),
        safe_recommendations=[
            "Exercise general cyber caution and independently verify unexpected communications.",
        ],
    ),
}


def get_category_metadata(category: SocialEngineeringCategory) -> CategoryMetadata:
    """Retrieve metadata, why it matters, and safe recommendations for a category."""
    return TAXONOMY_REGISTRY.get(category, TAXONOMY_REGISTRY[SocialEngineeringCategory.OTHER])
