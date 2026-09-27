"""
ScamBuster AI Cybersecurity Assistant Service
Provides contextual scam triage, indicator extraction, threat intelligence lookups,
social engineering analysis, and actionable security guidance.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple
import urllib.request
import urllib.error
from urllib.parse import urlparse

from app.config.settings import settings
from app.schemas.chat import (
    ChatExtractedIndicator,
    ChatMessage,
    ChatRequest,
    ChatResponse,
    ChatSuggestedAction,
    ChatTriageResult,
)
from app.services.message_analysis.normalizer import normalize_message_input
from app.services.social_engineering_rules import evaluate_social_engineering_rules
from app.intelligence.feeds.catalog import get_local_feed_catalog
from app.intelligence.models import IndicatorType
from app.ml.message_inference import get_message_model_manager

logger = logging.getLogger("scambuster.assistant")


URL_REGEX = re.compile(
    r"(?:https?://|hxxps?://|[a-zA-Z0-9-]+\.(?:com|org|net|xyz|top|ru|cn|cc|info|biz|tk|ml|ga|cf|gq|io|dev|app|online|site|live|shop|vip|pw|link|click|work|icu|cam|stream)/?)[^\s<>\"'{}|\\^`]*",
    re.IGNORECASE,
)

EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
    re.IGNORECASE,
)

PHONE_REGEX = re.compile(
    r"(?:\+?\d{1,4}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"
)

# Common scam & security intent triggers
TRIAGE_KEYWORDS = {
    "urgent", "immediately", "deadline", "suspended", "blocked", "locked", "freeze",
    "otp", "pin", "password", "verify", "verification", "kyc", "bank", "account",
    "lottery", "winner", "won", "prize", "gift card", "reward", "crypto", "bitcoin",
    "refund", "customs", "delivery", "package", "parcel", "fedex", "dhl", "usps",
    "police", "arrest", "warrant", "court", "lawsuit", "irs", "cbi", "tax",
    "wire", "western union", "gift cards", "apk", "install", "anydesk", "teamviewer"
}

EMERGENCY_PATTERNS = [
    re.compile(r"\b(?:gave|shared|sent|provided|disclosed)\s+(?:my\s+|the\s+)?(?:otp|pin|password|passcode|code|cvv|credentials)\b", re.IGNORECASE),
    re.compile(r"\b(?:transferred|sent|paid|wired)\s+(?:(?:some|the|my)\s+)?(?:money|funds|cash|crypto|bitcoin|gift\s*cards?)\b", re.IGNORECASE),
    re.compile(r"\b(?:i\s+)?(?:got|was|been)\s+(?:scammed|defrauded|duped|tricked)\b", re.IGNORECASE),
    re.compile(r"\b(?:fell\s+for|clicked\s+on\s+a\s+scam|money\s+deducted|unauthorized\s+transaction)\b", re.IGNORECASE),
    re.compile(r"\b(?:account|card|phone)\s+(?:is\s+)?(?:compromised|hacked|taken\s+over)\b", re.IGNORECASE),
]


class AIAssistantService:
    """
    AI Cybersecurity Assistant delivering expert scam analysis,
    real-time threat classification, and emergency response workflows.
    """

    def __init__(self):
        self.catalog = get_local_feed_catalog()

    def extract_indicators(self, text: str) -> List[ChatExtractedIndicator]:
        """Extract URLs, emails, and phone numbers from user prompt."""
        indicators: List[ChatExtractedIndicator] = []
        seen = set()

        # Extract URLs
        for match in URL_REGEX.finditer(text):
            raw_url = match.group(0).rstrip(".,;:!?)")
            if len(raw_url) > 4 and raw_url not in seen:
                seen.add(raw_url)
                canonical_url = raw_url.replace("hxxp://", "http://").replace("hxxps://", "https://")
                if not canonical_url.startswith("http"):
                    canonical_url = f"http://{canonical_url}"
                
                # Check threat intel catalog
                match_record = self.catalog.lookup(IndicatorType.URL, canonical_url)
                if match_record:
                    risk_score = 95
                    risk_level = "CRITICAL"
                else:
                    risk_score = 45 if any(k in canonical_url.lower() for k in ["login", "verify", "secure", "bank", "update"]) else 15
                    risk_level = "HIGH" if risk_score >= 40 else "LOW"
                
                indicators.append(
                    ChatExtractedIndicator(
                        type="url",
                        value=canonical_url,
                        risk_score=risk_score,
                        risk_level=risk_level,
                    )
                )

        # Extract Emails
        for match in EMAIL_REGEX.finditer(text):
            email_val = match.group(0)
            if email_val not in seen:
                seen.add(email_val)
                domain = email_val.split("@")[-1]
                match_record = self.catalog.lookup(IndicatorType.DOMAIN, domain)
                risk_score = 90 if match_record else 20
                risk_level = "HIGH" if match_record else "SAFE"
                indicators.append(
                    ChatExtractedIndicator(
                        type="email",
                        value=email_val,
                        risk_score=risk_score,
                        risk_level=risk_level,
                    )
                )

        # Extract Phones (avoid pure numbers of length < 7)
        for match in PHONE_REGEX.finditer(text):
            phone_val = match.group(0).strip()
            digits = re.sub(r"\D", "", phone_val)
            if len(digits) >= 10 and phone_val not in seen:
                seen.add(phone_val)
                match_record = self.catalog.lookup(IndicatorType.PHONE, phone_val)
                if match_record:
                    risk_score = 95
                    risk_level = "CRITICAL"
                else:
                    risk_score = 50 if (digits.startswith("1800") or digits.startswith("800") or len(digits) > 12) else 25
                    risk_level = "MEDIUM" if risk_score >= 50 else "LOW"
                indicators.append(
                    ChatExtractedIndicator(
                        type="phone",
                        value=phone_val,
                        risk_score=risk_score,
                        risk_level=risk_level,
                    )
                )

        return indicators

    def _query_gemini(
        self,
        user_message: str,
        history: List[ChatMessage],
        telemetry_context: str,
    ) -> Optional[str]:
        """Query Gemini API with conversation history and ScamBuster telemetry."""
        api_key = settings.GEMINI_API_KEY or os.getenv("GEMINI_API_KEY")
        if not api_key:
            return None

        system_instruction = (
            "You are ScamBuster AI, an expert cybersecurity assistant and scam triage specialist for the ScamBuster platform.\n"
            "Your objective: Protect users from scams, phishing, smishing, vishing, malware, APK risks, and digital fraud.\n"
            "Style: Calm, empathetic, authoritative, and security-first. Never blame the victim.\n"
            "Rules:\n"
            "1. If an emergency or loss of credentials/funds occurred, immediately advise freezing cards/accounts, changing passwords, and reporting to authorities (1930 in India, IC3/FTC in US).\n"
            "2. If analyzing suspicious text, explain the manipulation tactics (urgency, intimidation, credential lures).\n"
            "3. Reference ScamBuster scanners (/scan/url, /scan/message, /scan/email, /scan/phone, /scan/apk) when relevant.\n"
            "4. Format your response cleanly in markdown with headings (###, ####), bullet points, and numbered action lists."
        )

        contents = []
        for msg in history[-6:]:
            role = "user" if msg.role == "user" else "model"
            contents.append({"role": role, "parts": [{"text": msg.content}]})

        full_prompt = f"{user_message}\n\n{telemetry_context}"
        contents.append({"role": "user", "parts": [{"text": full_prompt}]})

        payload = {
            "system_instruction": {"parts": [{"text": system_instruction}]},
            "contents": contents,
            "generationConfig": {
                "temperature": 0.4,
                "topP": 0.95,
                "maxOutputTokens": 1024,
            },
        }

        candidate_models = ["gemini-3.5-flash-lite", "gemini-3.1-flash-lite", "gemini-flash-latest", "gemini-3.5-flash"]
        for model in candidate_models:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
            try:
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text")
                        if text and len(text.strip()) > 10:
                            return text.strip()
            except Exception as e:
                logger.warning("Gemini query with model %s failed: %s", model, e)
                continue

        return None

    def handle_chat(self, request: ChatRequest) -> ChatResponse:
        """Process incoming chat query and return expert cybersecurity guidance."""
        raw_message = request.message.strip()
        norm_result = normalize_message_input(raw_message)
        clean_text = norm_result.normalized_text
        lower_clean = clean_text.lower()

        # Extract indicators
        indicators = self.extract_indicators(raw_message)

        # Check for emergency victim scenario
        is_emergency = any(pat.search(clean_text) for pat in EMERGENCY_PATTERNS)

        # Check for message / scam triage scenario
        has_triage_clues = any(kw in lower_clean for kw in TRIAGE_KEYWORDS) or len(indicators) > 0

        # Build local baseline response
        if is_emergency:
            base_response = self._build_emergency_response(indicators)
        elif has_triage_clues and len(clean_text) > 15:
            base_response = self._build_triage_response(raw_message, clean_text, indicators)
        elif any(w in lower_clean for w in ["how to use", "how do i scan", "apk scanner", "url scanner", "phone scanner", "email scanner", "features", "what can you do"]):
            base_response = self._build_navigation_response()
        else:
            base_response = self._build_educational_response(lower_clean, indicators)

        # Query Gemini API with ScamBuster telemetry
        telemetry_context = (
            f"[ScamBuster Local Security Context]:\n"
            f"- Extracted Indicators: {[f'{ind.type.upper()}: {ind.value} (Risk: {ind.risk_level})' for ind in indicators]}\n"
            f"- Heuristic Triage: {base_response.triage.risk_level if base_response.triage else 'SAFE'} "
            f"({base_response.triage.scam_category if base_response.triage else 'None'})\n"
            f"- Red Flags: {base_response.triage.red_flags if base_response.triage else []}\n"
            f"- Emergency Detected: {is_emergency}"
        )

        gemini_reply = self._query_gemini(raw_message, request.history, telemetry_context)
        if gemini_reply:
            base_response.reply = gemini_reply

        return base_response

    def _build_emergency_response(self, indicators: List[ChatExtractedIndicator]) -> ChatResponse:
        """Immediate incident containment protocol when a user indicates they were compromised."""
        reply = (
            "### 🚨 Immediate Incident Containment Protocol\n\n"
            "If you suspect you have fallen victim to a scam, **act immediately to minimize financial and account loss**:\n\n"
            "1. **Freeze Bank & Card Accounts Immediately**:\n"
            "   - Call your bank or card issuer's emergency fraud line (usually on the back of your physical card or official app).\n"
            "   - Request an immediate block on transactions, net banking, and cards.\n"
            "   - Ask for a **Fraud Transaction Dispute / Chargeback** reference number.\n\n"
            "2. **Secure Your Credentials & Active Sessions**:\n"
            "   - Log into your primary email and banking accounts from a known secure, clean device.\n"
            "   - Change your passwords immediately to strong, unique passphrases.\n"
            "   - Select **'Log out of all other sessions/devices'**.\n"
            "   - Enable Multi-Factor Authentication using an **Authenticator App (TOTP)** rather than SMS.\n\n"
            "3. **If You Downloaded an APK or Software**:\n"
            "   - Turn off Wi-Fi and Mobile Data immediately (Airplane Mode).\n"
            "   - Boot into Android Safe Mode or inspect installed apps to uninstall the malicious application.\n"
            "   - Revoke Device Administrator and Accessibility permissions.\n\n"
            "4. **Report to Cybercrime Authorities**:\n"
            "   - **India**: Call **1930** (Citizen Financial Cyber Fraud Reporting) or visit [cybercrime.gov.in](https://cybercrime.gov.in).\n"
            "   - **United States**: File an IC3 report at [ic3.gov](https://www.ic3.gov) and report to the FTC at [reportfraud.ftc.gov](https://reportfraud.ftc.gov).\n"
            "   - **International**: Report to your national CERT or local law enforcement fraud division.\n\n"
            "Keep all SMS messages, emails, transaction IDs, and call logs as evidence."
        )

        triage = ChatTriageResult(
            has_threat_detected=True,
            risk_level="CRITICAL",
            scam_category="Active Account Compromise / Post-Scam Incident",
            confidence=0.98,
            emergency_actions=[
                "Freeze bank cards & notify fraud department immediately",
                "Change passwords and terminate all remote active sessions",
                "Disconnect Wi-Fi/Mobile Data if suspicious software was installed",
                "File official report with national cybercrime portal (1930 / IC3.gov)",
            ],
            red_flags=[
                "Unauthorized financial transaction initiated",
                "Credentials or one-time passcodes disclosed to third party",
                "Potential account takeover or remote access compromise",
            ],
        )

        suggested_actions = [
            ChatSuggestedAction(label="Scan Phone Number", action_type="navigate", target="/scan/phone"),
            ChatSuggestedAction(label="Scan Suspicious URL", action_type="navigate", target="/scan/url"),
            ChatSuggestedAction(label="Audit APK Security", action_type="navigate", target="/scan/apk"),
        ]

        suggested_prompts = [
            "How do I remove a malicious APK from my phone?",
            "What should I tell my bank's fraud department?",
            "How can I tell if my email was compromised?",
        ]

        return ChatResponse(
            reply=reply,
            indicators=indicators,
            triage=triage,
            suggested_prompts=suggested_prompts,
            suggested_actions=suggested_actions,
        )

    def _build_triage_response(
        self,
        raw_text: str,
        clean_text: str,
        indicators: List[ChatExtractedIndicator]
    ) -> ChatResponse:
        """Perform triage and explain detected deception vectors in user text."""
        findings = evaluate_social_engineering_rules(clean_text)
        
        # Check ML model prediction
        ml_prediction = "benign"
        ml_score = 0.0
        try:
            msg_mgr = get_message_model_manager()
            if msg_mgr and msg_mgr.is_loaded():
                ml_res = msg_mgr.predict(clean_text)
                ml_prediction = ml_res.get("prediction", "benign")
                ml_score = ml_res.get("probability", 0.0)
        except Exception:
            pass

        # Calculate triage risk
        max_score = 0
        categories_found = []
        red_flags = []
        recommendations = []

        for f in findings:
            max_score = max(max_score, f.score_weight)
            categories_found.append(f.name)
            red_flags.append(f"{f.name}: {f.evidence}")
            recommendations.extend(f.safe_recommendations)

        for ind in indicators:
            if ind.risk_score:
                max_score = max(max_score, ind.risk_score)
            if ind.risk_level in ["CRITICAL", "HIGH"]:
                red_flags.append(f"High-Risk Indicator: {ind.type.upper()} '{ind.value}' matches known threat parameters.")

        if ml_prediction in ["scam", "spam"] and ml_score > 0.6:
            max_score = max(max_score, int(ml_score * 100))
            red_flags.append(f"Statistical NLP Classifier: High scam linguistic similarity ({ml_score:.1%}).")

        # Determine level
        if max_score >= 80:
            risk_tier = "CRITICAL"
            badge = "🔴 **CRITICAL RISK SCAM DETECTED**"
        elif max_score >= 50:
            risk_tier = "HIGH"
            badge = "🟠 **HIGH RISK SUSPICIOUS MESSAGE**"
        elif max_score >= 25:
            risk_tier = "MEDIUM"
            badge = "🟡 **ELEVATED CAUTION ADVISED**"
        else:
            risk_tier = "LOW"
            badge = "🟢 **NO IMMEDIATE HIGH-RISK THREATS DETECTED**"

        primary_cat = categories_found[0] if categories_found else ("Phishing / Social Engineering" if indicators else "Suspicious Message")

        # Construct markdown reply
        reply_lines = [
            f"### {badge}",
            f"**Primary Pattern:** {primary_cat}  ",
            f"**Triage Score:** {max_score}/100 ({risk_tier})\n",
            "#### 🔍 Red Flag Analysis:",
        ]

        if red_flags:
            for rf in red_flags[:5]:
                reply_lines.append(f"- {rf}")
        else:
            reply_lines.append("- No overt urgent threats or credential solicitations were identified in the text snippet.")

        if indicators:
            reply_lines.append("\n#### 🎯 Extracted Indicators:")
            for ind in indicators:
                status_icon = "⚠️" if ind.risk_level in ["CRITICAL", "HIGH"] else "ℹ️"
                reply_lines.append(f"- {status_icon} **{ind.type.upper()}**: `{ind.value}` (Risk: {ind.risk_level})")

        reply_lines.append("\n#### 🛡️ Recommended Security Actions:")
        unique_recs = list(dict.fromkeys(recommendations))[:4] if recommendations else [
            "Never share OTPs, passwords, or PINs with unsolicited callers or senders.",
            "Verify the communication independently via official channels, not via numbers in the message.",
            "Do not click unverified links or download unexpected attachments.",
        ]
        for rec in unique_recs:
            reply_lines.append(f"1. {rec}")

        triage = ChatTriageResult(
            has_threat_detected=max_score >= 40,
            risk_level=risk_tier,
            scam_category=primary_cat,
            confidence=0.92,
            emergency_actions=unique_recs,
            red_flags=red_flags[:5],
        )

        suggested_actions = []
        for ind in indicators:
            if ind.type == "url":
                suggested_actions.append(
                    ChatSuggestedAction(label=f"Scan URL ({ind.value[:20]}...)", action_type="scan", target=f"/scan/url?url={ind.value}")
                )
            elif ind.type == "phone":
                suggested_actions.append(
                    ChatSuggestedAction(label=f"Scan Phone ({ind.value})", action_type="scan", target=f"/scan/phone?phone={ind.value}")
                )

        if not suggested_actions:
            suggested_actions = [
                ChatSuggestedAction(label="Deep Message Scanner", action_type="navigate", target="/scan/message"),
                ChatSuggestedAction(label="Verify URL Safety", action_type="navigate", target="/scan/url"),
            ]

        suggested_prompts = [
            "What if I already clicked the link?",
            "Why would a legitimate bank never ask for an OTP?",
            "How do scammers fake phone caller IDs?",
        ]

        return ChatResponse(
            reply="\n".join(reply_lines),
            indicators=indicators,
            triage=triage,
            suggested_prompts=suggested_prompts,
            suggested_actions=suggested_actions,
        )

    def _build_navigation_response(self) -> ChatResponse:
        """Provide guidance on using ScamBuster's scanners."""
        reply = (
            "### 🛡️ Welcome to ScamBuster Security Platform\n\n"
            "ScamBuster provides five specialized, defense-in-depth scanners combining heuristic rules, AI/ML models, and threat intelligence:\n\n"
            "1. **🌐 URL & Website Scanner** (`/scan/url`)\n"
            "   - Evaluates links for phishing, IP hostnames, typosquatting, redirect chains, credential-harvesting forms, and downloads.\n\n"
            "2. **💬 Message & SMS Scanner** (`/scan/message`)\n"
            "   - Decodes multilingual leetspeak, strips zero-width obfuscation, extracts embedded links, and predicts scam intent.\n\n"
            "3. **📧 Email & Phishing Scanner** (`/scan/email`)\n"
            "   - Audits MIME headers, SPF/DKIM/DMARC authentication, display-name spoofing, deceptive anchors, and supports direct `.eml` uploads.\n\n"
            "4. **📞 Phone Number Intelligence** (`/scan/phone`)\n"
            "   - E.164 normalization, carrier analysis, entropy profiling, sequential runs, and Wangiri/toll fraud detection.\n\n"
            "5. **📦 Android APK Scanner** (`/scan/apk`)\n"
            "   - Static manifest inspection, 152 AOSP permission catalog, Dalvik bytecode correlation, toxic permission combos, and privacy audits.\n\n"
            "Select an action below or paste any suspicious text here to begin immediate analysis!"
        )

        suggested_actions = [
            ChatSuggestedAction(label="Scan a URL", action_type="navigate", target="/scan/url"),
            ChatSuggestedAction(label="Scan an SMS / Message", action_type="navigate", target="/scan/message"),
            ChatSuggestedAction(label="Scan an Email", action_type="navigate", target="/scan/email"),
            ChatSuggestedAction(label="Scan a Phone Number", action_type="navigate", target="/scan/phone"),
            ChatSuggestedAction(label="Audit an Android APK", action_type="navigate", target="/scan/apk"),
        ]

        suggested_prompts = [
            "How does ScamBuster protect against SSRF?",
            "What are toxic Android permission combinations?",
            "How does Threat Intelligence correlation work?",
        ]

        return ChatResponse(
            reply=reply,
            indicators=[],
            triage=None,
            suggested_prompts=suggested_prompts,
            suggested_actions=suggested_actions,
        )

    def _build_educational_response(
        self,
        lower_text: str,
        indicators: List[ChatExtractedIndicator]
    ) -> ChatResponse:
        """Provide informative cybersecurity answers to general questions."""
        if any(w in lower_text for w in ["phishing", "fake email", "spoof"]):
            reply = (
                "### 🎣 Understanding Phishing Attacks\n\n"
                "**Phishing** is a social engineering technique where attackers impersonate reputable organizations "
                "(banks, delivery companies, government agencies, streaming services) to steal credentials or payment data.\n\n"
                "#### Common Red Flags:\n"
                "- **Generic Greetings**: 'Dear Customer' instead of your actual registered name.\n"
                "- **Sender Mismatch**: The display name says 'PayPal Security', but the underlying email is `@random-mail.xyz`.\n"
                "- **Hyperlink Deception**: The displayed text says `https://chase.com`, but the actual href leads to `https://chase-update-login.top`.\n"
                "- **Artificial Urgency**: Demands that you act within 24 hours or face account suspension or legal action.\n\n"
                "**Pro-Tip**: You can use ScamBuster's [Email Scanner](/scan/email) to inspect raw RFC-822 headers and `.eml` files safely!"
            )
        elif any(w in lower_text for w in ["otp", "verification code", "2fa"]):
            reply = (
                "### 🔐 The Golden Rule of One-Time Passwords (OTPs)\n\n"
                "> **Legitimate organizations, banks, credit card issuers, and technical support will NEVER ask you to disclose an OTP over the phone, SMS, or email.**\n\n"
                "#### How OTP Theft Scams Work:\n"
                "1. Attackers obtain your phone number and password from a data breach.\n"
                "2. They trigger a password reset or bank transfer on your real account, which prompts your bank to send an OTP to your phone.\n"
                "3. The scammer calls or texts you claiming to be 'Fraud Protection' or 'Customer Support' preventing an unauthorized charge.\n"
                "4. They ask you to 'read back the verification code to cancel the charge'.\n"
                "5. The moment you give them the code, **you authorize their transaction**.\n\n"
                "**Action**: Never share verification codes with anyone, under any circumstances."
            )
        elif any(w in lower_text for w in ["apk", "android", "malware", "app"]):
            reply = (
                "### 📱 Mobile Security & Android APK Risks\n\n"
                "Android apps distributed outside official stores (Google Play, F-Droid) via direct `.apk` downloads "
                "are the primary delivery vector for **Banking Trojans** (Cerberus, FluBot, SharkBot) and **Spyware** (SpyNote).\n\n"
                "#### Toxic Permission Patterns to Watch For:\n"
                "- **Accessibility Services**: Allows malware to read all screen content, log keystrokes, and click buttons without your consent.\n"
                "- **SMS Permissions** (`RECEIVE_SMS`, `READ_SMS`): Used by banking trojans to silently intercept OTP codes.\n"
                "- **System Alert Window** (`SYSTEM_ALERT_WINDOW`): Draws fake phishing overlay login screens over your genuine banking apps.\n"
                "- **Device Admin** (`BIND_DEVICE_ADMIN`): Prevents the user from uninstalling the malicious app.\n\n"
                "**Action**: Upload any suspicious APK to ScamBuster's [APK Scanner](/scan/apk) for static manifest and Dalvik bytecode analysis!"
            )
        else:
            reply = (
                "### 🛡️ ScamBuster AI Cybersecurity Assistant\n\n"
                "I am your dedicated digital fraud triage assistant. I can help you evaluate suspicious communications, "
                "detect social engineering tactics, check URLs and phone numbers, and guide you through security incidents.\n\n"
                "**What would you like assistance with?**\n"
                "- Paste a suspicious SMS, email, or message for instant AI risk triage.\n"
                "- Ask about specific threats (phishing, fake APKs, OTP scams, robocalls).\n"
                "- Inquire about emergency steps if you suspect your account has been compromised."
            )

        suggested_prompts = [
            "What should I do if someone called asking for my bank details?",
            "How do I recognize a fake package delivery text?",
            "Can a website hack me just by visiting it?",
            "How do I check if an APK has hidden spyware?",
        ]

        suggested_actions = [
            ChatSuggestedAction(label="Scan a Message", action_type="navigate", target="/scan/message"),
            ChatSuggestedAction(label="Scan a URL", action_type="navigate", target="/scan/url"),
            ChatSuggestedAction(label="Scan a Phone Number", action_type="navigate", target="/scan/phone"),
        ]

        return ChatResponse(
            reply=reply,
            indicators=indicators,
            triage=None,
            suggested_prompts=suggested_prompts,
            suggested_actions=suggested_actions,
        )


_assistant_service: Optional[AIAssistantService] = None


def get_ai_assistant_service() -> AIAssistantService:
    global _assistant_service
    if _assistant_service is None:
        _assistant_service = AIAssistantService()
    return _assistant_service
