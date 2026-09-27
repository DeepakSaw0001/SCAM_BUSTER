"""
ScamBuster — Message Normalizer & Anti-Obfuscation Service (Phase 10)

Handles:
1. Text normalization: Unicode NFKC, whitespace collapsing, casing preservation.
2. Anti-evasion / obfuscation normalization:
   - De-spacing spaced scam words (e.g. "O T P" -> "OTP", "v e r i f y" -> "verify")
   - De-obfuscating leetspeak (e.g. "v3rify your acc0unt", "sh0rtly exp1res")
   - De-obfuscating defanged URLs (e.g. "hxxps://example[.]com", "www[dot]domain[dot]com")
   - Handling Unicode homoglyphs while preserving raw text as ground-truth evidence.
3. Language detection: English, Hindi, Marathi, Hinglish, with fallback to 'unknown'.
4. Entity extraction: URLs, phone numbers, emails.
"""

from dataclasses import dataclass, field
import re
import string
import unicodedata
from typing import Any, Dict, List, Optional, Set, Tuple


# Defanged URL patterns
DEFANGED_URL_PATTERNS = [
    (re.compile(r"hxxps?://", re.IGNORECASE), lambda m: "https://" if "hxxps" in m.group(0).lower() else "http://"),
    (re.compile(r"\[\.\]|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[:\]|\[colon\]", re.IGNORECASE), ":"),
    (re.compile(r"\[/\]|\[slash\]", re.IGNORECASE), "/"),
]

# Standard URL regex
URL_REGEX = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>{}\"\'\[\]`]+",
    re.IGNORECASE
)

# Email regex
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# Phone number regex
PHONE_REGEX = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b"
)

# Common spaced scam keywords to de-space
SPACED_KEYWORDS = [
    r"\bO\s+T\s+P\b",
    r"\bU\s+P\s+I\b",
    r"\bP\s+I\s+N\b",
    r"\bC\s+V\s+V\b",
    r"\bv\s+e\s+r\s+i\s+f\s+y\b",
    r"\bs\s+u\s+s\s+p\s+e\s+n\s+d\s+e\s+d\b",
    r"\bu\s+r\s+g\s+e\s+n\s+t\b",
    r"\bl\s+o\s+g\s+i\s+n\b",
    r"\bp\s+a\s+s\s+s\s+w\s+o\s+r\s+d\b",
    r"\bw\s+i\s+n\s+n\s+e\s+r\b",
    r"\bc\s+l\s+a\s+i\s+m\b",
]

# Leetspeak translation dictionary for evasion detection
LEET_REPLACEMENTS = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"
}

# Devanagari script range for Hindi/Marathi
DEVANAGARI_RANGE = range(0x0900, 0x097F + 1)

# Marathi specific vocabulary / morphemes
MARATHI_MARKERS = {
    "आहे", "नाही", "करा", "खाते", "पैसे", "तात्काळ", "संदेश", "क्रमांक", "मिळाले", "झाले", "कृपया", "करावे"
}

# Hindi specific vocabulary / morphemes
HINDI_MARKERS = {
    "है", "नहीं", "करें", "खाता", "पैसे", "तुरंत", "संदेश", "नंबर", "मिला", "गया", "कृपया", "करें"
}

# Hinglish markers (Hindi in Latin script)
HINGLISH_MARKERS = {
    "karo", "kare", "karna", "aapka", "apna", "khata", "paisa", "paise", "turant",
    "bhejo", "band", "ho", "gaya", "hai", "nahi", "kripya", "namaskar", "shukriya"
}


@dataclass
class NormalizedMessageData:
    original_text: str
    normalized_text: str  # NFKC, whitespace collapsed, de-spaced
    cleaned_for_ml: str   # Lowercase, punctuation/entity stripped for TF-IDF
    detected_language: str
    language_confidence: float
    obfuscation_detected: bool
    obfuscation_details: List[str]
    extracted_urls: List[str]
    extracted_phones: List[str]
    extracted_emails: List[str]
    char_count: int
    word_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected_language": self.detected_language,
            "language_confidence": self.language_confidence,
            "obfuscation_detected": self.obfuscation_detected,
            "obfuscation_details": self.obfuscation_details,
            "extracted_urls": self.extracted_urls,
            "extracted_phones": self.extracted_phones,
            "extracted_emails": self.extracted_emails,
            "char_count": self.char_count,
            "word_count": self.word_count,
        }


def deobfuscate_urls_in_text(text: str) -> Tuple[str, bool]:
    """Replace defanged URL structures (e.g. hxxps://, [.], [dot]) with standard syntax."""
    res = text
    modified = False
    for pat, repl in DEFANGED_URL_PATTERNS:
        if pat.search(res):
            res = pat.sub(repl, res)
            modified = True
    return res, modified


def deobfuscate_spaced_keywords(text: str) -> Tuple[str, List[str]]:
    """Detect and collapse spaced keywords (e.g. 'O T P' -> 'OTP')."""
    res = text
    found_obfuscations: List[str] = []
    for pattern in SPACED_KEYWORDS:
        matches = list(re.finditer(pattern, res, re.IGNORECASE))
        for m in matches:
            orig = m.group(0)
            collapsed = re.sub(r"\s+", "", orig)
            res = res.replace(orig, collapsed)
            found_obfuscations.append(f"Spaced letter evasion: '{orig}' -> '{collapsed}'")
    return res, found_obfuscations


def normalize_leetspeak_word(word: str) -> Tuple[str, bool]:
    """Substitute numbers in words that resemble evasion (e.g. v3rify -> verify)."""
    # Only translate if word has letters AND leet digits/symbols
    has_letters = any(c.isalpha() for c in word)
    has_leet = any(c in LEET_REPLACEMENTS for c in word)
    if has_letters and has_leet:
        translated = "".join(LEET_REPLACEMENTS.get(c.lower(), c) for c in word)
        return translated, True
    return word, False


def detect_language(text: str) -> Tuple[str, float]:
    """
    Detect message language: English, Hindi, Marathi, Hinglish, or unknown.
    Uses script inspection and token matching.
    """
    if not text.strip():
        return "unknown", 0.0

    devanagari_chars = sum(1 for c in text if ord(c) in DEVANAGARI_RANGE)
    total_alpha = sum(1 for c in text if c.isalpha())

    # 1. Script is predominantly Devanagari -> Hindi or Marathi
    if total_alpha > 0 and (devanagari_chars / total_alpha) > 0.4:
        tokens = set(text.split())
        marathi_hits = len(tokens & MARATHI_MARKERS)
        hindi_hits = len(tokens & HINDI_MARKERS)
        if marathi_hits > hindi_hits:
            return "Marathi", 0.90
        elif hindi_hits > 0 or devanagari_chars > 5:
            return "Hindi", 0.90
        return "Hindi", 0.75

    # 2. Latin script -> Check Hinglish vs English
    lower_words = set(re.findall(r"\b[a-z]{2,}\b", text.lower()))
    hinglish_hits = len(lower_words & HINGLISH_MARKERS)
    if hinglish_hits >= 2:
        return "Hinglish", 0.85

    # Check for basic English ascii
    ascii_alpha = sum(1 for c in text if c.isascii() and c.isalpha())
    if total_alpha > 0 and (ascii_alpha / total_alpha) > 0.8:
        return "English", 0.95

    return "unknown", 0.50


def normalize_message_input(raw_text: str) -> NormalizedMessageData:
    """
    Execute comprehensive normalization and entity extraction on raw communication text.
    Preserves original text intact for evidence.
    """
    if not isinstance(raw_text, str):
        raw_text = str(raw_text or "")

    original = raw_text.strip()
    obfuscation_details: List[str] = []

    # 1. Unicode NFKC normalization (collapses homoglyphs, full-width chars)
    nfkc_text = unicodedata.normalize("NFKC", original)

    # 2. Defanged URL handling
    deobf_url_text, urls_deobfuscated = deobfuscate_urls_in_text(nfkc_text)
    if urls_deobfuscated:
        obfuscation_details.append("Defanged URL obfuscation (e.g. hxxp or [.] notation) neutralized.")

    # 3. Spaced keyword de-spacing
    despaced_text, spaced_hits = deobfuscate_spaced_keywords(deobf_url_text)
    obfuscation_details.extend(spaced_hits)

    # 4. Leetspeak word normalization
    tokens = despaced_text.split()
    normalized_tokens = []
    leet_detected_count = 0
    for t in tokens:
        clean_word = re.sub(r"^[^\w]+|[^\w]+$", "", t)
        norm_w, was_leet = normalize_leetspeak_word(clean_word)
        if was_leet and clean_word.lower() != norm_w.lower():
            leet_detected_count += 1
            normalized_tokens.append(t.replace(clean_word, norm_w))
        else:
            normalized_tokens.append(t)

    if leet_detected_count > 0:
        obfuscation_details.append(f"Leetspeak character substitution detected in {leet_detected_count} word(s).")

    normalized_text = " ".join(normalized_tokens)
    normalized_text = re.sub(r"\s+", " ", normalized_text).strip()

    # 5. Entity extraction
    extracted_urls = list(dict.fromkeys(URL_REGEX.findall(normalized_text)))
    extracted_emails = list(dict.fromkeys(EMAIL_REGEX.findall(normalized_text)))

    # Phone numbers filtering
    candidate_phones = PHONE_REGEX.findall(normalized_text)
    filtered_phones = []
    for p in candidate_phones:
        digits = re.sub(r"\D", "", p)
        if 7 <= len(digits) <= 15:
            # Avoid years or small amounts
            if not (len(digits) == 4 and (digits.startswith("19") or digits.startswith("20"))):
                filtered_phones.append(p.strip())
    extracted_phones = list(dict.fromkeys(filtered_phones))

    # 6. Language detection
    detected_lang, lang_conf = detect_language(original)

    # 7. Cleaned text for TF-IDF ML models
    cleaned = normalized_text.lower()
    cleaned = URL_REGEX.sub(" ", cleaned)
    cleaned = EMAIL_REGEX.sub(" ", cleaned)
    cleaned = PHONE_REGEX.sub(" ", cleaned)
    cleaned = cleaned.translate(str.maketrans("", "", string.punctuation))
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    return NormalizedMessageData(
        original_text=original,
        normalized_text=normalized_text,
        cleaned_for_ml=cleaned,
        detected_language=detected_lang,
        language_confidence=lang_conf,
        obfuscation_detected=len(obfuscation_details) > 0,
        obfuscation_details=obfuscation_details,
        extracted_urls=extracted_urls,
        extracted_phones=extracted_phones,
        extracted_emails=extracted_emails,
        char_count=len(original),
        word_count=len(normalized_text.split()),
    )
