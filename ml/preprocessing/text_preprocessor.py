"""
ScamBuster ML — Text Preprocessor

Cleans raw SMS/message text before TF-IDF vectorisation.
All transformations are deterministic and stateless so they
can be applied identically at training time and inference time.
"""

import re
import string


def clean_text(text: str) -> str:
    """
    Minimal, reproducible text cleaning pipeline:
      1. Lowercase
      2. Strip URLs (they carry no signal once we remove the URL model's job)
      3. Strip email addresses
      4. Strip phone-number-like sequences
      5. Strip punctuation
      6. Collapse whitespace
    """
    if not isinstance(text, str):
        return ""

    text = text.lower()

    # Remove URLs
    text = re.sub(r"https?://\S+|www\.\S+", " ", text)

    # Remove email addresses
    text = re.sub(r"\S+@\S+\.\S+", " ", text)

    # Remove phone numbers (sequences of digits with optional separators)
    text = re.sub(r"[\+]?[\d\-\(\)\s]{7,15}", " ", text)

    # Remove punctuation
    text = text.translate(str.maketrans("", "", string.punctuation))

    # Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip()

    return text
