"""
ScamBuster ML — Phone Feature Engineering Layer (Phase 06)

Directly integrates and reuses the authoritative phone feature extractor from
backend/app/features/phone_features.py to guarantee strict feature parity between
training, evaluation, and production inference.
"""

from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Union

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.features.phone_features import (
    PHONE_FEATURE_NAMES as FEATURE_NAMES,
    calculate_consecutive_repeated_digits,
    calculate_digit_entropy,
    calculate_sequential_pattern_score,
    extract_phone_feature_vector,
    extract_phone_features,
)
from app.services.phone_normalizer import NormalizedPhone, normalize_phone_number

__all__ = [
    "FEATURE_NAMES",
    "calculate_consecutive_repeated_digits",
    "calculate_digit_entropy",
    "calculate_sequential_pattern_score",
    "extract_phone_features",
    "extract_phone_feature_vector",
    "normalize_phone_number",
    "NormalizedPhone",
]
