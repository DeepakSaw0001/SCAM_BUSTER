"""
ScamBuster ML — URL Feature Engineering Layer

Directly integrates and reuses the authoritative URL feature extractor from
backend/app/services/url_feature_extractor.py to guarantee strict feature consistency
between training, evaluation, and production inference.
"""

import sys
from pathlib import Path
from typing import Dict, List

# Ensure backend is on sys.path
REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.services.url_feature_extractor import (
    URL_FEATURE_NAMES as FEATURE_NAMES,
    extract_feature_dict as extract_url_features,
    extract_feature_vector as extract_features_vector,
    extract_url_features as extract_url_features_pydantic,
)

__all__ = [
    "FEATURE_NAMES",
    "extract_url_features",
    "extract_features_vector",
    "extract_url_features_pydantic",
]
