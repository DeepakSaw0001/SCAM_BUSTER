"""
ScamBuster ML — Message Preprocessor (Phase 04)

Provides reproducible text preprocessing for NLP model training and inference.
Reuses the canonical preprocessing logic from backend/app/services/message_preprocessor.py.
"""

import sys
from pathlib import Path

# Add backend to path if needed for import
BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.services.message_preprocessor import (
    PreprocessedMessage,
    preprocess_message,
)

__all__ = ["PreprocessedMessage", "preprocess_message"]
