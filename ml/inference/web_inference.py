"""
ML Subsystem — Web Risk Standalone Inference Module
"""

import sys
import os

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.app.ml.web_inference import WebRiskModelManager, predict_web_risk

__all__ = ["WebRiskModelManager", "predict_web_risk"]
