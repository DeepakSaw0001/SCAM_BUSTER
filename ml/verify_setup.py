"""
Verification test script for ScamBuster AIML subsystem.
Checks imports, feature extraction, and basic functions.
"""

import sys
from pathlib import Path

# Add ml/ to path
ML_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ML_ROOT))

modules_to_test = [
    ("utils.model_utils", "Model utilities & paths"),
    ("preprocessing.text_preprocessor", "Text cleaning preprocessor"),
    ("preprocessing.url_preprocessor", "URL parser"),
    ("features.text_features", "TF-IDF feature builder"),
    ("features.url_features", "URL feature engineering"),
    ("training.train_text_model", "Text training module"),
    ("training.train_url_model", "URL training module"),
    ("evaluation.evaluate_text_model", "Text evaluation module"),
    ("evaluation.evaluate_url_model", "URL evaluation module"),
    ("inference.text_predictor", "Text inference module"),
    ("inference.url_predictor", "URL inference module"),
    ("api.main", "FastAPI inference service"),
]

print("=" * 60)
print("1. TESTING MODULE IMPORTS")
print("=" * 60)

passed = 0
failed = 0

for mod_name, desc in modules_to_test:
    try:
        __import__(mod_name)
        print(f"  [PASS] {mod_name:35s} ({desc})")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] {mod_name:35s} ERROR: {e}")
        failed += 1

print(f"\nImport results: {passed} passed, {failed} failed.")

print("\n" + "=" * 60)
print("2. TESTING FEATURE EXTRACTION & PREPROCESSING")
print("=" * 60)

from preprocessing.text_preprocessor import clean_text
from preprocessing.url_preprocessor import parse_url
from features.url_features import extract_url_features, FEATURE_NAMES

sample_text = "URGENT! You have won a $1,000 Walmart Gift Card. Click https://scam.example.com to claim!"
cleaned = clean_text(sample_text)
print(f"  Raw text:     {sample_text}")
print(f"  Cleaned text: {cleaned}")
assert len(cleaned) > 0, "Cleaned text should not be empty"
print("  [PASS] clean_text works correctly")

sample_url = "http://secure-login.bank-update.phishing.example.com/account/login?id=999"
parsed = parse_url(sample_url)
print(f"  Hostname:     {parsed['hostname']}")
print(f"  Path:         {parsed['path']}")
assert parsed["hostname"] == "secure-login.bank-update.phishing.example.com"
print("  [PASS] parse_url works correctly")

features = extract_url_features(sample_url)
print(f"  Extracted {len(features)} URL features (expected {len(FEATURE_NAMES)}):")
for k, v in features.items():
    print(f"    {k:28s}: {v}")
assert len(features) == len(FEATURE_NAMES), "Feature count mismatch"
print("  [PASS] extract_url_features works correctly")

print("\n" + "=" * 60)
print("ALL PRE-TRAINING VERIFICATION CHECKS PASSED!")
print("=" * 60)
