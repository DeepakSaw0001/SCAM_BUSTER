"""
Test client to verify FastAPI ML service endpoints.
"""

import json
import requests

BASE_URL = "http://127.0.0.1:8000"

print("=" * 60)
print("1. TESTING GET /health")
print("=" * 60)

res = requests.get(f"{BASE_URL}/health", timeout=5)
print(f"Status Code: {res.status_code}")
print(json.dumps(res.json(), indent=2))
assert res.status_code == 200
assert res.json()["status"] == "healthy"
assert res.json()["models"]["text_classifier"]["available"] is True
assert res.json()["models"]["url_classifier"]["available"] is True
print("  [PASS] /health is healthy and both models are available")

print("\n" + "=" * 60)
print("2. TESTING POST /predict/text (Spam sample)")
print("=" * 60)

payload = {"text": "Congratulations! You won a $1,000 gift card! Claim now at http://win.fake.com"}
res = requests.post(f"{BASE_URL}/predict/text", json=payload, timeout=5)
print(f"Status Code: {res.status_code}")
print(json.dumps(res.json(), indent=2))
assert res.status_code == 200
assert res.json()["prediction"] in ("ham", "spam")
print("  [PASS] /predict/text returned valid prediction")

print("\n" + "=" * 60)
print("3. TESTING POST /predict/text (Ham sample)")
print("=" * 60)

payload = {"text": "Hey mom, I'll be home for dinner around 7pm."}
res = requests.post(f"{BASE_URL}/predict/text", json=payload, timeout=5)
print(f"Status Code: {res.status_code}")
print(json.dumps(res.json(), indent=2))
assert res.status_code == 200
assert res.json()["prediction"] == "ham"
print("  [PASS] /predict/text correctly classified benign message as ham")

print("\n" + "=" * 60)
print("4. TESTING POST /predict/url (Phishing sample)")
print("=" * 60)

payload = {"url": "http://secure-login.update-billing-verification.com/login.php?id=8831"}
res = requests.post(f"{BASE_URL}/predict/url", json=payload, timeout=5)
print(f"Status Code: {res.status_code}")
print(json.dumps(res.json(), indent=2))
assert res.status_code == 200
assert res.json()["prediction"] in ("benign", "malicious")
print("  [PASS] /predict/url returned valid prediction")

print("\n" + "=" * 60)
print("5. TESTING POST /predict/url (Legitimate sample)")
print("=" * 60)

payload = {"url": "https://google.com"}
res = requests.post(f"{BASE_URL}/predict/url", json=payload, timeout=5)
print(f"Status Code: {res.status_code}")
print(json.dumps(res.json(), indent=2))
assert res.status_code == 200
assert res.json()["prediction"] == "benign"
print("  [PASS] /predict/url correctly classified google.com as benign")

print("\n" + "=" * 60)
print("ALL FASTAPI ENDPOINTS VERIFIED AND WORKING!")
print("=" * 60)
