"""
Test script for text and URL inference modules with known test samples.
"""

from inference.text_predictor import predict_text
from inference.url_predictor import predict_url

text_samples = [
    "Hey, are we still meeting for lunch tomorrow at 1pm?",
    "CONGRATULATIONS! You have won a 1000 dollar Walmart Gift Card. Call now to claim your prize.",
    "URGENT: Your bank account has been temporarily suspended. Verify your identity immediately.",
    "Ok, see you later tonight.",
    "Claim your free entry to win a brand new car! Text WIN to 88001.",
]

url_samples = [
    "https://google.com",
    "https://github.com",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "http://192.168.1.100:8080/account/login/verify.php?token=xyz",
    "http://secure-login.paypal-verification.alert-update.com/login.html",
    "http://free-prize-winner-claim.xyz/update/password?user=victim",
]

print("=" * 60)
print("1. TESTING TEXT PREDICTOR INFERENCE")
print("=" * 60)

for s in text_samples:
    res = predict_text(s)
    print(f"Message : {s}")
    print(f"  Prediction       : {res['prediction']}")
    print(f"  Confidence       : {res['probability']:.4f}")
    print(f"  Spam Probability : {res['spam_probability']:.4f}")
    print(f"  Model            : {res['model']} v{res['model_version']}")
    print(f"  Cleaned input    : {res['preprocessed_input']}")
    print("-" * 50)

print("\n" + "=" * 60)
print("2. TESTING URL PREDICTOR INFERENCE")
print("=" * 60)

for u in url_samples:
    res = predict_url(u)
    print(f"URL     : {u}")
    print(f"  Prediction            : {res['prediction']}")
    print(f"  Confidence            : {res['probability']:.4f}")
    print(f"  Malicious Probability : {res['malicious_probability']:.4f}")
    print(f"  Model                 : {res['model']} v{res['model_version']}")
    print(f"  Features Extracted    : {res['features_used']}")
    print(f"  Sample Features       : length={res['extracted_features']['url_length']}, "
          f"dots={res['extracted_features']['num_dots']}, "
          f"keywords={res['extracted_features']['num_suspicious_keywords']}, "
          f"entropy={res['extracted_features']['entropy']:.3f}")
    print("-" * 50)

print("\n[ALL INFERENCE TESTS COMPLETED SUCCESSFULLY]")
