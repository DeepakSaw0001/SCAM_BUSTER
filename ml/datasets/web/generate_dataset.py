"""
Synthetic / Benchmark Web Risk Dataset Generator (Phase 09)

Generates a balanced, realistic corpus of web interaction profiles
spanning 4 threat categories:
- benign
- suspicious
- phishing
- malicious

Includes domain grouping metadata to enable strictly disjoint train/test splits,
preventing data leakage.
"""

import os
import random
import pandas as pd
import numpy as np

# Ensure repeatable generation
random.seed(42)
np.random.seed(42)

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_CSV = os.path.join(OUT_DIR, "web_risk_corpus.csv")


def generate_web_corpus(n_samples: int = 1200) -> pd.DataFrame:
    records = []
    
    # 300 benign samples
    benign_domains = [f"trusted-service-{i}.com" for i in range(1, 101)]
    for i in range(350):
        dom = random.choice(benign_domains)
        rec = {
            "domain": dom,
            "target_label": "benign",
            "redirect_count": random.choice([0, 0, 1]),
            "cross_domain_count": 0,
            "distinct_domain_count": 1,
            "has_cross_domain": 0,
            "domain_hopping": 0,
            "loop_detected": 0,
            "limit_reached": 0,
            "shortener_detected": 0,
            "meta_refresh_detected": 0,
            "js_redirect_detected": 0,
            "is_https": 1,
            "missing_hsts": random.choice([0, 0, 1]),
            "missing_csp": random.choice([0, 1]),
            "hardening_score": random.randint(60, 100),
            "form_count": random.randint(0, 3),
            "password_form_count": random.choice([0, 0, 1]),
            "payment_form_count": 0,
            "has_credential_form": random.choice([0, 0, 1]),
            "iframe_count": random.choice([0, 1]),
            "hidden_iframe_count": 0,
            "cross_domain_iframe_count": 0,
            "download_detected": 0,
            "is_executable": 0,
            "is_apk": 0,
        }
        records.append(rec)

    # 300 phishing samples
    phish_domains = [f"secure-login-update-{i}.top" for i in range(1, 101)]
    for i in range(350):
        dom = random.choice(phish_domains)
        rec = {
            "domain": dom,
            "target_label": "phishing",
            "redirect_count": random.randint(1, 3),
            "cross_domain_count": random.randint(1, 2),
            "distinct_domain_count": random.randint(2, 3),
            "has_cross_domain": 1,
            "domain_hopping": random.choice([0, 1]),
            "loop_detected": 0,
            "limit_reached": 0,
            "shortener_detected": random.choice([0, 1]),
            "meta_refresh_detected": random.choice([0, 1]),
            "js_redirect_detected": random.choice([0, 1]),
            "is_https": random.choice([0, 1]),
            "missing_hsts": 1,
            "missing_csp": 1,
            "hardening_score": random.randint(0, 40),
            "form_count": random.randint(1, 4),
            "password_form_count": random.randint(1, 2),
            "payment_form_count": random.choice([0, 1, 1]),
            "has_credential_form": 1,
            "iframe_count": random.randint(0, 2),
            "hidden_iframe_count": random.choice([0, 1]),
            "cross_domain_iframe_count": random.choice([0, 1]),
            "download_detected": 0,
            "is_executable": 0,
            "is_apk": 0,
        }
        records.append(rec)

    # 300 malicious download samples (malware / APK drops)
    mal_domains = [f"cdn-installer-fast-{i}.xyz" for i in range(1, 101)]
    for i in range(300):
        dom = random.choice(mal_domains)
        is_apk = random.choice([0, 1])
        is_exe = 1 if not is_apk else 0
        rec = {
            "domain": dom,
            "target_label": "malicious",
            "redirect_count": random.randint(2, 5),
            "cross_domain_count": random.randint(1, 4),
            "distinct_domain_count": random.randint(2, 4),
            "has_cross_domain": 1,
            "domain_hopping": random.choice([0, 1]),
            "loop_detected": 0,
            "limit_reached": 0,
            "shortener_detected": random.choice([0, 1]),
            "meta_refresh_detected": random.choice([0, 1]),
            "js_redirect_detected": random.choice([0, 1]),
            "is_https": random.choice([0, 1]),
            "missing_hsts": 1,
            "missing_csp": 1,
            "hardening_score": random.randint(0, 20),
            "form_count": 0,
            "password_form_count": 0,
            "payment_form_count": 0,
            "has_credential_form": 0,
            "iframe_count": random.randint(0, 3),
            "hidden_iframe_count": random.randint(0, 2),
            "cross_domain_iframe_count": random.randint(0, 2),
            "download_detected": 1,
            "is_executable": is_exe,
            "is_apk": is_apk,
        }
        records.append(rec)

    # 200 suspicious redirect / evasion samples
    susp_domains = [f"traffic-routing-hub-{i}.net" for i in range(1, 81)]
    for i in range(250):
        dom = random.choice(susp_domains)
        rec = {
            "domain": dom,
            "target_label": "suspicious",
            "redirect_count": random.randint(3, 7),
            "cross_domain_count": random.randint(2, 5),
            "distinct_domain_count": random.randint(3, 5),
            "has_cross_domain": 1,
            "domain_hopping": 1,
            "loop_detected": random.choice([0, 0, 1]),
            "limit_reached": random.choice([0, 0, 1]),
            "shortener_detected": 1,
            "meta_refresh_detected": random.choice([0, 1]),
            "js_redirect_detected": random.choice([0, 1]),
            "is_https": random.choice([0, 1]),
            "missing_hsts": 1,
            "missing_csp": 1,
            "hardening_score": random.randint(10, 40),
            "form_count": random.choice([0, 1]),
            "password_form_count": 0,
            "payment_form_count": 0,
            "has_credential_form": 0,
            "iframe_count": random.randint(1, 3),
            "hidden_iframe_count": random.choice([0, 1]),
            "cross_domain_iframe_count": random.randint(1, 2),
            "download_detected": 0,
            "is_executable": 0,
            "is_apk": 0,
        }
        records.append(rec)

    df = pd.DataFrame(records)
    # Shuffle
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    df.to_csv(OUT_CSV, index=False)
    print(f"Generated {len(df)} samples into {OUT_CSV}")
    return df


if __name__ == "__main__":
    generate_web_corpus()
