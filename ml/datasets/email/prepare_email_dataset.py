"""
ScamBuster ML — Email Dataset Preparation Pipeline
Downloads the Apache SpamAssassin public corpus (standard benchmark in academic and cybersecurity literature),
extracts raw emails, parses MIME structures using Python's standard email library, removes duplicates,
and creates a clean structured dataset for NLP model training.

Primary Source: Apache SpamAssassin Public Corpus (20021010_easy_ham & 20021010_spam)
URL: https://spamassassin.apache.org/old/publiccorpus/
License: Apache License 2.0 / Public Research Use
"""

import email
from email import policy
import io
import os
import re
import sys
import tarfile
import urllib.request
import pandas as pd


SPAM_CORPUS_URL = "https://spamassassin.apache.org/old/publiccorpus/20021010_spam.tar.bz2"
HAM_CORPUS_URL = "https://spamassassin.apache.org/old/publiccorpus/20021010_easy_ham.tar.bz2"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_DIR = os.path.join(BASE_DIR, "..", "raw")
PROCESSED_DIR = os.path.join(BASE_DIR, "..", "processed")
OUTPUT_CSV = os.path.join(PROCESSED_DIR, "email_corpus_clean.csv")


def download_tarball(url: str, dest_path: str):
    """Download tarball if not already present."""
    if os.path.exists(dest_path) and os.path.getsize(dest_path) > 100000:
        print(f"Archive already exists at {dest_path} ({os.path.getsize(dest_path)} bytes).")
        return

    print(f"Downloading {url} to {dest_path}...")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ScamBuster/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp, open(dest_path, "wb") as f:
        data = resp.read()
        f.write(data)
    print(f"Downloaded {len(data)} bytes.")


def extract_email_content(msg: email.message.EmailMessage) -> str:
    """Extract plain text or HTML body from parsed EmailMessage."""
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in content_disposition:
                continue
            if content_type in ["text/plain", "text/html"]:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        text = payload.decode(charset, errors="replace")
                        body_parts.append(text)
                except Exception:
                    continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                body_parts.append(payload.decode(charset, errors="replace"))
            else:
                body_parts.append(str(msg.get_payload() or ""))
        except Exception:
            body_parts.append(str(msg.get_payload() or ""))

    combined = "\n".join(body_parts)
    # Strip HTML tags if mostly HTML
    if "<html" in combined.lower() or "<body" in combined.lower() or "<p" in combined.lower():
        clean_text = re.sub(r"<style.*?</style>", " ", combined, flags=re.DOTALL | re.IGNORECASE)
        clean_text = re.sub(r"<script.*?</script>", " ", clean_text, flags=re.DOTALL | re.IGNORECASE)
        clean_text = re.sub(r"<[^>]+>", " ", clean_text)
        clean_text = re.sub(r"\s+", " ", clean_text).strip()
        return clean_text
    return re.sub(r"\s+", " ", combined).strip()


def parse_tarball_emails(tar_path: str, label: int, max_samples: int = 1500):
    """Parse raw RFC-822 email files from tarball."""
    records = []
    print(f"Extracting and parsing from {tar_path}...")
    with tarfile.open(tar_path, mode="r:bz2") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            try:
                raw_bytes = tar.extractfile(member).read()
                # Parse using email parser
                try:
                    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
                except Exception:
                    # Fallback with compat policy
                    msg = email.message_from_bytes(raw_bytes, policy=policy.compat32)

                subject = str(msg.get("Subject", "") or "").strip()
                sender = str(msg.get("From", "") or "").strip()
                body = extract_email_content(msg)

                # Skip completely blank messages
                if not body and not subject:
                    continue

                records.append({
                    "subject": subject,
                    "sender": sender,
                    "body": body,
                    "full_text": f"{subject} {body}".strip(),
                    "label": label,  # 0 = ham / legitimate, 1 = spam / phishing
                })

                if len(records) >= max_samples:
                    break
            except Exception as e:
                continue

    print(f"Parsed {len(records)} records from {tar_path}.")
    return records


def main():
    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    spam_tar = os.path.join(RAW_DIR, "20021010_spam.tar.bz2")
    ham_tar = os.path.join(RAW_DIR, "20021010_easy_ham.tar.bz2")

    download_tarball(SPAM_CORPUS_URL, spam_tar)
    download_tarball(HAM_CORPUS_URL, ham_tar)

    spam_records = parse_tarball_emails(spam_tar, label=1, max_samples=1000)
    ham_records = parse_tarball_emails(ham_tar, label=0, max_samples=1500)

    all_records = spam_records + ham_records
    df = pd.DataFrame(all_records)

    print(f"Total raw records parsed: {len(df)}")
    print("Class distribution before deduplication:")
    print(df["label"].value_counts())

    # Deduplicate based on body text
    df = df.drop_duplicates(subset=["full_text"]).reset_index(drop=True)
    # Filter very short non-informative texts (< 10 chars)
    df = df[df["full_text"].str.len() >= 10].reset_index(drop=True)

    print(f"\nTotal clean unique records: {len(df)}")
    print("Class distribution after deduplication:")
    print(df["label"].value_counts())

    df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8")
    print(f"Saved clean dataset to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
