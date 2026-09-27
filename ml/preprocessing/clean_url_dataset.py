"""
ScamBuster ML — Dataset Cleaning & Validation Pipeline

Reads raw URL data, performs validation, whitespace stripping,
canonical deduplication, and writes clean dataset to ml/datasets/processed/url_dataset_clean.csv.
"""

import sys
from pathlib import Path
import pandas as pd

# Add repo root to path
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

RAW_PATH = REPO_ROOT / "ml" / "datasets" / "raw" / "url_dataset.csv"
PROCESSED_PATH = REPO_ROOT / "ml" / "datasets" / "processed" / "url_dataset_clean.csv"


def clean_url_dataset(input_csv: Path = RAW_PATH, output_csv: Path = PROCESSED_PATH) -> pd.DataFrame:
    print(f"[CLEANING] Loading raw dataset from: {input_csv}")
    if not input_csv.exists():
        raise FileNotFoundError(f"Raw dataset not found at {input_csv}")

    df = pd.read_csv(input_csv)
    initial_count = len(df)
    print(f"[INFO] Initial record count: {initial_count}")

    # 1. Check required columns
    required_cols = {"url", "label"}
    if not required_cols.issubset(df.columns):
        raise ValueError(f"Dataset missing required columns. Expected {required_cols}, found {df.columns.tolist()}")

    # 2. Drop rows with nulls in url or label
    df = df.dropna(subset=["url", "label"])
    after_na = len(df)
    if initial_count - after_na > 0:
        print(f"[CLEANING] Dropped {initial_count - after_na} rows with null values")

    # 3. Clean string values
    df["url"] = df["url"].astype(str).str.strip()
    df["label"] = df["label"].astype(int)

    # 4. Filter out invalid/empty URLs
    valid_mask = (df["url"].str.len() >= 4) & (df["url"].str.contains(r"[a-zA-Z0-9]"))
    df = df[valid_mask]

    # 5. Deduplicate based on URL
    before_dedup = len(df)
    df = df.drop_duplicates(subset=["url"])
    duplicates_removed = before_dedup - len(df)
    if duplicates_removed > 0:
        print(f"[CLEANING] Removed {duplicates_removed} duplicate URLs")

    # 6. Verify labels
    valid_labels = {0, 1}
    df = df[df["label"].isin(valid_labels)]

    # 7. Write output
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_csv, index=False)

    print(f"[OK] Cleaned dataset saved to: {output_csv}")
    print(f"[INFO] Final sample count: {len(df)}")
    print(f"[INFO] Class distribution:\n{df['label'].value_counts().to_dict()}")

    return df


if __name__ == "__main__":
    clean_url_dataset()
