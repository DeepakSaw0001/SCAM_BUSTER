# ScamBuster ML — Phone Scam & Robocall Dataset Documentation (Phase 06)

## 1. Dataset Overview

* **Dataset Name**: ScamBuster Phone Scam & Telephony Reputation Corpus (v1.0)
* **Primary Sources**:
  1. **US Federal Trade Commission (FTC) Do Not Call (DNC) Reported Robocalls & Telemarketing Complaints**:
     * Source: [FTC Do Not Call Data](https://www.ftc.gov/policy-notices/open-government/data-sets/do-not-call-data) / [Data.gov](https://catalog.data.gov/dataset/do-not-call-data)
     * License: U.S. Federal Government Public Domain / Open Data
  2. **FCC Consumer Inquiries & Robocall Complaints Data**:
     * Source: [FCC Open Data](https://opendata.fcc.gov/)
     * License: U.S. Federal Government Public Domain
  3. **Verified Public Utility & Enterprise Directory Series**:
     * Standard verified customer support numbers, public emergency helplines (e.g. 112, 911), ITU-T E.164 allocation series, and verified institutional directory lines.
* **Acquisition Date**: September 2026
* **Sample Count**: 4,200 deduplicated records (2,100 reported scam/robocall, 2,100 legitimate/verified directory numbers)
* **Labels**:
  * `0`: `LEGITIMATE` / Neutral (verified directory services, enterprise support lines, valid ITU-T subscriber ranges)
  * `1`: `REPORTED_SCAM` (numbers flagged in consumer regulatory fraud/robocall complaints)

---

## 2. Privacy & Data Safety Safeguards

In strict accordance with ScamBuster Phase 06 privacy mandates:
1. **No Private Leaks**: No personal mobile contact lists, leaked databases, or private subscriber records were used.
2. **Deduplication & Anonymization**: Numbers are normalized to canonical E.164. All internal tracking hashes use keyed HMAC-SHA256.
3. **No Individual Identification**: The dataset contains zero subscriber names, addresses, or personal identities.

---

## 3. Data Leakage Prevention

* **Strict Number-Level Deduplication**: The same phone number is never allowed to appear more than once in the dataset.
* **Partitioning**: Train (80%) and Test (20%) splits are formed strictly after group-level deduplication so that no overlapping numbers cross the split boundary.

---

## 4. Fundamental Telephony Data Limitations

As mandated by Phase 06 specifications (Section 17), static telephony datasets have severe inherent limitations compared to text/URL corpora:

1. **Spoofing Vulnerability**: Attackers frequently forge caller ID using VoIP CLI manipulation. A scam call may display a legitimate subscriber's number.
2. **Number Churn & Recycling**: Inactive numbers are recycled by telecom carriers after 90–180 days. A number reported as fraudulent 6 months ago may now belong to an innocent consumer.
3. **Geographic & Reporting Bias**: Public complaint registries predominantly reflect regions with active reporting mechanisms (e.g. US, UK, India). Unreported numbers are not guaranteed to be safe.
4. **Weak Static Signals**: Digit distributions (entropy, repetition) are weak indicators. The model outputs a probabilistic contextual signal, never a defamatory declaration about any individual.
