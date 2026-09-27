# ScamBuster — Phone Number Threat Intelligence Architecture (Phase 06)

## 1. Provider Abstraction Architecture

ScamBuster decouples threat intelligence providers from the scoring engine through an abstract provider pattern:

```text
                  Normalized Phone (E.164)
                             │
                             ▼
              PhoneIntelligenceService (Singleton)
                             │
             ┌───────────────┴───────────────┐
             ▼                               ▼
       In-Memory Cache               In-Flight Lock
   (Keyed HMAC, TTL 300s)           (Deduplication)
             │                               │
             └───────────────┬───────────────┘
                             ▼
                PhoneIntelligenceProvider
               (Abstract Interface: base.py)
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
   Mock Provider      Numverify Driver      Twilio Driver
   (Unit Testing)       (Optional)            (Optional)
```

### Core Interface Contract (`app/intelligence/base.py`)

Every provider must implement:
```python
class PhoneIntelligenceProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def is_configured(self) -> bool:
        ...

    @abstractmethod
    async def lookup(self, phone: NormalizedPhone) -> PhoneIntelligenceResult:
        ...
```

The normalized return schema guarantees provider, checked timestamp, status attribution, reputation, and optional real report count:
```json
{
  "provider": "numverify-or-mock",
  "status": "available",
  "reputation": "reported_scam",
  "report_count": 24,
  "checked_at": "2026-09-25T22:30:00Z"
}
```

---

## 2. Privacy Engineering & PII Protection

* **No Plaintext Number Storage**: Raw user inputs are immediately normalized and masked.
* **Keyed HMAC-SHA256**: Cache keys and internal reference tokens use a keyed HMAC:
  ```python
  hmac.new(SECRET_SALT, e164.encode(), hashlib.sha256).hexdigest()
  ```
  This prevents brute-force enumeration attacks against the finite space of telephone numbers.
* **Zero PII Logging**: Operational logs output only the masked phone representation:
  ```text
  +91 ******3210
  ```
* **No Contact / Device Access**: ScamBuster requires zero mobile permissions (no contact book access, no call recording, no SMS interception).

---

## 3. Caching & Rate-Limiting Protection

* **TTL Memory Caching**: Intelligence lookup responses are cached for 300 seconds (5 minutes) by default to conserve third-party API quotas.
* **In-Flight Request Deduplication**: Uses `asyncio.Lock` keyed on the number's HMAC token so concurrent scans for the same target issue only a single provider request.
* **Single Query per Scan**: Lookups are called once at the start of a scan pipeline and shared across heuristic rules, ML verification, and result assembly.

---

## 4. Failure Handling & Non-Blocking Resilience

If an external intelligence provider is:
* Unconfigured (missing API key or environment variable)
* Rate limited (HTTP 429)
* Timed out (exceeds 5.0 seconds)
* Experiencing service outages (HTTP 500)

**The scan does NOT fail.**
The provider returns an explicit status (`"not_configured"`, `"rate_limited"`, `"timeout"`, or `"error"`), and ScamBuster seamlessly proceeds using static heuristic rules, digit pattern analysis, and the ML statistical model.

---

## 5. Environment Configuration

Add the following placeholders to your environment or `.env`:

```bash
# Threat Intelligence Provider Options: 'none', 'mock', or external provider name
PHONE_INTELLIGENCE_PROVIDER=none
PHONE_INTELLIGENCE_API_KEY=

# Optional custom HMAC secret for phone number tokenization
SCAMBUSTER_PHONE_HMAC_SECRET=your-secret-salt-here
```

---

## 6. Strict Avoidance of Fake Data

ScamBuster strictly adheres to academic and engineering honesty:
* If no external threat intelligence provider is configured, the status is explicitly reported as `not_configured` or `unavailable`.
* ScamBuster **never** fabricates fake phone reputation databases or invents complaint counts.
* An absence of scam complaints is never equated with proof of safety: unverified clean numbers return an explicit `UNKNOWN` state.
