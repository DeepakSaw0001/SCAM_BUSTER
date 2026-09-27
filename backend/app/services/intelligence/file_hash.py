"""
File Hash Threat Intelligence Provider Abstraction

Provides modular lookup interface for file cryptographic hashes (SHA-256).
Adheres strictly to the ScamBuster Threat Intelligence standard:
- Never fabricates provider results.
- Returns 'not_configured' status when no external API key is present.
"""

from typing import Any, Dict, Optional


class FileHashIntelligenceService:
    """
    Modular threat intelligence client for file hashes (SHA-256).
    """

    def __init__(self, api_key: Optional[str] = None, provider_name: str = "none"):
        self.api_key = api_key
        self.provider_name = provider_name

    def lookup_hash(self, sha256_hash: str) -> Dict[str, Any]:
        """
        Check hash against configured threat intelligence database.
        Returns explicit status structure without fabrication.
        """
        if not self.api_key or self.provider_name == "none":
            return {
                "status": "not_configured",
                "provider": "none",
                "sha256": sha256_hash,
                "reputation": "unknown",
                "malicious_votes": 0,
                "total_engines": 0,
                "details": "Threat intelligence hash provider is not configured. Analysis relies on static analysis.",
            }

        # Extensible stub for future integrations (e.g. VirusTotal, MalwareBazaar, MISP)
        return {
            "status": "configured",
            "provider": self.provider_name,
            "sha256": sha256_hash,
            "reputation": "unknown",
            "malicious_votes": 0,
            "total_engines": 0,
            "details": "Provider configured but live external queries disabled in local deployment.",
        }


# Default singleton instance
file_intel_service = FileHashIntelligenceService()
