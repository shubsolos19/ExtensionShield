"""
Protected-Service (visa / travel-document) automation detection.

This module is the declarative replacement for the visa/travel-doc detection
that was hardcoded in ``scoring/gates.py`` and ``scoring/engine.py``. The domain,
pattern, and keyword lists live in ``config/protected_services.yaml`` (versioned,
auditable) and are loaded here once.

It exposes:
- The raw lists (``PROTECTED_SERVICE_DOMAINS`` etc.) for the legacy gate to import,
  so there is a single source of truth.
- ``detect()`` which turns a SignalPack + manifest into structured, evidence-bearing
  detections. The governance ``SignalExtractor`` uses this to emit signals that the
  ``PROTECTED_SERVICE_AUTOMATION`` rulepack evaluates.

Detection here is deterministic and side-effect free (no network, no source copy).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

_CONFIG_PATH = Path(__file__).parent.parent / "config" / "protected_services.yaml"


@lru_cache(maxsize=1)
def _load_config() -> Dict[str, Any]:
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        data = {}
    return data


def _list(key: str) -> List[str]:
    return [str(x) for x in (_load_config().get(key) or [])]


# Public, declarative lists (single source of truth).
DATA_VERSION: str = str(_load_config().get("version", "0"))
PROTECTED_SERVICE_DOMAINS: Tuple[str, ...] = tuple(_list("protected_service_domains"))
ECOSYSTEM_DOMAINS: Tuple[str, ...] = tuple(_list("ecosystem_domains"))
IDENTITY_KEYWORDS: Tuple[str, ...] = tuple(_list("identity_keywords"))
SABOTAGE_INDICATORS: Tuple[str, ...] = tuple(_list("sabotage_indicators"))


def _compile(key: str) -> List[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE) for p in _list(key)]


_SCREENSHOT_RX = _compile("screenshot_capture_patterns")
_XHR_RX = _compile("xhr_interception_patterns")
_CREDENTIAL_RX = _compile("credential_capture_patterns")
_EXFIL_RX = _compile("exfil_patterns")
_SABOTAGE_RX = [
    re.compile(p, re.IGNORECASE) for p in SABOTAGE_INDICATORS if any(c in p for c in ".*\\[")
]


@dataclass
class ProtectedServiceDetection:
    """Structured result of protected-service analysis."""

    protected_domain: bool = False
    automation_capability: bool = False
    screenshot_capture: bool = False
    xhr_interception: bool = False
    credential_capture: bool = False
    external_exfil: bool = False
    identity_keywords: bool = False
    competitor_sabotage: bool = False
    protected_domain_hits: List[str] = field(default_factory=list)
    ecosystem_hits: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    @property
    def is_protected_service_automation(self) -> bool:
        """Protected service + a capability to act on / capture from it."""
        return self.protected_domain and (
            self.automation_capability or self.xhr_interception or self.screenshot_capture
        )

    @property
    def any_signal(self) -> bool:
        return any(
            [
                self.protected_domain,
                self.screenshot_capture,
                self.xhr_interception,
                self.credential_capture,
                self.external_exfil,
                self.identity_keywords,
                self.competitor_sabotage,
            ]
        )


def _domains_in(text: str, domains: Tuple[str, ...]) -> List[str]:
    low = text.lower()
    return [d for d in domains if d in low]


def detect(signal_pack: Any, manifest: Dict[str, Any] | None = None) -> ProtectedServiceDetection:
    """Analyze a SignalPack (+ optional manifest) for protected-service automation.

    Uses only data already on the SignalPack (permissions, SAST findings, network
    domains) plus the manifest. No network access, no source copy.
    """
    manifest = manifest or {}
    det = ProtectedServiceDetection()

    perms = getattr(signal_pack, "permissions", None)
    api_perms = list(getattr(perms, "api_permissions", []) or [])
    host_perms = list(getattr(perms, "host_permissions", []) or [])
    network = getattr(signal_pack, "network", None)
    net_domains = list(getattr(network, "domains", []) or [])

    # Manifest text (content_scripts matches, externally_connectable, etc.)
    manifest_text = " ".join(
        str(v) for v in [
            manifest.get("host_permissions"),
            manifest.get("content_scripts"),
            manifest.get("externally_connectable"),
        ] if v
    ).lower()

    # SAST findings text (descriptive; check_id + message + snippet).
    sast = getattr(signal_pack, "sast", None)
    findings_text_parts: List[str] = []
    for f in getattr(sast, "deduped_findings", []) or []:
        findings_text_parts.append(
            f"{getattr(f, 'check_id', '')} {getattr(f, 'message', '')} "
            f"{getattr(f, 'code_snippet', '') or ''}"
        )
    sast_text = "\n".join(findings_text_parts)

    host_blob = " ".join(host_perms + api_perms).lower() + " " + manifest_text

    # --- Protected service domains ---
    domain_hits = list(dict.fromkeys(
        _domains_in(host_blob, PROTECTED_SERVICE_DOMAINS)
        + _domains_in(sast_text, PROTECTED_SERVICE_DOMAINS)
    ))
    if domain_hits:
        det.protected_domain = True
        det.protected_domain_hits = domain_hits
        det.evidence.append(f"protected_service_domains:{','.join(domain_hits)}")

    # --- Ecosystem (third-party processor) domains ---
    eco_hits = list(dict.fromkeys(
        _domains_in(" ".join(net_domains).lower(), ECOSYSTEM_DOMAINS)
        + _domains_in(sast_text, ECOSYSTEM_DOMAINS)
        + _domains_in(manifest_text, ECOSYSTEM_DOMAINS)
    ))
    det.ecosystem_hits = eco_hits

    # --- Automation capability (inject scripts / intercept) ---
    has_injection = (
        any(p in api_perms for p in ("scripting", "webRequest", "webRequestBlocking", "declarativeNetRequest"))
        or bool(manifest.get("content_scripts"))
    )
    if has_injection:
        det.automation_capability = True
        det.evidence.append("automation_capability:scripting_or_content_scripts")

    # --- Pattern-based behaviors in code ---
    if any(rx.search(sast_text) for rx in _SCREENSHOT_RX):
        det.screenshot_capture = True
        det.evidence.append("screenshot_capture")
    if any(rx.search(sast_text) for rx in _XHR_RX):
        det.xhr_interception = True
        det.automation_capability = True
        det.evidence.append("xhr_interception")
    if any(rx.search(sast_text) for rx in _CREDENTIAL_RX):
        det.credential_capture = True
        det.evidence.append("credential_capture")

    # --- External exfiltration: ecosystem endpoint OR exfil pattern + external host ---
    has_exfil_pattern = any(rx.search(sast_text) for rx in _EXFIL_RX)
    if eco_hits or (has_exfil_pattern and (eco_hits or net_domains)):
        det.external_exfil = True
        det.evidence.append("external_exfil:" + (",".join(eco_hits) if eco_hits else "exfil_pattern"))

    # --- Sensitive identity keywords ---
    if any(kw in sast_text.lower() for kw in IDENTITY_KEYWORDS) or any(
        kw in manifest_text for kw in IDENTITY_KEYWORDS
    ):
        det.identity_keywords = True
        det.evidence.append("identity_keywords")

    # --- Competitor sabotage indicators ---
    plain_indicators = [s for s in SABOTAGE_INDICATORS if not any(c in s for c in ".*\\[")]
    if any(ind in sast_text.lower() for ind in plain_indicators) or any(
        rx.search(sast_text) for rx in _SABOTAGE_RX
    ):
        det.competitor_sabotage = True
        det.evidence.append("competitor_sabotage")

    return det
