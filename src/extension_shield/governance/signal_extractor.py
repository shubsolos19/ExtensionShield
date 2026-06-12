"""
Signal Extractor - Stage 4 of Governance Pipeline

Extracts governance signals from facts and security findings.
Signals are high-level risk indicators used by the Rules Engine.

Now supports the 3-Layer Scoring Architecture:
- Layer 0 (Signal Extraction): Uses SignalPack from tool adapters
- Layer 1 (Risk Scoring): Deterministic scoring from normalized signals
- Layer 2 (Decision): Final governance verdict

MVP Signal Types:
- HOST_PERMS_BROAD: Extension requests broad host permissions (<all_urls>, *://*/*)
- SENSITIVE_API: Extension uses sensitive Chrome APIs (webRequest, proxy, debugger)
- ENDPOINT_FOUND: External endpoint/URL detected in code
- DATAFLOW_TRACE: Potential data exfiltration pattern detected
- OBFUSCATION: Code obfuscation or packing detected
- VIRUSTOTAL_HIT: VirusTotal malicious/suspicious detection
- SAST_CRITICAL: Critical SAST findings detected

Output: signals.json
"""

import logging
import re
from datetime import datetime
from typing import Dict, Any, List, Optional, TYPE_CHECKING
from uuid import uuid4

from .schemas import Signal, Signals, Facts

if TYPE_CHECKING:
    from .signal_pack import SignalPack

logger = logging.getLogger(__name__)


# =============================================================================
# SIGNAL TYPE DEFINITIONS
# =============================================================================

class SignalType:
    """Signal type constants."""
    # Original MVP signal types
    HOST_PERMS_BROAD = "HOST_PERMS_BROAD"
    SENSITIVE_API = "SENSITIVE_API"
    ENDPOINT_FOUND = "ENDPOINT_FOUND"
    DATAFLOW_TRACE = "DATAFLOW_TRACE"
    OBFUSCATION = "OBFUSCATION"
    
    # Layer 0 signal types (from SignalPack)
    VIRUSTOTAL_HIT = "VIRUSTOTAL_HIT"
    SAST_CRITICAL = "SAST_CRITICAL"
    SAST_HIGH = "SAST_HIGH"
    LOW_WEBSTORE_TRUST = "LOW_WEBSTORE_TRUST"
    CHROMESTATS_RISK = "CHROMESTATS_RISK"
    HIGH_ENTROPY = "HIGH_ENTROPY"
    UNREASONABLE_PERMISSIONS = "UNREASONABLE_PERMISSIONS"

    # Protected-service (visa / travel-document) automation signal types.
    # Consumed by the PROTECTED_SERVICE_AUTOMATION rulepack.
    PROTECTED_SERVICE_DOMAIN = "PROTECTED_SERVICE_DOMAIN"
    PROTECTED_SERVICE_AUTOMATION = "PROTECTED_SERVICE_AUTOMATION"
    SCREENSHOT_CAPTURE = "SCREENSHOT_CAPTURE"
    XHR_INTERCEPTION = "XHR_INTERCEPTION"
    CREDENTIAL_CAPTURE = "CREDENTIAL_CAPTURE"
    IDENTITY_DATA_EXFIL = "IDENTITY_DATA_EXFIL"
    SENSITIVE_IDENTITY_KEYWORDS = "SENSITIVE_IDENTITY_KEYWORDS"
    COMPETITOR_SABOTAGE = "COMPETITOR_SABOTAGE"


# Sensitive Chrome APIs that warrant review
SENSITIVE_APIS = [
    "webRequest",
    "webRequestBlocking",
    "proxy",
    "debugger",
    "nativeMessaging",
    "enterprise.platformKeys",
    "vpnProvider",
    "networking.config",
    "declarativeNetRequest",
    "desktopCapture",
    "tabCapture",
]

# Broad host permission patterns
BROAD_HOST_PATTERNS = [
    "<all_urls>",
    "*://*/*",
    "http://*/*",
    "https://*/*",
    "*://*",
]


class SignalExtractor:
    """
    Extracts governance signals from facts.
    
    Stage 4 of the Governance Decisioning Pipeline.
    
    Usage:
        extractor = SignalExtractor()
        signals = extractor.extract(facts)
        signals_dict = signals.model_dump()
    """
    
    def __init__(self):
        """Initialize the Signal Extractor."""
        self._signal_counter = 0
    
    def extract(self, facts: Facts) -> Signals:
        """
        Extract all signals from facts.
        
        Args:
            facts: Facts object from Stage 2
            
        Returns:
            Signals object containing all extracted signals
        """
        logger.info("Extracting signals for scan_id=%s", facts.scan_id)
        
        self._signal_counter = 0
        signals_list: List[Signal] = []
        
        # Extract each signal type
        signals_list.extend(self._extract_host_perms_broad(facts))
        signals_list.extend(self._extract_sensitive_api(facts))
        signals_list.extend(self._extract_endpoint_found(facts))
        signals_list.extend(self._extract_dataflow_trace(facts))
        signals_list.extend(self._extract_obfuscation(facts))
        
        logger.info(
            "Extracted %d signals: %s",
            len(signals_list),
            [s.type for s in signals_list]
        )
        
        return Signals(scan_id=facts.scan_id, signals=signals_list)
    
    def extract_from_dict(self, facts_dict: Dict[str, Any], scan_id: str) -> Signals:
        """
        Extract signals from a facts dictionary.
        
        Args:
            facts_dict: Facts as a dictionary
            scan_id: Scan identifier
            
        Returns:
            Signals object
        """
        facts = Facts(**facts_dict)
        return self.extract(facts)
    
    def _next_signal_id(self) -> str:
        """Generate the next signal ID."""
        self._signal_counter += 1
        return f"sig_{self._signal_counter:03d}"
    
    # =========================================================================
    # SIGNAL EXTRACTION METHODS
    # =========================================================================
    
    def _extract_host_perms_broad(self, facts: Facts) -> List[Signal]:
        """
        Extract HOST_PERMS_BROAD signals.
        
        Triggers when extension requests broad host permissions that grant
        access to all or most websites.
        """
        signals = []
        
        broad_patterns_found = []
        for pattern in facts.host_access_patterns:
            if pattern in BROAD_HOST_PATTERNS:
                broad_patterns_found.append(pattern)
        
        if broad_patterns_found:
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.HOST_PERMS_BROAD,
                confidence=0.95,
                evidence_refs=[],  # Will be populated by evidence builder
                description=f"Broad host permissions detected: {', '.join(broad_patterns_found)}",
                severity="high",
            ))
            logger.debug("HOST_PERMS_BROAD signal: %s", broad_patterns_found)
        
        return signals
    
    def _extract_sensitive_api(self, facts: Facts) -> List[Signal]:
        """
        Extract SENSITIVE_API signals.
        
        Triggers when extension uses sensitive Chrome APIs that require
        heightened security review.
        """
        signals = []
        
        # Check manifest permissions
        permissions = facts.manifest.permissions or []
        sensitive_found = []
        
        for perm in permissions:
            if perm in SENSITIVE_APIS:
                sensitive_found.append(perm)
        
        # Check optional permissions too
        optional_perms = facts.manifest.optional_permissions or []
        for perm in optional_perms:
            if perm in SENSITIVE_APIS and perm not in sensitive_found:
                sensitive_found.append(f"{perm} (optional)")
        
        if sensitive_found:
            severity = "critical" if any(p in ["debugger", "proxy", "vpnProvider"] for p in sensitive_found) else "high"
            
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.SENSITIVE_API,
                confidence=0.90,
                evidence_refs=[],
                description=f"Sensitive APIs detected: {', '.join(sensitive_found)}",
                severity=severity,
            ))
            logger.debug("SENSITIVE_API signal: %s", sensitive_found)
        
        return signals
    
    def _extract_endpoint_found(self, facts: Facts) -> List[Signal]:
        """
        Extract ENDPOINT_FOUND signals.
        
        Triggers when external URLs/endpoints are detected in the code
        (typically from SAST findings).
        """
        signals = []
        
        # Check SAST findings for external endpoints
        sast_findings = facts.security_findings.sast_findings or []
        endpoint_findings = []
        
        for finding in sast_findings:
            # Look for findings that indicate external communication
            finding_type = finding.finding_type.lower()
            description = finding.description.lower()
            
            if any(indicator in finding_type or indicator in description for indicator in [
                "endpoint", "fetch", "xhr", "ajax", "http", "api",
                "external", "remote", "url", "network"
            ]):
                endpoint_findings.append(finding)
        
        if endpoint_findings:
            # Deduplicate by file path
            unique_files = set(f.file_path for f in endpoint_findings)
            
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.ENDPOINT_FOUND,
                confidence=0.85,
                evidence_refs=[],
                description=f"External endpoints detected in {len(unique_files)} file(s): {', '.join(list(unique_files)[:3])}{'...' if len(unique_files) > 3 else ''}",
                severity="medium",
            ))
            logger.debug("ENDPOINT_FOUND signal: %d findings", len(endpoint_findings))
        
        return signals
    
    def _extract_dataflow_trace(self, facts: Facts) -> List[Signal]:
        """
        Extract DATAFLOW_TRACE signals.
        
        Triggers when potential data exfiltration patterns are detected:
        - Data collection + external transfer
        - Sensitive data access + network calls
        """
        signals = []
        
        # Check SAST findings for data exfiltration patterns
        sast_findings = facts.security_findings.sast_findings or []
        dataflow_findings = []
        
        for finding in sast_findings:
            finding_type = finding.finding_type.lower()
            description = finding.description.lower()
            
            # Look for data exfiltration indicators
            if any(indicator in finding_type or indicator in description for indicator in [
                "exfil", "dataflow", "data-flow", "leak", "steal",
                "send", "transmit", "upload", "transfer", "harvest"
            ]):
                dataflow_findings.append(finding)
        
        # Also trigger if we have both storage access AND external endpoints
        has_storage = "storage" in (facts.manifest.permissions or [])
        has_endpoints = any(f.finding_type.lower() in ["endpoint", "fetch", "network"] 
                          for f in sast_findings)
        
        if dataflow_findings:
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.DATAFLOW_TRACE,
                confidence=0.85,
                evidence_refs=[],
                description=f"Data exfiltration pattern detected in {len(dataflow_findings)} finding(s)",
                severity="high",
            ))
            logger.debug("DATAFLOW_TRACE signal from SAST: %d findings", len(dataflow_findings))
        elif has_storage and has_endpoints:
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.DATAFLOW_TRACE,
                confidence=0.70,
                evidence_refs=[],
                description="Storage permission combined with external endpoint access",
                severity="medium",
            ))
            logger.debug("DATAFLOW_TRACE signal from permissions+endpoints")
        
        return signals
    
    def _extract_obfuscation(self, facts: Facts) -> List[Signal]:
        """
        Extract OBFUSCATION signals.
        
        Triggers when code obfuscation or packing is detected:
        - High entropy files
        - Known obfuscation patterns
        - Packed/minified code that hides functionality
        """
        signals = []
        
        security = facts.security_findings
        
        # Check entropy-based obfuscation detection
        if security.obfuscation_detected:
            # Get high-risk entropy files
            high_entropy_files = [
                f for f in security.entropy_findings
                if f.is_likely_obfuscated or f.risk_level == "high"
            ]
            
            file_names = [f.file_name for f in high_entropy_files[:5]]
            
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.OBFUSCATION,
                confidence=0.80,
                evidence_refs=[],
                description=f"Code obfuscation detected in {len(high_entropy_files)} file(s): {', '.join(file_names)}{'...' if len(high_entropy_files) > 5 else ''}",
                severity="medium",
            ))
            logger.debug("OBFUSCATION signal: %d files", len(high_entropy_files))
        
        # Check entropy risk level even if obfuscation flag is not set
        elif security.entropy_risk_level == "high":
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.OBFUSCATION,
                confidence=0.70,
                evidence_refs=[],
                description="High entropy detected, possible code obfuscation",
                severity="medium",
            ))
            logger.debug("OBFUSCATION signal from entropy risk level")
        
        return signals
    
    def save(self, signals: Signals, output_path: str) -> None:
        """
        Save signals to a JSON file.
        
        Args:
            signals: The Signals object to save
            output_path: Path to save the signals.json file
        """
        import json
        from pathlib import Path
        
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output, "w", encoding="utf-8") as f:
            json.dump(signals.model_dump(mode="json"), f, indent=2, default=str)
        
        logger.info("Signals saved to %s", output_path)
    
    # =========================================================================
    # LAYER 0: SIGNAL PACK EXTRACTION METHODS
    # =========================================================================
    
    def extract_from_signal_pack(self, signal_pack: "SignalPack") -> Signals:
        """
        Extract signals from a SignalPack (Layer 0 output).
        
        This is the new 3-layer architecture approach. Uses normalized
        signals from tool adapters instead of raw facts.
        
        Args:
            signal_pack: SignalPack from Layer 0 (tool adapters)
            
        Returns:
            Signals object with extracted signals and evidence refs
        """
        logger.info("Extracting signals from SignalPack for scan_id=%s", signal_pack.scan_id)
        
        self._signal_counter = 0
        signals_list: List[Signal] = []
        
        # Extract signals from each tool pack
        signals_list.extend(self._extract_sast_signals(signal_pack))
        signals_list.extend(self._extract_virustotal_signals(signal_pack))
        signals_list.extend(self._extract_entropy_signals(signal_pack))
        signals_list.extend(self._extract_permissions_signals(signal_pack))
        signals_list.extend(self._extract_webstore_signals(signal_pack))
        signals_list.extend(self._extract_chromestats_signals(signal_pack))
        signals_list.extend(self._extract_protected_service_signals(signal_pack))
        
        # Link evidence to signals
        signals_list = self._link_evidence_to_signals(signal_pack, signals_list)
        
        logger.info(
            "Extracted %d signals from SignalPack: %s",
            len(signals_list),
            [s.type for s in signals_list]
        )
        
        return Signals(scan_id=signal_pack.scan_id, signals=signals_list)
    
    def _extract_protected_service_signals(self, signal_pack: "SignalPack") -> List[Signal]:
        """Emit protected-service (visa/travel-doc) automation signals.

        Detection is delegated to ``governance.protected_services.detect`` which
        reads the declarative config/protected_services.yaml. These signals are
        consumed by the PROTECTED_SERVICE_AUTOMATION rulepack.
        """
        from extension_shield.governance.protected_services import detect

        manifest = getattr(signal_pack, "manifest", None) or {}
        det = detect(signal_pack, manifest)
        signals: List[Signal] = []

        def _add(stype: str, desc: str, severity: str, confidence: float = 0.85):
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=stype,
                confidence=confidence,
                evidence_refs=[],
                description=desc,
                severity=severity,
            ))

        if det.protected_domain:
            _add(
                SignalType.PROTECTED_SERVICE_DOMAIN,
                f"Targets protected service domain(s): {', '.join(det.protected_domain_hits)}",
                "high",
                0.95,
            )
        if det.is_protected_service_automation:
            _add(
                SignalType.PROTECTED_SERVICE_AUTOMATION,
                "Automates a protected service whose terms prohibit automated access",
                "critical",
                0.9,
            )
        if det.screenshot_capture:
            _add(SignalType.SCREENSHOT_CAPTURE, "Screenshot/page capture of rendered content", "high")
        if det.xhr_interception:
            _add(SignalType.XHR_INTERCEPTION, "Intercepts the page's XHR/fetch API traffic", "high")
        if det.credential_capture:
            _add(SignalType.CREDENTIAL_CAPTURE, "Captures or auto-fills credentials/security answers", "critical", 0.9)
        if det.external_exfil:
            _add(
                SignalType.IDENTITY_DATA_EXFIL,
                "Sends data to an external/third-party endpoint: "
                + (", ".join(det.ecosystem_hits) or "external host"),
                "critical",
                0.9,
            )
        if det.identity_keywords:
            _add(SignalType.SENSITIVE_IDENTITY_KEYWORDS, "Handles sensitive identity data (passport/visa/appointment)", "high")
        if det.competitor_sabotage:
            _add(SignalType.COMPETITOR_SABOTAGE, "Indicators of sabotaging competitor extensions", "medium", 0.7)

        return signals

    def _extract_sast_signals(self, signal_pack: "SignalPack") -> List[Signal]:
        """Extract signals from SAST findings in SignalPack."""
        signals = []
        sast = signal_pack.sast
        
        # Critical SAST findings
        if sast.counts_by_severity.get("CRITICAL", 0) > 0:
            count = sast.counts_by_severity["CRITICAL"]
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.SAST_CRITICAL,
                confidence=sast.confidence,
                evidence_refs=[],
                description=f"{count} critical SAST finding(s) detected",
                severity="critical",
            ))
        
        # High/Error SAST findings
        error_count = sast.counts_by_severity.get("ERROR", 0)
        if error_count >= 3:
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.SAST_HIGH,
                confidence=sast.confidence,
                evidence_refs=[],
                description=f"{error_count} high-severity SAST finding(s) detected",
                severity="high",
            ))
        
        # Check for endpoint/external API findings
        endpoint_findings = [
            f for f in sast.deduped_findings
            if any(kw in f.check_id.lower() or kw in f.message.lower()
                   for kw in ["endpoint", "fetch", "external", "api", "http"])
        ]
        if endpoint_findings:
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.ENDPOINT_FOUND,
                confidence=0.85,
                evidence_refs=[],
                description=f"External API calls detected in {len(endpoint_findings)} finding(s)",
                severity="medium",
            ))
        
        # Check for data flow issues
        dataflow_findings = [
            f for f in sast.deduped_findings
            if any(kw in f.check_id.lower() or kw in f.message.lower()
                   for kw in ["exfil", "leak", "send", "transmit", "dataflow"])
        ]
        if dataflow_findings:
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.DATAFLOW_TRACE,
                confidence=0.85,
                evidence_refs=[],
                description=f"Potential data exfiltration pattern in {len(dataflow_findings)} finding(s)",
                severity="high",
            ))
        
        return signals
    
    def _extract_virustotal_signals(self, signal_pack: "SignalPack") -> List[Signal]:
        """Extract signals from VirusTotal results in SignalPack."""
        signals = []
        vt = signal_pack.virustotal
        
        if not vt.enabled:
            return signals
        
        if vt.malicious_count > 0:
            severity = "critical" if vt.malicious_count >= 3 else "high"
            families = ", ".join(vt.malware_families[:3]) if vt.malware_families else "Unknown"
            
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.VIRUSTOTAL_HIT,
                confidence=0.95,
                evidence_refs=[],
                description=f"VirusTotal: {vt.malicious_count} malicious detection(s). Families: {families}",
                severity=severity,
            ))
        elif vt.suspicious_count > 0:
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.VIRUSTOTAL_HIT,
                confidence=0.80,
                evidence_refs=[],
                description=f"VirusTotal: {vt.suspicious_count} suspicious detection(s)",
                severity="medium",
            ))
        
        return signals
    
    def _extract_entropy_signals(self, signal_pack: "SignalPack") -> List[Signal]:
        """Extract signals from entropy analysis in SignalPack."""
        signals = []
        entropy = signal_pack.entropy
        
        if entropy.obfuscated_count > 0:
            files = entropy.suspected_obfuscation_files[:3]
            files_str = ", ".join(files)
            if len(entropy.suspected_obfuscation_files) > 3:
                files_str += "..."
            
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.OBFUSCATION,
                confidence=0.80,
                evidence_refs=[],
                description=f"Code obfuscation detected in {entropy.obfuscated_count} file(s): {files_str}",
                severity="medium",
            ))
        
        if entropy.overall_risk == "high":
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.HIGH_ENTROPY,
                confidence=0.75,
                evidence_refs=[],
                description="High entropy detected across analyzed files",
                severity="medium",
            ))
        
        return signals
    
    def _extract_permissions_signals(self, signal_pack: "SignalPack") -> List[Signal]:
        """Extract signals from permissions analysis in SignalPack."""
        signals = []
        perms = signal_pack.permissions
        
        # Broad host permissions
        if perms.has_broad_host_access:
            patterns = ", ".join(perms.broad_host_patterns)
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.HOST_PERMS_BROAD,
                confidence=0.95,
                evidence_refs=[],
                description=f"Broad host permissions detected: {patterns}",
                severity="high",
            ))
        
        # Sensitive APIs
        sensitive_apis = [
            p for p in perms.api_permissions
            if p in SENSITIVE_APIS
        ]
        if sensitive_apis:
            severity = "critical" if any(p in ["debugger", "proxy"] for p in sensitive_apis) else "high"
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.SENSITIVE_API,
                confidence=0.90,
                evidence_refs=[],
                description=f"Sensitive APIs detected: {', '.join(sensitive_apis)}",
                severity=severity,
            ))
        
        # Unreasonable permissions
        if len(perms.unreasonable_permissions) >= 3:
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.UNREASONABLE_PERMISSIONS,
                confidence=0.85,
                evidence_refs=[],
                description=f"{len(perms.unreasonable_permissions)} unreasonable permission(s) detected",
                severity="medium",
            ))
        
        return signals
    
    def _extract_webstore_signals(self, signal_pack: "SignalPack") -> List[Signal]:
        """Extract signals from webstore stats in SignalPack.

        Fairness: User count alone is NOT a trust signal. Niche developer tools,
        enterprise extensions, and specialized utilities naturally have small user
        bases. We only flag concrete quality/compliance issues.
        """
        signals = []
        stats = signal_pack.webstore_stats
        reviews = signal_pack.webstore_reviews

        # Low trust indicators — only concrete quality/compliance gaps
        low_trust_reasons = []

        # Low rating is an objective quality signal from actual users
        if stats.rating_avg is not None and stats.rating_avg < 3.0:
            low_trust_reasons.append(f"low rating ({stats.rating_avg})")

        # Missing privacy policy is a concrete compliance gap
        if not stats.has_privacy_policy:
            low_trust_reasons.append("no privacy policy")

        # NOTE: Low user count is NOT included as a trust signal.
        # Many legitimate extensions have small user bases.

        if len(low_trust_reasons) >= 2:
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.LOW_WEBSTORE_TRUST,
                confidence=0.75,
                evidence_refs=[],
                description=f"Low webstore trust: {', '.join(low_trust_reasons)}",
                severity="medium",
            ))
        
        # Review manipulation flags
        if reviews.manipulation_flags:
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.LOW_WEBSTORE_TRUST,
                confidence=0.70,
                evidence_refs=[],
                description=f"Review manipulation indicators: {', '.join(reviews.manipulation_flags)}",
                severity="medium",
            ))
        
        return signals
    
    def _extract_chromestats_signals(self, signal_pack: "SignalPack") -> List[Signal]:
        """Extract signals from Chrome Stats in SignalPack."""
        signals = []
        cs = signal_pack.chromestats
        
        if not cs.enabled:
            return signals
        
        if cs.overall_risk_level in ["high", "critical"]:
            indicators = cs.risk_indicators[:3]
            signals.append(Signal(
                signal_id=self._next_signal_id(),
                type=SignalType.CHROMESTATS_RISK,
                confidence=0.80,
                evidence_refs=[],
                description=f"ChromeStats risk: {cs.overall_risk_level}. Indicators: {', '.join(indicators)}",
                severity="high" if cs.overall_risk_level == "critical" else "medium",
            ))
        
        return signals
    
    def _link_evidence_to_signals(
        self,
        signal_pack: "SignalPack",
        signals_list: List[Signal],
    ) -> List[Signal]:
        """
        Link evidence from SignalPack to extracted signals.
        
        Args:
            signal_pack: SignalPack with evidence
            signals_list: Extracted signals
            
        Returns:
            Signals with evidence_refs populated
        """
        # Group evidence by tool
        evidence_by_tool: Dict[str, List[str]] = {}
        for ev in signal_pack.evidence:
            tool = ev.tool_name
            if tool not in evidence_by_tool:
                evidence_by_tool[tool] = []
            evidence_by_tool[tool].append(ev.evidence_id)
        
        # Map signal types to tools
        signal_to_tool = {
            SignalType.SAST_CRITICAL: "sast",
            SignalType.SAST_HIGH: "sast",
            SignalType.ENDPOINT_FOUND: "sast",
            SignalType.DATAFLOW_TRACE: "sast",
            SignalType.VIRUSTOTAL_HIT: "virustotal",
            SignalType.OBFUSCATION: "entropy",
            SignalType.HIGH_ENTROPY: "entropy",
            SignalType.HOST_PERMS_BROAD: "permissions",
            SignalType.SENSITIVE_API: "permissions",
            SignalType.UNREASONABLE_PERMISSIONS: "permissions",
            SignalType.LOW_WEBSTORE_TRUST: "webstore_stats",
            SignalType.CHROMESTATS_RISK: "chromestats",
        }
        
        # Link evidence to signals
        for signal in signals_list:
            tool = signal_to_tool.get(signal.type)
            if tool and tool in evidence_by_tool:
                signal.evidence_refs = evidence_by_tool[tool][:10]  # Limit refs
        
        return signals_list

