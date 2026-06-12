"""
Tests for the declarative PROTECTED_SERVICE_AUTOMATION rulepack (P3).

Verifies that the visa/travel-doc detection migrated from hardcoded
gates.py/engine.py logic into config/protected_services.yaml +
governance/protected_services.py + the rulepack still BLOCKs CheckVisaSlots,
end to end through the SignalExtractor and RulesEngine.
"""

from pathlib import Path

import pytest

from extension_shield.governance.protected_services import (
    ECOSYSTEM_DOMAINS,
    PROTECTED_SERVICE_DOMAINS,
    detect,
)
from extension_shield.governance.rules_engine import RulesEngine
from extension_shield.governance.signal_extractor import SignalExtractor, SignalType
from extension_shield.governance.signal_pack import (
    NetworkSignalPack,
    PermissionsSignalPack,
    SastFindingNormalized,
    SastSignalPack,
    SignalPack,
    WebstoreStatsSignalPack,
)

RULEPACKS_DIR = (
    Path(__file__).parent.parent.parent
    / "src" / "extension_shield" / "governance" / "rulepacks"
)


def _checkvisaslots_pack() -> SignalPack:
    """Synthetic CheckVisaSlots pack (no real data) - mirrors P2 fixture."""
    findings = [
        SastFindingNormalized(
            check_id="credential-autofill", file_path="js/content.js", severity="HIGH",
            message="Writes username/password into #signInName and #password (loginDetails)",
            code_snippet="document.querySelector('#password').value = loginDetails.password",
        ),
        SastFindingNormalized(
            check_id="security-question-autofill", file_path="js/content.js", severity="HIGH",
            message="auto-fills security questions during login",
        ),
        SastFindingNormalized(
            check_id="screenshot-capture", file_path="js/content.js", severity="HIGH",
            message="html2canvas appointment page export",
            code_snippet="html2canvas(el).then(c => c.toDataURL('image/png'))",
        ),
        SastFindingNormalized(
            check_id="xhr-interception", file_path="js/page.js", severity="HIGH",
            message="overrides portal API", code_snippet="XMLHttpRequest.prototype.send = function(){}",
        ),
        SastFindingNormalized(
            check_id="external-exfil", file_path="js/sw.js", severity="HIGH",
            message="fetch sends appointment/identity data to third party",
            code_snippet="fetch('https://app.checkvisaslots.com/push/v5')",
        ),
    ]
    return SignalPack(
        scan_id="cvs", extension_id="beepaenfejnphdgnkmccjcfiieihhogl",
        sast=SastSignalPack(deduped_findings=findings, files_scanned=8, confidence=0.9),
        permissions=PermissionsSignalPack(
            api_permissions=["storage", "activeTab", "scripting"],
            host_permissions=["https://*.usvisascheduling.com/*"],
            total_permissions=4,
        ),
        network=NetworkSignalPack(enabled=True, domains=["app.checkvisaslots.com"], confidence=0.8),
        webstore_stats=WebstoreStatsSignalPack(has_privacy_policy=False),
    )


class TestDeclarativeSingleSource:
    def test_gates_reuse_declarative_domains(self):
        """The legacy gate names must point at the declarative single source."""
        from extension_shield.scoring import gates

        assert gates.TRAVEL_DOCS_PROTECTED_DOMAINS == PROTECTED_SERVICE_DOMAINS
        assert gates.VISA_SLOT_ECOSYSTEM_DOMAINS == ECOSYSTEM_DOMAINS
        assert "usvisascheduling.com" in PROTECTED_SERVICE_DOMAINS
        assert "checkvisaslots.com" in ECOSYSTEM_DOMAINS


class TestDetector:
    def test_detects_all_categories(self):
        det = detect(_checkvisaslots_pack(), manifest={})
        assert det.protected_domain
        assert det.is_protected_service_automation
        assert det.screenshot_capture
        assert det.xhr_interception
        assert det.credential_capture
        assert det.external_exfil
        assert det.identity_keywords


class TestSignalEmission:
    def test_emits_protected_service_signals(self):
        signals = SignalExtractor().extract_from_signal_pack(_checkvisaslots_pack())
        types = {s.type for s in signals.signals}
        assert SignalType.PROTECTED_SERVICE_AUTOMATION in types
        assert SignalType.CREDENTIAL_CAPTURE in types
        assert SignalType.IDENTITY_DATA_EXFIL in types
        assert SignalType.SCREENSHOT_CAPTURE in types


class TestRulepackBlocks:
    def test_rulepack_blocks_checkvisaslots(self):
        rulepacks, errors = RulesEngine.load_rulepacks_with_report(str(RULEPACKS_DIR))
        assert not errors, f"rulepacks failed validation: {errors}"

        signals = SignalExtractor().extract_from_signal_pack(_checkvisaslots_pack())
        engine = RulesEngine(rulepacks)
        results = engine.evaluate(
            scan_id="cvs",
            facts={},
            signals=[s.model_dump(mode="json") for s in signals.signals],
            store_listing={},
            context={"rulepacks": ["PROTECTED_SERVICE_AUTOMATION"]},
        )
        verdicts = [r.verdict for r in results.rule_results]
        assert "BLOCK" in verdicts, f"expected BLOCK, got {verdicts}"
        # The two BLOCK rules (R1 automation+capture, R2 credential capture) must fire.
        blocked_ids = {r.rule_id for r in results.rule_results if r.verdict == "BLOCK"}
        assert "PROTECTED_SERVICE_AUTOMATION::R1" in blocked_ids
        assert "PROTECTED_SERVICE_AUTOMATION::R2" in blocked_ids

    def test_new_rulepack_is_valid_and_loaded(self):
        rulepacks, errors = RulesEngine.load_rulepacks_with_report(str(RULEPACKS_DIR))
        ids = {rp.get("rulepack_id") for rp in rulepacks}
        assert "PROTECTED_SERVICE_AUTOMATION" in ids
        assert errors == []
