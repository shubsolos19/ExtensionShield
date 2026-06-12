"""
Consumer-consistency contract: the API serializer (model_dump_for_api), used by
the /recent rebuild/upgrade path, must preserve the audit fields so rebuilt rows
match freshly-scanned payloads (see ADR 0001).
"""

from extension_shield.governance.signal_pack import (
    SastSignalPack,
    SignalPack,
    VirusTotalSignalPack,
)
from extension_shield.scoring.engine import ScoringEngine


def _covered_pack() -> SignalPack:
    pack = SignalPack(scan_id="covered", extension_id="b" * 32)
    pack.sast = SastSignalPack(deduped_findings=[], files_scanned=20, confidence=0.9)
    pack.virustotal = VirusTotalSignalPack(enabled=True, malicious_count=0, total_engines=70)
    return pack


class TestModelDumpForApiPreservesAuditFields:
    REQUIRED = (
        "overall_confidence",
        "insufficient_data",
        "decision_authority",
        "decision_reasons",
        "decision",
    )

    def test_covered_scan_payload_has_audit_fields(self):
        result = ScoringEngine().calculate_scores(
            _covered_pack(), manifest={"name": "x", "manifest_version": 3}
        )
        payload = result.model_dump_for_api()
        for key in self.REQUIRED:
            assert key in payload, f"{key} missing from API payload"
        # Confidence is real, never the 1.0 default.
        assert payload["overall_confidence"] is not None
        assert payload["overall_confidence"] < 1.0
        assert payload["insufficient_data"] is False
        # decision_reasons mirrors reasons for consumer consistency.
        assert payload["decision_reasons"] == result.reasons

    def test_insufficient_data_scan_surfaces_flag_and_reason(self):
        # Zero-coverage pack -> insufficient_data path.
        result = ScoringEngine().calculate_scores(
            SignalPack(scan_id="empty", extension_id="a" * 32),
            manifest={"name": "x", "manifest_version": 3},
        )
        payload = result.model_dump_for_api()
        assert payload["insufficient_data"] is True
        assert payload["decision"] == "NEEDS_REVIEW"
        assert payload["overall_confidence"] < 1.0
        assert "insufficient_data_reason" in payload
        # decision_authority is a non-empty string (which rung decided).
        assert isinstance(payload["decision_authority"], str) and payload["decision_authority"]
