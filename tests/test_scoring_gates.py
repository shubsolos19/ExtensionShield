import pytest

from extension_shield.governance.signal_pack import (
    SastFindingNormalized,
    SastSignalPack,
    SignalPack,
    VirusTotalSignalPack,
)
from extension_shield.scoring.engine import ScoringEngine
from extension_shield.scoring.gates import HardGates


def test_critical_high_sast_pattern_triggers_block():
    """HIGH/ERROR SAST finding matching a critical pattern should BLOCK even if count < threshold."""
    finding = SastFindingNormalized(
        check_id="EVAL_USAGE",
        file_path="src/content.js",
        line_number=42,
        severity="HIGH",
        message="Use of eval('...') for dynamic code execution",
    )

    sast_pack = SastSignalPack(
        raw_findings={"src/content.js": 1},
        deduped_findings=[finding],
        counts_by_severity={"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0},
        confidence=0.9,
        files_scanned=1,
        files_with_findings=1,
    )

    gates = HardGates()
    result = gates.evaluate_critical_sast(sast_pack)

    assert result.gate_id == "CRITICAL_SAST"
    assert result.triggered is True
    assert result.decision == "BLOCK"
    assert any(
        "Dangerous code pattern found" in reason for reason in result.reasons
    )


def test_sast_missing_coverage_caps_score_and_sets_review():
    """When SAST coverage is missing, overall score is capped and decision is at least NEEDS_REVIEW."""
    signal_pack = SignalPack(scan_id="test-scan")

    # Ensure SAST coverage is missing: default SastSignalPack has files_scanned == 0
    assert signal_pack.sast.files_scanned == 0
    assert signal_pack.sast.deduped_findings == []
    # Provide VirusTotal coverage so this exercises the SAST-only cap (80), not the
    # broader insufficient-data path (which applies only when SAST+VT+network are all absent).
    signal_pack.virustotal = VirusTotalSignalPack(
        enabled=True, malicious_count=0, total_engines=70
    )

    engine = ScoringEngine()
    result = engine.calculate_scores(signal_pack, manifest={})

    assert result.overall_score <= 80
    assert result.decision.name == "NEEDS_REVIEW"
    assert any(
        "SAST coverage missing; score capped at 80" in reason
        for reason in result.reasons
    )



