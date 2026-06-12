"""
Tests for the single Decision Authority (scoring.decision.resolve) and its
integration with the scoring engine.

Covers audit fixes:
- P1.1 one precedence chain
- P1.2 overall_confidence never defaults to 1.0
- P1.3 insufficient-data behavior
- P1.4 single threshold policy (DecisionPolicy)
"""

import pytest

from extension_shield.governance.signal_pack import (
    SastSignalPack,
    SignalPack,
    VirusTotalSignalPack,
)
from extension_shield.scoring.decision import (
    DecisionPolicy,
    FinalDecision,
    OrgPolicy,
    resolve,
)
from extension_shield.scoring.engine import ScoringEngine
from extension_shield.scoring.models import Decision


class _Gate:
    """Minimal gate-like object with reasons (duck-typed)."""

    def __init__(self, *reasons):
        self.reasons = list(reasons)


# =============================================================================
# Precedence chain (unit) - P1.1 / P1.4
# =============================================================================

class TestPrecedenceChain:
    EXT = "abcdefghijklmnopqrstuvwxyzabcdef"

    def _clean_kwargs(self):
        return dict(
            extension_id=self.EXT,
            overall_score=95,
            security_score=95,
            privacy_score=95,
            governance_score=95,
            overall_confidence=0.9,
        )

    def test_org_block_wins_over_everything(self):
        final = resolve(
            **{**self._clean_kwargs()},
            blocking_gates=[],
            org_policy=OrgPolicy(block_ids={self.EXT}),
        )
        assert final.verdict == Decision.BLOCK
        assert final.authority == "org_block"

    def test_org_allow_exception_overrides_gates_and_scores(self):
        # Even with a blocking gate and a bad score, an explicit org allow wins.
        final = resolve(
            extension_id=self.EXT,
            overall_score=10,
            security_score=10,
            blocking_gates=[_Gate("malware")],
            baseline_block_reasons=["governance block"],
            overall_confidence=0.9,
            org_policy=OrgPolicy(allow_ids={self.EXT}),
        )
        assert final.verdict == Decision.ALLOW
        assert final.authority == "org_allow_exception"

    def test_baseline_governance_block(self):
        final = resolve(
            **self._clean_kwargs(),
            blocking_gates=[],
            baseline_block_reasons=["Undisclosed data exfiltration"],
        )
        assert final.verdict == Decision.BLOCK
        assert final.authority == "baseline_governance"

    def test_hard_gate_block(self):
        final = resolve(
            **self._clean_kwargs(),
            blocking_gates=[_Gate("VT malware 9/70")],
        )
        assert final.verdict == Decision.BLOCK
        assert final.authority == "hard_gate"
        assert "VT malware 9/70" in final.reasons

    def test_score_threshold_block_uses_policy(self):
        final = resolve(
            extension_id=self.EXT,
            overall_score=20,
            security_score=20,
            overall_confidence=0.9,
            blocking_gates=[],
        )
        assert final.verdict == Decision.BLOCK
        assert final.authority == "score_threshold"

    def test_warning_gate_needs_review(self):
        final = resolve(
            **self._clean_kwargs(),
            blocking_gates=[],
            warning_gates=[_Gate("sensitive exfil risk")],
        )
        assert final.verdict == Decision.NEEDS_REVIEW
        assert final.authority == "score_threshold"

    def test_low_confidence_downgrades_allow(self):
        final = resolve(
            **{**self._clean_kwargs(), "overall_confidence": 0.3},
            blocking_gates=[],
        )
        assert final.verdict == Decision.NEEDS_REVIEW
        assert final.authority == "low_confidence"
        assert final.insufficient_data is True

    def test_insufficient_data_downgrades_allow(self):
        final = resolve(
            **self._clean_kwargs(),
            blocking_gates=[],
            insufficient_data=True,
        )
        assert final.verdict == Decision.NEEDS_REVIEW
        assert final.authority == "insufficient_data"

    def test_clean_high_confidence_allows(self):
        final = resolve(**self._clean_kwargs(), blocking_gates=[])
        assert final.verdict == Decision.ALLOW
        assert final.authority == "score_pass"

    def test_thresholds_are_single_source(self):
        # Guard against reintroducing divergent thresholds.
        assert DecisionPolicy.BLOCK_SCORE == 30
        assert DecisionPolicy.REVIEW_SCORE == 75
        assert 0.0 < DecisionPolicy.LOW_CONFIDENCE < 1.0


# =============================================================================
# Engine integration - P1.2 / P1.3
# =============================================================================

class TestEngineInsufficientData:
    def test_zero_data_extension_not_confident_safe(self):
        """A zero-data extension must NOT look like a confident 80/100 safe."""
        engine = ScoringEngine()
        pack = SignalPack(scan_id="empty", extension_id="a" * 32)
        result = engine.calculate_scores(pack, manifest={"name": "x", "manifest_version": 3})

        assert result.insufficient_data is True
        assert result.overall_score <= 65  # pushed into the review band
        assert result.decision == Decision.NEEDS_REVIEW
        # P1.2: confidence must be real, never the 1.0 default.
        assert result.overall_confidence < 1.0

    def test_overall_confidence_reflects_coverage(self):
        """With SAST + VT coverage, confidence should be clearly higher than empty."""
        engine = ScoringEngine()

        empty = SignalPack(scan_id="empty", extension_id="a" * 32)
        empty_result = engine.calculate_scores(empty, manifest={"name": "x", "manifest_version": 3})

        covered = SignalPack(scan_id="covered", extension_id="b" * 32)
        covered.sast = SastSignalPack(deduped_findings=[], files_scanned=20, confidence=0.9)
        covered.virustotal = VirusTotalSignalPack(enabled=True, malicious_count=0, total_engines=70)
        covered_result = engine.calculate_scores(
            covered, manifest={"name": "x", "manifest_version": 3}
        )

        assert covered_result.overall_confidence > empty_result.overall_confidence
        assert covered_result.insufficient_data is False
