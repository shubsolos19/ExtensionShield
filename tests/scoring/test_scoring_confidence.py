"""
Scoring Confidence Tests

Tests that confidence is properly handled for missing/incomplete data:
- Missing VT should not inflate scores (confidence=0 excludes from formula)
- Explanation should include low confidence when data is missing

Based on normalize_virustotal() behavior:
- enabled=False → confidence=0.0, severity=0.0 (excluded from formula)
- total_engines=0 → confidence=0.0 (rate-limited, excluded)
- total_engines < 30 → confidence=0.7 (partial scan)
- total_engines >= 30 → confidence=1.0 (full scan)

Uses test utilities from tests/scoring/utils.py to construct valid SignalPacks.
"""

import pytest
import sys
from pathlib import Path

# Add tests directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scoring.utils import (
    make_min_signal_pack,
    add_webstore_stats,
    make_test_manifest,
)
from extension_shield.scoring.engine import ScoringEngine
from extension_shield.scoring.normalizers import normalize_virustotal
from extension_shield.governance.signal_pack import VirusTotalSignalPack


class TestVirusTotalConfidence:
    """Test VT confidence behavior based on data availability."""
    
    def test_normalize_virustotal_missing_returns_zero_confidence(self):
        """
        Test: When VT is disabled, normalize_virustotal returns confidence=0.0
        so that the factor is excluded from the weighted formula entirely.
        """
        vt_missing = VirusTotalSignalPack(enabled=False)
        
        factor = normalize_virustotal(vt_missing)
        
        print(f"\nVT disabled: severity={factor.severity}, confidence={factor.confidence}")
        
        assert factor.severity == 0.0, "Missing VT should have severity 0"
        assert factor.confidence == 0.0, "Missing VT should have confidence 0.0"
    
    def test_normalize_virustotal_rate_limited_returns_zero_confidence(self):
        """
        Test: When VT has total_engines=0 (rate-limited), confidence is 0.0
        so that the factor is excluded from the weighted formula.
        """
        vt_rate_limited = VirusTotalSignalPack(
            enabled=True,
            malicious_count=0,
            total_engines=0,  # Rate-limited
        )
        
        factor = normalize_virustotal(vt_rate_limited)
        
        print(f"\nVT rate-limited: severity={factor.severity}, confidence={factor.confidence}")
        
        assert factor.confidence == 0.0, "Rate-limited VT should have confidence 0.0"
    
    def test_normalize_virustotal_partial_scan_returns_medium_confidence(self):
        """
        Test: When VT has partial engines (<30), confidence is 0.7.
        """
        vt_partial = VirusTotalSignalPack(
            enabled=True,
            malicious_count=0,
            total_engines=25,  # Partial scan
        )
        
        factor = normalize_virustotal(vt_partial)
        
        print(f"\nVT partial: severity={factor.severity}, confidence={factor.confidence}")
        
        assert factor.confidence == 0.7, "Partial VT should have confidence 0.7"
    
    def test_normalize_virustotal_full_scan_returns_high_confidence(self):
        """
        Test: When VT has full engines (>=30), confidence is 1.0.
        """
        vt_full = VirusTotalSignalPack(
            enabled=True,
            malicious_count=0,
            total_engines=70,  # Full scan
        )
        
        factor = normalize_virustotal(vt_full)
        
        print(f"\nVT full: severity={factor.severity}, confidence={factor.confidence}")
        
        assert factor.confidence == 1.0, "Full VT should have confidence 1.0"


class TestMissingVTDoesNotDrasticallyReduceScore:
    """Test that missing VT data doesn't drastically reduce scores."""
    
    @pytest.fixture
    def engine(self):
        """Create a scoring engine instance."""
        return ScoringEngine(weights_version="v1")
    
    @pytest.fixture
    def manifest(self):
        """Create a test manifest."""
        return make_test_manifest()
    
    def test_missing_vt_score_difference_less_than_10(self, engine, manifest):
        """
        Test: Missing VT should not reduce security_score by more than 10 points.
        
        Since VT weight is 0.15 and missing VT has severity=0 (not high),
        the score impact should be minimal.
        """
        # Both packs have SAST coverage so we isolate VT's *marginal* effect.
        # (Zero-coverage behavior is covered by the insufficient-data tests; a pack
        # whose only signal is VT is not a realistic baseline for this comparison.)
        from extension_shield.governance.signal_pack import SastSignalPack

        # Pack with VT enabled and clean
        pack_with_vt = make_min_signal_pack(scan_id="with-vt")
        pack_with_vt.sast = SastSignalPack(deduped_findings=[], files_scanned=12, confidence=0.9)
        pack_with_vt.virustotal = VirusTotalSignalPack(
            enabled=True,
            malicious_count=0,
            suspicious_count=0,
            total_engines=70,
        )
        add_webstore_stats(pack_with_vt, installs=10000, rating_avg=4.5)

        result_with_vt = engine.calculate_scores(pack_with_vt, manifest, user_count=10000)

        # Pack with VT disabled (missing) but SAST coverage present
        pack_missing_vt = make_min_signal_pack(scan_id="missing-vt")
        pack_missing_vt.sast = SastSignalPack(deduped_findings=[], files_scanned=12, confidence=0.9)
        pack_missing_vt.virustotal = VirusTotalSignalPack(enabled=False)
        add_webstore_stats(pack_missing_vt, installs=10000, rating_avg=4.5)
        
        result_missing_vt = engine.calculate_scores(pack_missing_vt, manifest, user_count=10000)
        
        print(f"\nWith VT: security={result_with_vt.security_score}, overall={result_with_vt.overall_score}")
        print(f"Missing VT: security={result_missing_vt.security_score}, overall={result_missing_vt.overall_score}")
        
        security_diff = abs(result_with_vt.security_score - result_missing_vt.security_score)
        overall_diff = abs(result_with_vt.overall_score - result_missing_vt.overall_score)
        
        print(f"Security difference: {security_diff}")
        print(f"Overall difference: {overall_diff}")
        
        assert security_diff < 10, (
            f"Missing VT should not reduce security_score by more than 10, "
            f"got difference of {security_diff}"
        )
        assert overall_diff < 10, (
            f"Missing VT should not reduce overall_score by more than 10, "
            f"got difference of {overall_diff}"
        )
    
    def test_missing_vt_vs_rate_limited_similar_scores(self, engine, manifest):
        """
        Test: Missing VT (enabled=False) and rate-limited (total_engines=0)
        should produce similar scores since both have low confidence.
        """
        # VT disabled
        pack_disabled = make_min_signal_pack(scan_id="vt-disabled")
        pack_disabled.virustotal = VirusTotalSignalPack(enabled=False)
        add_webstore_stats(pack_disabled, installs=10000)
        
        result_disabled = engine.calculate_scores(pack_disabled, manifest)
        
        # VT rate-limited
        pack_rate_limited = make_min_signal_pack(scan_id="vt-rate-limited")
        pack_rate_limited.virustotal = VirusTotalSignalPack(
            enabled=True,
            malicious_count=0,
            total_engines=0,
        )
        add_webstore_stats(pack_rate_limited, installs=10000)
        
        result_rate_limited = engine.calculate_scores(pack_rate_limited, manifest)
        
        print(f"\nVT disabled: security={result_disabled.security_score}")
        print(f"VT rate-limited: security={result_rate_limited.security_score}")
        
        diff = abs(result_disabled.security_score - result_rate_limited.security_score)
        print(f"Difference: {diff}")
        
        # Both should have similar scores (within 5 points)
        assert diff <= 5, (
            f"Disabled and rate-limited VT should have similar scores, "
            f"got difference of {diff}"
        )


class TestExplanationIncludesConfidence:
    """Test that explanation includes confidence information."""
    
    @pytest.fixture
    def engine(self):
        """Create a scoring engine instance."""
        return ScoringEngine(weights_version="v1")
    
    @pytest.fixture
    def manifest(self):
        """Create a test manifest."""
        return make_test_manifest()
    
    def test_explanation_includes_vt_factor_with_low_confidence(self, engine, manifest):
        """
        Test: When VT is missing, explanation should show VirusTotal factor
        with low confidence (<0.5).
        """
        pack_missing_vt = make_min_signal_pack(scan_id="missing-vt-explain")
        pack_missing_vt.virustotal = VirusTotalSignalPack(enabled=False)
        add_webstore_stats(pack_missing_vt, installs=10000)
        
        result = engine.calculate_scores(pack_missing_vt, manifest)
        explanation = engine.get_explanation()
        
        # Find VT factor in security layer
        security_layer = explanation.security
        assert security_layer is not None, "Security layer should exist in explanation"
        
        vt_factor = None
        for factor in security_layer.factors:
            if factor.name == "VirusTotal":
                vt_factor = factor
                break
        
        print(f"\nVT factor in explanation:")
        if vt_factor:
            print(f"  name: {vt_factor.name}")
            print(f"  severity: {vt_factor.severity}")
            print(f"  confidence: {vt_factor.confidence}")
        else:
            print("  Not found!")
        
        assert vt_factor is not None, "VirusTotal factor should be in explanation"
        assert vt_factor.confidence < 0.5, (
            f"Missing VT should show confidence < 0.5, got {vt_factor.confidence}"
        )
    
    def test_explanation_includes_overall_confidence(self, engine, manifest):
        """
        Test: Explanation should include overall_confidence field.
        """
        pack = make_min_signal_pack(scan_id="confidence-test")
        pack.virustotal = VirusTotalSignalPack(enabled=True, malicious_count=0, total_engines=70)
        add_webstore_stats(pack, installs=10000)
        
        result = engine.calculate_scores(pack, manifest)
        explanation = engine.get_explanation()
        
        print(f"\nOverall confidence in result: {result.overall_confidence}")
        print(f"Overall confidence in explanation: {explanation.overall_confidence}")
        
        assert hasattr(explanation, "overall_confidence"), (
            "Explanation should have overall_confidence"
        )
        assert 0 <= explanation.overall_confidence <= 1, (
            f"Overall confidence should be in [0,1], got {explanation.overall_confidence}"
        )
    
    def test_explanation_layer_includes_confidence(self, engine, manifest):
        """
        Test: Each layer in explanation should include its confidence.
        """
        pack = make_min_signal_pack(scan_id="layer-confidence")
        pack.virustotal = VirusTotalSignalPack(enabled=True, malicious_count=0, total_engines=70)
        add_webstore_stats(pack, installs=10000)
        
        result = engine.calculate_scores(pack, manifest)
        explanation = engine.get_explanation()
        
        for layer_name in ["security", "privacy", "governance"]:
            layer = getattr(explanation, layer_name, None)
            assert layer is not None, f"{layer_name} layer should exist"
            assert hasattr(layer, "confidence"), f"{layer_name} should have confidence"
            print(f"  {layer_name} layer confidence: {layer.confidence}")
            assert 0 <= layer.confidence <= 1, (
                f"{layer_name} confidence should be in [0,1], got {layer.confidence}"
            )


class TestConfidenceWeightedScoring:
    """Test that low confidence factors have less impact on scores."""
    
    @pytest.fixture
    def engine(self):
        """Create a scoring engine instance."""
        return ScoringEngine(weights_version="v1")
    
    @pytest.fixture
    def manifest(self):
        """Create a test manifest."""
        return make_test_manifest()
    
    def test_low_confidence_factor_has_less_impact(self, engine, manifest):
        """
        Test: A factor with low confidence should have less impact on the score
        than the same severity with high confidence.
        
        This is verified by the confidence-weighted formula:
        R = Σ(w_i * c_i * s_i) / Σ(w_i * c_i)
        """
        # Test with partial VT data (confidence 0.7 vs 1.0)
        pack_full = make_min_signal_pack(scan_id="vt-full")
        pack_full.virustotal = VirusTotalSignalPack(
            enabled=True,
            malicious_count=2,  # Same severity
            total_engines=70,   # Full scan = confidence 1.0
        )
        add_webstore_stats(pack_full, installs=10000)
        
        result_full = engine.calculate_scores(pack_full, manifest)
        
        pack_partial = make_min_signal_pack(scan_id="vt-partial")
        pack_partial.virustotal = VirusTotalSignalPack(
            enabled=True,
            malicious_count=2,  # Same severity
            total_engines=25,   # Partial scan = confidence 0.7
        )
        add_webstore_stats(pack_partial, installs=10000)
        
        result_partial = engine.calculate_scores(pack_partial, manifest)
        
        print(f"\nFull VT (conf 1.0): security={result_full.security_score}")
        print(f"Partial VT (conf 0.7): security={result_partial.security_score}")
        
        # With same severity but lower confidence, score should be higher
        # (less impact from the risky factor)
        assert result_partial.security_score >= result_full.security_score, (
            "Lower confidence should mean less score impact for same severity"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

