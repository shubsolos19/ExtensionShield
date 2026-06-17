"""
Regression tests for `build_report_view_model(skip_llm=True)`.

The retrieval/rebuild path passes skip_llm=True to avoid LLM latency and network
dependency. Previously two surfaces ignored the flag and called the LLM anyway:
the layer-details generator and the unified consumer summary. This pins that
skip_llm=True takes the deterministic path for every LLM-backed surface, while
the default (skip_llm=False) still attempts the LLM.
"""

import pytest

import extension_shield.core.report_view_model as rvm

VALID_EXT_ID = "abcdefghijklmnopabcdefghijklmnop"  # 32 chars in [a-p]
MANIFEST = {
    "name": "Skip LLM Example",
    "version": "1.0.0",
    "manifest_version": 3,
    "permissions": ["storage"],
    "host_permissions": [],
}


def _rig_llm_to_explode(monkeypatch):
    """Make every LLM entry point raise, so any LLM call fails the test."""
    def boom(*args, **kwargs):
        raise AssertionError("LLM must not be called when skip_llm=True")

    monkeypatch.setattr(rvm.SummaryGenerator, "generate", boom)
    monkeypatch.setattr(rvm.ImpactAnalyzer, "generate", boom)
    monkeypatch.setattr(rvm.PrivacyComplianceAnalyzer, "generate", boom)
    monkeypatch.setattr(rvm.LayerDetailsGenerator, "generate", boom)
    import extension_shield.llm.clients.fallback as fb
    monkeypatch.setattr(fb, "invoke_with_fallback", boom)


def test_skip_llm_build_uses_only_deterministic_fallbacks(monkeypatch):
    _rig_llm_to_explode(monkeypatch)

    report = rvm.build_report_view_model(
        manifest=MANIFEST,
        analysis_results={},
        metadata={},
        extension_id=VALID_EXT_ID,
        scan_id="s1",
        skip_llm=True,
    )

    # Unified summary came from the deterministic fallback, not the LLM.
    assert report["unified_summary"]["source"] == "fallback"
    # Layer details still fully populated by the deterministic generator.
    assert set(report["layer_details"].keys()) == {"security", "privacy", "governance"}
    # Core surfaces are present.
    assert "scorecard" in report
    assert "consumer_summary" in report
    assert set(report["consumer_insights"].keys()) == {"safety_label", "scenarios", "top_drivers"}


def test_skip_llm_unified_summary_helper_short_circuits(monkeypatch):
    """build_unified_consumer_summary(skip_llm=True) returns the fallback directly."""
    import extension_shield.llm.clients.fallback as fb
    monkeypatch.setattr(
        fb, "invoke_with_fallback",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("LLM called")),
    )
    out = rvm.build_unified_consumer_summary(
        report_view_model={
            "scorecard": {"score": 40, "score_label": "MEDIUM RISK"},
            "evidence": {"host_access_summary": {}, "capability_flags": {}},
            "layer_details": {},
            "highlights": {},
            "meta": {"name": "X"},
        },
        scoring_v2={"decision": "BLOCK"},
        skip_llm=True,
    )
    assert out["source"] == "fallback"
    # Verdict-aware: a BLOCK must not be softened.
    blob = (out["headline"] + " " + out["recommendation"]).lower()
    assert any(p in blob for p in ["blocked", "not safe", "do not install"])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
