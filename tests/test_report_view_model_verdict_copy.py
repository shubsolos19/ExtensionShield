"""
Regression tests for verdict-driven consumer copy (Phase 1 follow-up).

The bug: report_view_model summary copy was keyed on the numeric score label,
so a BLOCKed extension whose score landed in the "medium" band rendered as
"Review before installing — … needs some attention." (see the Check US Visa
Slots report). The authoritative governance verdict — not the score — must own
the headline, TL;DR, recommendation, verdict, and action copy.

These tests pin the deterministic fallbacks (the LLM-free path) and the label
reconciliation helpers. They do NOT touch decision.resolve() precedence or any
detection logic.
"""

import pytest

from extension_shield.core.report_view_model import (
    _normalize_verdict,
    _reconcile_score_label,
    _fallback_unified_consumer_summary,
    build_consumer_summary,
)

# Phrases that must never appear for a BLOCK verdict (they soften a block).
SOFTENING_PHRASES = [
    "review before installing",
    "needs some attention",
    "moderate issues",
    "appears safe",
    "safe for general use",
    "some permissions and behaviors need review",
]

BLOCKING_PHRASES = ["blocked", "not safe", "do not install"]


def _has_any(text: str, needles) -> bool:
    t = (text or "").lower()
    return any(n in t for n in needles)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestVerdictHelpers:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("BLOCK", "BLOCK"),
            ("block", "BLOCK"),
            ("NEEDS_REVIEW", "NEEDS_REVIEW"),
            ("WARN", "NEEDS_REVIEW"),
            ("ALLOW", "ALLOW"),
            ("", "UNKNOWN"),
            (None, "UNKNOWN"),
        ],
    )
    def test_normalize_verdict(self, raw, expected):
        assert _normalize_verdict(raw) == expected

    def test_normalize_verdict_accepts_enum_like(self):
        class _D:
            value = "BLOCK"

        assert _normalize_verdict(_D()) == "BLOCK"

    def test_reconcile_only_raises_label(self):
        # BLOCK forces HIGH RISK regardless of the score-derived label.
        assert _reconcile_score_label("MEDIUM RISK", "BLOCK") == "HIGH RISK"
        assert _reconcile_score_label("LOW RISK", "BLOCK") == "HIGH RISK"
        # NEEDS_REVIEW lifts LOW RISK to MEDIUM but never lowers.
        assert _reconcile_score_label("LOW RISK", "NEEDS_REVIEW") == "MEDIUM RISK"
        assert _reconcile_score_label("HIGH RISK", "NEEDS_REVIEW") == "HIGH RISK"
        # ALLOW / unknown never change the label.
        assert _reconcile_score_label("LOW RISK", "ALLOW") == "LOW RISK"
        assert _reconcile_score_label("MEDIUM RISK", "UNKNOWN") == "MEDIUM RISK"


# ---------------------------------------------------------------------------
# Unified consumer summary fallback (the exact path that produced the bug)
# ---------------------------------------------------------------------------

class TestUnifiedFallbackVerdictCopy:
    def _summary(self, verdict, score_label="MEDIUM RISK"):
        # The Check US Visa Slots shape: BLOCK verdict but a mid-band score label.
        return _fallback_unified_consumer_summary(
            score=53,
            score_label=score_label,
            host_access={"host_scope_label": "SINGLE_DOMAIN"},
            capability_flags={},
            layer_details={},
            highlights={},
            extension_name="Check US Visa Slots",
            verdict=verdict,
        )

    def test_block_never_softens(self):
        out = self._summary("BLOCK", score_label="MEDIUM RISK")
        blob = " ".join([out["headline"], out["narrative"], out["tldr"], out["recommendation"]])
        assert not _has_any(blob, SOFTENING_PHRASES), f"softening copy leaked: {blob}"
        # And it must read as a block.
        assert _has_any(out["headline"] + out["recommendation"], BLOCKING_PHRASES)

    def test_block_even_with_low_risk_label(self):
        out = self._summary("BLOCK", score_label="LOW RISK")
        blob = " ".join([out["headline"], out["narrative"], out["tldr"], out["recommendation"]])
        assert not _has_any(blob, SOFTENING_PHRASES)
        assert _has_any(out["headline"], ["not safe", "blocked"])

    def test_needs_review_not_shown_as_safe(self):
        out = self._summary("NEEDS_REVIEW", score_label="LOW RISK")
        blob = " ".join([out["headline"], out["narrative"], out["tldr"], out["recommendation"]])
        assert not _has_any(blob, ["appears safe", "safe for general use"])
        assert "review" in blob.lower()

    def test_allow_unchanged_low_risk(self):
        # ALLOW must still be allowed to read as safe (no over-warning).
        out = self._summary("ALLOW", score_label="LOW RISK")
        assert "appears safe" in out["headline"].lower()


# ---------------------------------------------------------------------------
# Compact consumer summary (verdict + action)
# ---------------------------------------------------------------------------

class TestConsumerSummaryVerdictCopy:
    def _rvm(self, score_label="MEDIUM RISK"):
        return {
            "scorecard": {"score": 53, "score_label": score_label, "one_liner": ""},
            "highlights": {"why_this_score": ["x"], "what_to_watch": ["Watch for updates."]},
            "evidence": {"host_access_summary": {}, "capability_flags": {}},
            "consumer_insights": {},
            "layer_details": {},
        }

    def test_block_verdict_and_action(self):
        out = build_consumer_summary(self._rvm(), scoring_v2={"decision": "BLOCK"})
        assert _has_any(out["verdict"], BLOCKING_PHRASES)
        assert not _has_any(out["verdict"], SOFTENING_PHRASES)
        # Action must not defer to the softer "Watch for updates." highlight.
        assert _has_any(out["action"], ["do not install", "security review"])

    def test_needs_review_action(self):
        out = build_consumer_summary(self._rvm(), scoring_v2={"decision": "NEEDS_REVIEW"})
        assert "review" in out["verdict"].lower()
        assert not _has_any(out["verdict"], ["appears safe", "safe for general use"])

    def test_allow_keeps_score_driven_copy(self):
        out = build_consumer_summary(self._rvm(score_label="LOW RISK"), scoring_v2={"decision": "ALLOW"})
        # ALLOW falls through to the what_to_watch / score-label copy.
        assert not _has_any(out["verdict"], BLOCKING_PHRASES)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
