"""
Decision Authority - THE single source of truth for the final verdict.

Every consumer (scoring engine, governance node, hard-gate convenience helpers)
must derive its verdict from :func:`resolve` so there is exactly one precedence
chain in the system.

Precedence chain (highest authority first):

    1. org_block            - explicit organization blocklist            -> BLOCK
    2. org_allow_exception  - explicit organization allow exception      -> ALLOW
    3. baseline_governance  - baseline governance rulepack BLOCK         -> BLOCK
    4. hard_gate            - hard security/privacy gate BLOCK           -> BLOCK
    5. score_threshold      - score below BLOCK / REVIEW thresholds,
                              warning gates, or baseline review rules    -> BLOCK / NEEDS_REVIEW
    6. low_confidence       - insufficient coverage / low confidence
                              downgrades an otherwise-ALLOW to review    -> NEEDS_REVIEW
    7. score_pass           - everything cleared                         -> ALLOW

Notes:
- Rungs 1-2 are organization overrides. An explicit org ALLOW exception wins over
  every automated signal below it (that is the point of an exception); an explicit
  org BLOCK wins over everything.
- The low-confidence / insufficient-data rung can only *downgrade* a tentative
  ALLOW to NEEDS_REVIEW. It never upgrades a BLOCK back to ALLOW.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, List, Optional, Sequence, Set

from extension_shield.scoring.models import Decision


# =============================================================================
# SHARED THRESHOLD POLICY  (single source of truth - P1.4)
# =============================================================================

class DecisionPolicy:
    """Canonical decision thresholds shared by engine.py and gates.py.

    There must be exactly one of these. Do not redefine thresholds elsewhere.
    """

    # Score at/below which a layer or overall score forces BLOCK.
    BLOCK_SCORE: int = 30
    # Score below which a layer or overall score forces NEEDS_REVIEW.
    REVIEW_SCORE: int = 75
    # Overall confidence below which an otherwise-ALLOW is downgraded to review.
    LOW_CONFIDENCE: float = 0.5


# =============================================================================
# ORG POLICY (optional override inputs)
# =============================================================================

@dataclass(frozen=True)
class OrgPolicy:
    """Optional organization-level overrides.

    Defaults are empty, so when no org policy is supplied the chain reduces to
    the automated rungs (baseline governance -> hard gate -> score -> confidence).
    """

    block_ids: Set[str] = field(default_factory=set)
    allow_ids: Set[str] = field(default_factory=set)

    def is_blocked(self, extension_id: str) -> bool:
        return bool(extension_id) and extension_id in self.block_ids

    def is_allowed(self, extension_id: str) -> bool:
        return bool(extension_id) and extension_id in self.allow_ids


# =============================================================================
# RESULT
# =============================================================================

@dataclass
class FinalDecision:
    """The single authoritative verdict plus which rung produced it."""

    verdict: Decision
    authority: str
    reasons: List[str] = field(default_factory=list)
    insufficient_data: bool = False


def _gate_reasons(gates: Iterable[Any], limit: int = 2) -> List[str]:
    """Collect human-readable reasons from gate-like objects (duck-typed)."""
    out: List[str] = []
    for g in gates or []:
        reasons = getattr(g, "reasons", None) or []
        out.extend(list(reasons)[:limit])
    return out


# =============================================================================
# THE ONE PRECEDENCE CHAIN
# =============================================================================

def resolve(
    *,
    extension_id: str = "",
    overall_score: int,
    security_score: int,
    privacy_score: int = 100,
    governance_score: int = 100,
    blocking_gates: Sequence[Any] = (),
    warning_gates: Sequence[Any] = (),
    overall_confidence: float = 1.0,
    insufficient_data: bool = False,
    extra_review_reasons: Optional[Sequence[str]] = None,
    baseline_block_reasons: Optional[Sequence[str]] = None,
    baseline_review_reasons: Optional[Sequence[str]] = None,
    org_policy: Optional[OrgPolicy] = None,
    policy: type[DecisionPolicy] = DecisionPolicy,
) -> FinalDecision:
    """Resolve the final verdict from all signals using one precedence chain.

    Args:
        extension_id: Extension ID (for org policy lookups).
        overall_score / security_score / privacy_score / governance_score: [0-100].
        blocking_gates / warning_gates: hard-gate results (objects with ``.reasons``).
        overall_confidence: layer-weighted confidence [0,1].
        insufficient_data: True when analysis coverage is too low to clear as safe.
        extra_review_reasons: coverage-driven review reasons (e.g. SAST cap).
        baseline_block_reasons / baseline_review_reasons: governance rulepack verdicts.
        org_policy: optional organization overrides.

    Returns:
        FinalDecision with verdict, deciding authority, and reasons.
    """
    # Rung 1: explicit org BLOCK
    if org_policy is not None and org_policy.is_blocked(extension_id):
        return FinalDecision(
            verdict=Decision.BLOCK,
            authority="org_block",
            reasons=["Organization policy blocks this extension"],
        )

    # Rung 2: explicit org ALLOW exception (overrides every automated rung below)
    if org_policy is not None and org_policy.is_allowed(extension_id):
        return FinalDecision(
            verdict=Decision.ALLOW,
            authority="org_allow_exception",
            reasons=["Organization policy explicitly allows this extension (exception)"],
        )

    # Rung 3: baseline governance BLOCK (rulepacks)
    if baseline_block_reasons:
        return FinalDecision(
            verdict=Decision.BLOCK,
            authority="baseline_governance",
            reasons=list(baseline_block_reasons)[:4],
        )

    # Rung 4: hard security/privacy gate BLOCK
    if blocking_gates:
        return FinalDecision(
            verdict=Decision.BLOCK,
            authority="hard_gate",
            reasons=_gate_reasons(blocking_gates) or ["Hard security/privacy gate triggered"],
        )

    # Rung 5: scoring thresholds (BLOCK first, then accumulate review reasons)
    if security_score < policy.BLOCK_SCORE:
        return FinalDecision(
            verdict=Decision.BLOCK,
            authority="score_threshold",
            reasons=[f"Security score {security_score}/100 critically low"],
        )
    if overall_score < policy.BLOCK_SCORE:
        return FinalDecision(
            verdict=Decision.BLOCK,
            authority="score_threshold",
            reasons=[f"Overall score {overall_score}/100 critically low"],
        )

    review_reasons: List[str] = []
    review_reasons.extend(_gate_reasons(warning_gates))
    if baseline_review_reasons:
        review_reasons.extend(list(baseline_review_reasons))
    if extra_review_reasons:
        review_reasons.extend(list(extra_review_reasons))
    if security_score < policy.REVIEW_SCORE:
        review_reasons.append(f"Security score {security_score}/100 below threshold")
    if overall_score < policy.REVIEW_SCORE:
        review_reasons.append(f"Overall score {overall_score}/100 below threshold")

    if review_reasons:
        return FinalDecision(
            verdict=Decision.NEEDS_REVIEW,
            authority="score_threshold",
            reasons=review_reasons,
        )

    # Rung 6: low-confidence / insufficient-data override (only downgrades ALLOW)
    if insufficient_data:
        return FinalDecision(
            verdict=Decision.NEEDS_REVIEW,
            authority="insufficient_data",
            reasons=["Insufficient analysis coverage to clear this extension as safe"],
            insufficient_data=True,
        )
    if overall_confidence < policy.LOW_CONFIDENCE:
        return FinalDecision(
            verdict=Decision.NEEDS_REVIEW,
            authority="low_confidence",
            reasons=[
                f"Low scoring confidence ({overall_confidence:.0%}); manual review recommended"
            ],
            insufficient_data=True,
        )

    # Rung 7: all clear
    return FinalDecision(
        verdict=Decision.ALLOW,
        authority="score_pass",
        reasons=[f"All checks passed. Overall score: {overall_score}/100"],
    )
