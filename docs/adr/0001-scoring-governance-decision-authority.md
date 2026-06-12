# ADR 0001: Single Decision Authority, Confidence, and Protected-Service Governance

- **Status:** Accepted
- **Date:** 2026-06-12
- **Area:** Scoring engine (`scoring/`) and governance pipeline (`governance/`, `workflow/`)

## Context

A review of the scoring/governance stack found several correctness and
maintainability problems:

1. **Multiple competing verdict paths.** The V2 scoring engine, the legacy
   scorecards, and the DSL rules engine each produced a verdict, and the
   governance node surfaced more than one of them. There was no single,
   well-defined precedence for the final ALLOW / BLOCK / NEEDS_REVIEW.
2. **`overall_confidence` was effectively hardcoded to `1.0`.** The engine built
   `ScoringResult` directly and never populated confidence, so every scan
   reported 100% confidence regardless of how little data was available.
3. **Zero-data extensions looked safe.** With no SAST, VirusTotal, or network
   coverage an extension could surface as ~80/100 at 100% confidence.
4. **Two different threshold systems.** `engine.py` used `<30 / <75`; the gate
   helper used `<30 / <50`.
5. **Layer weights disagreed with their own docs** (`0.5/0.3/0.2` in docstrings
   vs `0.34/0.33/0.33` in code).
6. **The rules engine failed open.** A malformed condition or rulepack was
   silently dropped, which for a BLOCK rule means a silent ALLOW.
7. **Visa / travel-document detection was hardcoded** in `scoring/gates.py` and
   `scoring/engine.py` (domain lists, regexes), making it brittle and
   non-auditable.

## Decision

### 1. One final decision authority
`scoring/decision.py` defines a single `resolve()` function — the only place a
final verdict is computed — with one precedence chain:

```
org_block            (explicit org blocklist)            -> BLOCK
org_allow_exception  (explicit org allow exception)      -> ALLOW   (wins over automated rungs)
baseline_governance  (governance rulepack BLOCK)         -> BLOCK
hard_gate            (hard security/privacy gate BLOCK)  -> BLOCK
score_threshold      (DecisionPolicy thresholds, warns)  -> BLOCK / NEEDS_REVIEW
low_confidence       (insufficient data / low conf.)     -> NEEDS_REVIEW (downgrades ALLOW only)
score_pass                                               -> ALLOW
```

- `ScoringEngine` uses `resolve()` for its decision (scoring rungs only).
- `governance_node` calls the **same** `resolve()` with the full input set
  (rulepack baseline verdicts + optional `OrgPolicy`) and surfaces that as the
  single authoritative `governance_verdict`. The rules-engine report and the
  per-layer scores remain as detail/audit, not as competing verdicts.
- The old `ScoringEngine._determine_decision` was removed.

### 2. Confidence fix
`overall_confidence` is computed in the engine as the layer-weighted average of
the three layer confidences and passed into `ScoringResult`. It is never the
`1.0` default. Low coverage now visibly produces low confidence.

### 3. Insufficient-data behavior
When **none** of SAST, VirusTotal, or network analysis produced coverage, the
result is marked `insufficient_data`, the overall score is capped into the
review band (`INSUFFICIENT_DATA_SCORE_CAP = 65`), and the decision authority
forces `NEEDS_REVIEW`. This is intentionally distinct from the pre-existing
"SAST-only missing → cap at 80" behavior, which is preserved.

### 4. Single threshold policy
`DecisionPolicy` (`BLOCK_SCORE=30`, `REVIEW_SCORE=75`, `LOW_CONFIDENCE=0.5`) is
the only source of thresholds. `gates.get_final_decision` delegates to
`resolve()`; the divergent `<50` path is gone.

### 5. Layer weights
Standardized on the in-code behavior **`0.34 / 0.33 / 0.33`** (security /
privacy / governance) and corrected the docstrings and the dead-code
`assemble()` defaults that claimed `0.5/0.3/0.2`. No score behavior changed.
(Hard gates already enforce hard BLOCKs for severe findings independent of layer
weights, so equal-ish weighting of the smooth score is acceptable. Re-weighting
toward security can be revisited separately with a calibration set.)

### 6. Rules-engine fails closed
- A condition that cannot be parsed raises `RuleConditionError`; the rule
  becomes `NEEDS_REVIEW`, never a silent ALLOW.
- `validate_rulepack()` checks structure (ids, conditions, verdict enum,
  confidence range). `load_rulepacks_with_report()` returns
  `(valid_rulepacks, errors)`; parse/schema errors and missing requested
  rulepacks produce synthetic `NEEDS_REVIEW` results.

### 7. Protected-service automation rulepack (visa / travel-doc)
Detection was migrated out of hardcoded Python into declarative, versioned data
and rules:

- `config/protected_services.yaml` — single source of truth for protected-service
  domains, ecosystem domains, code patterns, identity keywords, and sabotage
  indicators.
- `governance/protected_services.py` — loads the YAML and centralizes detection.
- `governance/signal_extractor.py` — emits `PROTECTED_SERVICE_AUTOMATION`,
  `CREDENTIAL_CAPTURE`, `IDENTITY_DATA_EXFIL`, `SCREENSHOT_CAPTURE`,
  `XHR_INTERCEPTION`, etc.
- `governance/rulepacks/PROTECTED_SERVICE_AUTOMATION.yaml` — declarative,
  cited rules that turn those signals into BLOCK / NEEDS_REVIEW.
- `scoring/gates.py` now imports its domain lists from the single declarative
  source (re-exported under the legacy names).

## Why the hardcoded TOS gate remains (temporarily)

The hardcoded `TOS_VIOLATION` gate in `scoring/gates.py` is **deliberately kept
as a defensive backstop**, not removed, even though `PROTECTED_SERVICE_AUTOMATION`
now covers the same case. Rationale:

- **Do not weaken detection during a refactor.** The gate is a proven path that
  produces a hard BLOCK; the rulepack path is new and depends on signal
  extraction wiring.
- **Defense in depth.** Two independent paths (gate + rulepack) both BLOCK the
  CheckVisaSlots fixture, so a regression in one does not silently drop the BLOCK.
- **Retirement criterion.** Retire the gate's travel-docs branch only after the
  rulepack has proven itself across more fixtures (more real protected-service
  extensions, plus benign visa-adjacent extensions to bound false positives).
  Until then the gate stays. The branch carries a deprecation note pointing here.

## Consequences

- There is exactly one precedence chain; consumers must not re-derive verdicts.
- Confidence and insufficient-data are now meaningful and surfaced.
- Malformed governance policy fails closed (safe for a tool whose job is to BLOCK).
- Protected-service detection is auditable and versioned via YAML; tuning no
  longer requires a Python release.
- Two detection paths exist for protected-service automation until the gate is
  retired — intentional redundancy, tracked here.

## Verification

- New tests: `tests/scoring/test_decision_authority.py`,
  `tests/governance/test_rules_engine_failclosed.py`,
  `tests/scoring/test_checkvisaslots_block.py`,
  `tests/governance/test_protected_service_rulepack.py`.
- Targeted suite (`tests/scoring`, `tests/governance`, `tests/workflow`,
  `tests/test_scoring_gates.py`, `tests/test_golden_snapshots.py`): **235 passed**.
- The CheckVisaSlots fixture asserts BLOCK via both the gate and the rulepack;
  detection is not weakened.

## Note on unrelated failures

In a full-repo `pytest tests/` run, a small number of API / Supabase /
open-core tests (`tests/api/test_telemetry_atomic.py`,
`tests/api/test_supabase_auth.py`,
`tests/test_open_core_enforceability.py::...returns_sqlite...`) fail or error.
These are **pre-existing infrastructure / test-isolation issues**: they import
the DB/Supabase layer (not any module changed here) and pass in isolation. They
are out of scope for this audit and must not be folded into this commit.
