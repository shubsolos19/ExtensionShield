"""
Tests for rules-engine fail-closed behavior and rulepack validation (P1.6).

A malformed rule or rulepack must NEVER silently ALLOW; it must surface as
NEEDS_REVIEW.
"""

import textwrap

import pytest

from extension_shield.governance.rules_engine import (
    ConditionEvaluator,
    RuleConditionError,
    RulesEngine,
    validate_rulepack,
)


# =============================================================================
# Rulepack schema validation
# =============================================================================

class TestValidateRulepack:
    def _valid_rule(self, **over):
        rule = {
            "rule_id": "RP::R1",
            "condition": "manifest.permissions contains \"tabs\"",
            "verdict": "BLOCK",
            "confidence": 0.9,
        }
        rule.update(over)
        return rule

    def test_valid_rulepack_has_no_errors(self):
        rp = {"rulepack_id": "RP", "rules": [self._valid_rule()]}
        assert validate_rulepack(rp) == []

    def test_missing_rulepack_id(self):
        rp = {"rules": [self._valid_rule()]}
        assert any("rulepack_id" in e for e in validate_rulepack(rp))

    def test_no_rules(self):
        rp = {"rulepack_id": "RP", "rules": []}
        assert any("rules" in e for e in validate_rulepack(rp))

    def test_invalid_verdict(self):
        rp = {"rulepack_id": "RP", "rules": [self._valid_rule(verdict="NUKE")]}
        assert any("invalid verdict" in e for e in validate_rulepack(rp))

    def test_empty_condition(self):
        rp = {"rulepack_id": "RP", "rules": [self._valid_rule(condition="   ")]}
        assert any("condition" in e for e in validate_rulepack(rp))

    def test_duplicate_rule_id(self):
        rp = {"rulepack_id": "RP", "rules": [self._valid_rule(), self._valid_rule()]}
        assert any("duplicate" in e for e in validate_rulepack(rp))

    def test_confidence_out_of_range(self):
        rp = {"rulepack_id": "RP", "rules": [self._valid_rule(confidence=5)]}
        assert any("confidence" in e for e in validate_rulepack(rp))


# =============================================================================
# Condition evaluation fails closed
# =============================================================================

class TestConditionFailsClosed:
    def test_unknown_operator_raises(self):
        ev = ConditionEvaluator()
        with pytest.raises(RuleConditionError):
            ev.evaluate("facts.foo WAT 'bar'", {"facts": {"foo": "bar"}})

    def test_valid_false_condition_returns_false_not_error(self):
        ev = ConditionEvaluator()
        # Legitimately false (missing key) must NOT raise.
        assert ev.evaluate('manifest.permissions contains "tabs"', {"manifest": {}}) is False

    def test_malformed_block_rule_becomes_needs_review(self):
        """A BLOCK rule whose condition cannot be parsed must NOT ALLOW."""
        rulepack = {
            "rulepack_id": "RP",
            "rules": [
                {
                    "rule_id": "RP::BROKEN",
                    "condition": "facts.x TOTALLY INVALID syntax here",
                    "verdict": "BLOCK",
                    "confidence": 0.9,
                }
            ],
        }
        engine = RulesEngine([rulepack])
        results = engine.evaluate(
            scan_id="s1",
            facts={},
            signals=[],
            store_listing={},
            context={"rulepacks": ["RP"]},
        )
        verdicts = {r.verdict for r in results.rule_results}
        assert "ALLOW" not in verdicts
        assert "NEEDS_REVIEW" in verdicts


# =============================================================================
# Loader + engine fail closed
# =============================================================================

class TestLoaderFailsClosed:
    def test_malformed_yaml_reported_as_error(self, tmp_path):
        (tmp_path / "broken.yaml").write_text("rulepack_id: RP\nrules: [unclosed")
        rulepacks, errors = RulesEngine.load_rulepacks_with_report(str(tmp_path))
        assert rulepacks == []
        assert errors and any("broken.yaml" in e for e in errors)

    def test_schema_invalid_rulepack_reported(self, tmp_path):
        (tmp_path / "bad.yaml").write_text(
            textwrap.dedent(
                """
                rulepack_id: BAD
                rules:
                  - rule_id: BAD::R1
                    condition: ""
                    verdict: NOPE
                """
            )
        )
        rulepacks, errors = RulesEngine.load_rulepacks_with_report(str(tmp_path))
        assert rulepacks == []
        assert errors

    def test_load_errors_force_needs_review(self):
        engine = RulesEngine([], load_errors=["could not parse pack X"])
        results = engine.evaluate(
            scan_id="s1", facts={}, signals=[], store_listing={}, context={"rulepacks": []}
        )
        assert any(r.verdict == "NEEDS_REVIEW" for r in results.rule_results)

    def test_missing_requested_rulepack_fails_closed(self):
        engine = RulesEngine([])  # no rulepacks loaded
        results = engine.evaluate(
            scan_id="s1",
            facts={},
            signals=[],
            store_listing={},
            context={"rulepacks": ["ENTERPRISE_GOV_BASELINE"]},
        )
        assert any(r.verdict == "NEEDS_REVIEW" for r in results.rule_results)

    def test_valid_block_rule_still_blocks(self):
        """Hardening must not weaken a legitimately-matching BLOCK rule."""
        rulepack = {
            "rulepack_id": "RP",
            "rules": [
                {
                    "rule_id": "RP::MAL",
                    "condition": "facts.security_findings.virustotal_malicious_count > 2",
                    "verdict": "BLOCK",
                    "confidence": 0.95,
                }
            ],
        }
        engine = RulesEngine([rulepack])
        results = engine.evaluate(
            scan_id="s1",
            facts={"security_findings": {"virustotal_malicious_count": 9}},
            signals=[],
            store_listing={},
            context={"rulepacks": ["RP"]},
        )
        assert any(r.verdict == "BLOCK" for r in results.rule_results)
