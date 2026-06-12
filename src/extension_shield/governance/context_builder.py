"""
Context Builder - Stage 6 of Governance Pipeline

Builds the governance context that determines which rulepacks to apply,
regional scope, domain categories, and cross-border risk assessment.

The context is tenant/config-driven and can be customized based on:
- Organization policies
- Extension characteristics (host patterns, detected domains)
- Regional compliance requirements

Output: context.json
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

from .schemas import GovernanceContext, Context, Facts


logger = logging.getLogger(__name__)


# =============================================================================
# DEFAULT CONFIGURATION
# =============================================================================

# Default rulepacks to apply
DEFAULT_RULEPACKS = [
    "ENTERPRISE_GOV_BASELINE",
    "CWS_LIMITED_USE",
    "PROTECTED_SERVICE_AUTOMATION",
]

# Supported regions
SUPPORTED_REGIONS = {
    "GLOBAL": "Global (all regions)",
    "US": "United States",
    "EU": "European Union (GDPR)",
    "UK": "United Kingdom",
    "IN": "India",
    "AU": "Australia",
    "CA": "Canada",
    "BR": "Brazil (LGPD)",
    "JP": "Japan",
    "SG": "Singapore",
}

# Domain category mappings (domain suffix -> category)
DOMAIN_CATEGORIES = {
    # Banking & Financial
    "banking_financial": [
        "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
        "paypal.com", "venmo.com", "stripe.com", "coinbase.com", "binance.com",
        "robinhood.com", "fidelity.com", "schwab.com", "vanguard.com",
    ],
    # Government
    "government": [
        ".gov", "irs.gov", "usa.gov", "healthcare.gov", "ssa.gov",
    ],
    # Healthcare
    "healthcare": [
        "anthem.com", "uhc.com", "cigna.com", "aetna.com", "humana.com",
        "kaiser.com", "teladoc.com", "zocdoc.com", "mychart.org",
    ],
    # Enterprise
    "enterprise": [
        "salesforce.com", "workday.com", "okta.com", "atlassian.com",
        "slack.com", "zoom.us", "microsoft.com", "office.com",
    ],
}

# Regional TLD mappings for cross-border detection
REGIONAL_TLDS = {
    "EU": [".eu", ".de", ".fr", ".it", ".es", ".nl", ".be", ".at", ".pl", ".ie"],
    "UK": [".uk", ".co.uk"],
    "IN": [".in", ".co.in"],
    "AU": [".au", ".com.au"],
    "CA": [".ca"],
    "BR": [".br", ".com.br"],
    "JP": [".jp", ".co.jp"],
    "SG": [".sg"],
    "US": [".us", ".gov"],
}


class ContextBuilder:
    """
    Builds governance context for rule evaluation.
    
    Stage 6 of the Governance Decisioning Pipeline.
    
    Usage:
        builder = ContextBuilder()
        context = builder.build(facts)
        
        # Or with custom configuration
        context = builder.build(
            facts,
            rulepacks=["ENTERPRISE_GOV_BASELINE"],
            regions=["US", "EU"],
        )
    """
    
    def __init__(
        self,
        config_path: Optional[str] = None,
        sensitive_domains_path: Optional[str] = None,
    ):
        """
        Initialize the Context Builder.
        
        Args:
            config_path: Optional path to governance configuration file
            sensitive_domains_path: Optional path to sensitive domains JSON
        """
        self.config = self._load_config(config_path)
        self.sensitive_domains = self._load_sensitive_domains(sensitive_domains_path)
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load governance configuration from file."""
        if config_path:
            try:
                with open(config_path, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning("Failed to load config from %s: %s", config_path, e)
        return {}
    
    def _load_sensitive_domains(self, path: Optional[str]) -> Dict[str, Any]:
        """Load sensitive domains configuration."""
        if path:
            try:
                with open(path, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning("Failed to load sensitive domains from %s: %s", path, e)
        
        # Try default location
        default_path = Path(__file__).parent.parent / "config" / "sensitive_domains.json"
        if default_path.exists():
            try:
                with open(default_path, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.debug("Failed to load default sensitive domains: %s", e)
        
        return {}
    
    def build(
        self,
        facts: Optional[Facts] = None,
        rulepacks: Optional[List[str]] = None,
        regions: Optional[List[str]] = None,
        domain_categories: Optional[List[str]] = None,
    ) -> Context:
        """
        Build governance context.
        
        Args:
            facts: Optional Facts object for context inference
            rulepacks: Override rulepacks to apply (default: all)
            regions: Override regions in scope (default: GLOBAL)
            domain_categories: Override domain categories
            
        Returns:
            Context object ready for rules evaluation
        """
        logger.info("Building governance context")
        
        # Determine rulepacks
        active_rulepacks = rulepacks or self._get_default_rulepacks()
        
        # Determine regions
        active_regions = regions or self._infer_regions(facts)
        
        # Determine domain categories
        detected_categories = domain_categories or self._detect_domain_categories(facts)
        
        # Assess cross-border risk
        cross_border = self._assess_cross_border_risk(facts, active_regions)
        
        governance_context = GovernanceContext(
            regions_in_scope=active_regions,
            rulepacks=active_rulepacks,
            domain_categories=detected_categories,
            cross_border_risk=cross_border,
        )
        
        logger.info(
            "Context built: regions=%s, rulepacks=%s, categories=%s, cross_border=%s",
            active_regions, active_rulepacks, detected_categories, cross_border
        )
        
        return Context(context=governance_context)
    
    def build_from_dict(
        self,
        facts_dict: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Context:
        """
        Build context from a facts dictionary.
        
        Args:
            facts_dict: Facts as a dictionary
            **kwargs: Additional arguments passed to build()
            
        Returns:
            Context object
        """
        facts = None
        if facts_dict:
            facts = Facts(**facts_dict)
        return self.build(facts, **kwargs)
    
    def _get_default_rulepacks(self) -> List[str]:
        """Get default rulepacks from config or hardcoded defaults."""
        return self.config.get("default_rulepacks", DEFAULT_RULEPACKS)
    
    def _infer_regions(self, facts: Optional[Facts]) -> List[str]:
        """
        Infer applicable regions from extension characteristics.
        
        Args:
            facts: Facts object
            
        Returns:
            List of region codes
        """
        if not facts:
            return ["GLOBAL"]
        
        regions: Set[str] = set()
        
        # Check host access patterns for regional TLDs
        for pattern in facts.host_access_patterns:
            pattern_lower = pattern.lower()
            
            for region, tlds in REGIONAL_TLDS.items():
                for tld in tlds:
                    if tld in pattern_lower:
                        regions.add(region)
        
        # If extension has broad access, consider GLOBAL
        broad_patterns = ["<all_urls>", "*://*/*", "http://*/*", "https://*/*"]
        if any(p in facts.host_access_patterns for p in broad_patterns):
            regions.add("GLOBAL")
        
        # Default to GLOBAL if no specific regions detected
        if not regions:
            regions.add("GLOBAL")
        
        return sorted(regions)
    
    def _detect_domain_categories(self, facts: Optional[Facts]) -> List[str]:
        """
        Detect domain categories from extension's host patterns.
        
        Args:
            facts: Facts object
            
        Returns:
            List of detected domain category names
        """
        if not facts:
            return ["general"]
        
        categories: Set[str] = set()
        
        # Check against built-in categories
        for pattern in facts.host_access_patterns:
            pattern_lower = pattern.lower()
            
            for category, domains in DOMAIN_CATEGORIES.items():
                for domain in domains:
                    if domain in pattern_lower:
                        categories.add(category)
        
        # Check against sensitive domains config
        if self.sensitive_domains:
            config_categories = self.sensitive_domains.get("categories", {})
            for category_id, category_data in config_categories.items():
                if not category_data.get("enabled", True):
                    continue
                
                domains = category_data.get("domains", [])
                for domain in domains:
                    for pattern in facts.host_access_patterns:
                        if domain.lower() in pattern.lower():
                            categories.add(category_id)
        
        # Default to general if no specific categories detected
        if not categories:
            categories.add("general")
        
        return sorted(categories)
    
    def _assess_cross_border_risk(
        self,
        facts: Optional[Facts],
        regions: List[str],
    ) -> bool:
        """
        Assess if extension poses cross-border data transfer risks.
        
        Cross-border risk is flagged when:
        - Extension accesses domains in multiple regions
        - Extension has broad host access AND is not local-only
        - Extension accesses EU domains (GDPR implications)
        
        Args:
            facts: Facts object
            regions: List of detected regions
            
        Returns:
            True if cross-border risk detected
        """
        if not facts:
            return False
        
        # Multiple regions = potential cross-border
        if len(regions) > 1:
            return True
        
        # EU access always flags cross-border for non-EU orgs
        if "EU" in regions and len(regions) == 1:
            # Could be cross-border depending on org location
            # For now, flag it for review
            return True
        
        # Broad access with external endpoints
        broad_patterns = ["<all_urls>", "*://*/*"]
        has_broad_access = any(p in facts.host_access_patterns for p in broad_patterns)
        
        # Check for external endpoints in SAST findings
        has_external = any(
            "external" in f.description.lower() or "endpoint" in f.finding_type.lower()
            for f in facts.security_findings.sast_findings
        )
        
        if has_broad_access and has_external:
            return True
        
        return False
    
    def get_available_rulepacks(self) -> List[str]:
        """Get list of available rulepack IDs."""
        rulepacks_dir = Path(__file__).parent / "rulepacks"
        rulepacks = []
        
        if rulepacks_dir.exists():
            for yaml_file in rulepacks_dir.glob("*.yaml"):
                # Extract rulepack ID from filename
                rulepack_id = yaml_file.stem.upper()
                rulepacks.append(rulepack_id)
        
        return sorted(rulepacks)
    
    def save(self, context: Context, output_path: str) -> None:
        """
        Save context to a JSON file.
        
        Args:
            context: The Context object to save
            output_path: Path to save the context.json file
        """
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output, "w", encoding="utf-8") as f:
            json.dump(context.model_dump(mode="json"), f, indent=2, default=str)
        
        logger.info("Context saved to %s", output_path)


def build_governance_context(
    facts: Optional[Facts] = None,
    facts_dict: Optional[Dict[str, Any]] = None,
    rulepacks: Optional[List[str]] = None,
    regions: Optional[List[str]] = None,
) -> Context:
    """
    Convenience function to build governance context.
    
    Args:
        facts: Facts object
        facts_dict: Facts as dictionary (alternative to facts)
        rulepacks: Override rulepacks to apply
        regions: Override regions in scope
        
    Returns:
        Context object
    """
    builder = ContextBuilder()
    
    if facts_dict and not facts:
        return builder.build_from_dict(facts_dict, rulepacks=rulepacks, regions=regions)
    
    return builder.build(facts, rulepacks=rulepacks, regions=regions)


def get_context_for_rules_engine(context: Context) -> Dict[str, Any]:
    """
    Convert Context object to dict format expected by RulesEngine.
    
    Args:
        context: Context object
        
    Returns:
        Dict with rulepacks list at top level
    """
    return context.context.model_dump()

