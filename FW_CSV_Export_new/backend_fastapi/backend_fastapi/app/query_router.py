"""
Query Router Module for NLM Queries
Intelligently classifies queries and determines which data to load, reducing prompt size and improving performance.
"""
import logging
import re
from enum import Enum
from typing import Dict, Any, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class QueryIntent(str, Enum):
    """Query intent categories"""
    COUNT = "count"              # "how many rules", "total rules"
    SPECIFIC_RULES = "specific"  # "show risky inbound", "list shadow rules"
    POLICY_ANALYSIS = "policy"   # "redundant rules", "consolidation"
    SECURITY_CONTROLS = "security" # "which controls failing"
    OVERVIEW = "overview"        # "summarize", "overview"
    COMPARISON = "comparison"    # "compare firewalls"


@dataclass
class DataRequirements:
    """Specifies which data needs to be loaded for a query"""
    needs_analysis_data: bool = False
    needs_dashboard_data: bool = False
    needs_policy_data: bool = False
    needs_rule_examples: bool = False
    needs_reordering: bool = False
    needs_firewall_distribution: bool = False
    needs_security_controls: bool = False
    specific_categories: List[str] = None  # e.g., ["riskyInbound", "shadowRules"]
    
    def __post_init__(self):
        if self.specific_categories is None:
            self.specific_categories = []


# Keyword patterns for each intent
INTENT_PATTERNS = {
    QueryIntent.COUNT: [
        r'\bhow many\b', r'\btotal\b', r'\bcount\b', r'\bnumber of\b',
        r'\bhow much\b', r'\bquantity\b'
    ],
    QueryIntent.SPECIFIC_RULES: [
        r'\brisky inbound\b', r'\brisky outbound\b', r'\bshadow\b',
        r'\bshow\b.*\brules?\b', r'\blist\b.*\brules?\b', r'\bdisplay\b.*\brules?\b',
        r'\bget\b.*\brules?\b', r'\bfind\b.*\brules?\b',
        r'\binsecure port\b', r'\boverpermissive\b', r'\bsource any\b',
        r'\bdestination any\b', r'\bservice broad\b'
    ],
    QueryIntent.POLICY_ANALYSIS: [
        r'\bredundant\b', r'\bconsolidation\b', r'\bgeneralization\b',
        r'\bcorrelation\b', r'\breorder\b', r'\bpartial shadow\b',
        r'\bposition\b.*\bchange\b', r'\bmove\b.*\brule\b', r'\brule order\b'
    ],
    QueryIntent.SECURITY_CONTROLS: [
        r'\bcontrol\b', r'\bCIS\b', r'\bNIST\b', r'\bPCI\b',
        r'\bcompliance\b', r'\bfailing\b.*\bcontrol\b', r'\bviolat\b',
        r'\bbenchmark\b', r'\bstandard\b'
    ],
    QueryIntent.COMPARISON: [
        r'\bcompare\b', r'\bfirewall\b.*\bfirewall\b', r'\bper firewall\b',
        r'\bby firewall\b', r'\beach firewall\b', r'\bdistribution\b',
        r'\bwhich firewall\b', r'\bamong firewalls\b', r'\bbetween firewalls\b',
        r'\bmore risky\b.*\bfirewall\b', r'\bmost risky\b.*\bfirewall\b',
        r'\bfirewall\b.*\brisky\b', r'\bfirewall\b.*\bworst\b'
    ],
    QueryIntent.OVERVIEW: [
        r'\bsummarize\b', r'\bsummary\b', r'\boverview\b', r'\bstatus\b',
        r'\bdashboard\b', r'\boverall\b', r'\bgeneral\b'
    ]
}

# Category-specific keywords for rule examples
CATEGORY_KEYWORDS = {
    'riskyInbound': [r'\brisky inbound\b', r'\binbound.*internet\b', r'\binternet.*inbound\b'],
    'riskyOutbound': [r'\brisky outbound\b', r'\boutbound.*internet\b', r'\binternet.*outbound\b'],
    'sourceAny': [r'\bsource any\b', r'\bsrc any\b', r'\bsource.*any\b'],
    'destinationAny': [r'\bdestination any\b', r'\bdst any\b', r'\bdestination.*any\b'],
    'insecurePorts': [r'\binsecure port\b', r'\binsecure service\b', r'\bunencrypted\b'],
    'shadowRules': [r'\bshadow\b', r'\bshadowed\b'],
    'partialShadowRules': [r'\bpartial shadow\b', r'\bpartially shadow\b'],
    'redundantRules': [r'\bredundant\b', r'\bredundancy\b'],
    'generalizationRisks': [r'\bgeneralization\b', r'\bgeneralize\b'],
    'correlationRisks': [r'\bcorrelation\b', r'\boverlap\b'],
    'consolidationCandidates': [r'\bconsolidation\b', r'\bconsolidate\b', r'\bmerge\b'],
    'serviceBroad': [r'\bservice broad\b', r'\bservice.*broad\b', r'\bbroad service\b'],
    'missingProfile': [r'\bmissing.*profile\b', r'\bno.*profile\b', r'\bsecurity profile\b'],
    'missingLogForwarding': [r'\bmissing.*log\b', r'\bno.*log\b', r'\blog forwarding\b']
}


def classify_query(query: str) -> QueryIntent:
    """
    Classify a query into an intent category.
    
    Args:
        query: The user's query string
        
    Returns:
        QueryIntent enum value
    """
    if not query or not query.strip():
        return QueryIntent.OVERVIEW
    
    query_lower = query.lower().strip()
    
    # Check each intent pattern
    intent_scores = {intent: 0 for intent in QueryIntent}
    
    for intent, patterns in INTENT_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, query_lower, re.IGNORECASE):
                intent_scores[intent] += 1
    
    # Get intent with highest score
    max_score = max(intent_scores.values())
    
    if max_score == 0:
        # No clear pattern, default to overview
        logger.info(f"📊 Query classification: OVERVIEW (no clear pattern)")
        return QueryIntent.OVERVIEW
    
    # Get all intents with max score (in case of tie)
    top_intents = [intent for intent, score in intent_scores.items() if score == max_score]
    
    # Priority order for tie-breaking: COUNT > SPECIFIC_RULES > POLICY_ANALYSIS > SECURITY_CONTROLS > COMPARISON > OVERVIEW
    priority_order = [
        QueryIntent.COUNT,
        QueryIntent.SPECIFIC_RULES,
        QueryIntent.POLICY_ANALYSIS,
        QueryIntent.SECURITY_CONTROLS,
        QueryIntent.COMPARISON,
        QueryIntent.OVERVIEW
    ]
    
    for intent in priority_order:
        if intent in top_intents:
            logger.info(f"📊 Query classification: {intent.value.upper()} (score: {max_score})")
            return intent
    
    return QueryIntent.OVERVIEW


def get_specific_categories(query: str) -> List[str]:
    """
    Determine which specific rule categories are mentioned in the query.
    
    Args:
        query: The user's query string
        
    Returns:
        List of category names (e.g., ["riskyInbound", "shadowRules"])
    """
    query_lower = query.lower().strip()
    categories = []
    
    for category, patterns in CATEGORY_KEYWORDS.items():
        for pattern in patterns:
            if re.search(pattern, query_lower, re.IGNORECASE):
                categories.append(category)
                break  # Only add category once
    
    return categories


def get_data_requirements(intent: QueryIntent, query: str) -> DataRequirements:
    """
    Determine which data needs to be loaded based on query intent.
    
    Args:
        intent: The classified query intent
        query: The original query string
        
    Returns:
        DataRequirements object specifying what data to load
    """
    specific_categories = get_specific_categories(query)
    
    # Define data requirements for each intent
    if intent == QueryIntent.COUNT:
        # Count queries only need basic analysis data
        return DataRequirements(
            needs_analysis_data=True,
            needs_dashboard_data=True,  # For specific counts
            needs_policy_data=False,
            needs_rule_examples=False,
            needs_reordering=False,
            needs_firewall_distribution=False,
            needs_security_controls=False,
            specific_categories=[]
        )
    
    elif intent == QueryIntent.SPECIFIC_RULES:
        # Specific rule queries need dashboard data and examples for those categories
        return DataRequirements(
            needs_analysis_data=True,
            needs_dashboard_data=True,
            needs_policy_data=False,
            needs_rule_examples=True,
            needs_reordering=False,
            needs_firewall_distribution=False,
            needs_security_controls=False,
            specific_categories=specific_categories
        )
    
    elif intent == QueryIntent.POLICY_ANALYSIS:
        # Policy analysis queries need policy data and examples
        return DataRequirements(
            needs_analysis_data=True,
            needs_dashboard_data=False,
            needs_policy_data=True,
            needs_rule_examples=True,
            needs_reordering=True,
            needs_firewall_distribution=False,
            needs_security_controls=False,
            specific_categories=specific_categories
        )
    
    elif intent == QueryIntent.SECURITY_CONTROLS:
        # Security control queries only need control failure data
        return DataRequirements(
            needs_analysis_data=True,
            needs_dashboard_data=False,
            needs_policy_data=False,
            needs_rule_examples=False,
            needs_reordering=False,
            needs_firewall_distribution=False,
            needs_security_controls=True,
            specific_categories=[]
        )
    
    elif intent == QueryIntent.COMPARISON:
        # Comparison queries need firewall distribution and analysis data
        return DataRequirements(
            needs_analysis_data=True,
            needs_dashboard_data=True,
            needs_policy_data=True,
            needs_rule_examples=False,
            needs_reordering=False,
            needs_firewall_distribution=True,
            needs_security_controls=False,
            specific_categories=[]
        )
    
    else:  # QueryIntent.OVERVIEW
        # Overview queries need analysis and dashboard data, but minimal examples
        return DataRequirements(
            needs_analysis_data=True,
            needs_dashboard_data=True,
            needs_policy_data=True,
            needs_rule_examples=False,
            needs_reordering=False,
            needs_firewall_distribution=False,
            needs_security_controls=False,
            specific_categories=[]
        )


def log_data_requirements(requirements: DataRequirements, query: str):
    """
    Log which data will be loaded for debugging.
    
    Args:
        requirements: The data requirements
        query: The original query
    """
    data_to_load = []
    if requirements.needs_analysis_data:
        data_to_load.append("analysis")
    if requirements.needs_dashboard_data:
        data_to_load.append("dashboard")
    if requirements.needs_policy_data:
        data_to_load.append("policy")
    if requirements.needs_rule_examples:
        data_to_load.append(f"examples({','.join(requirements.specific_categories) if requirements.specific_categories else 'all'})")
    if requirements.needs_reordering:
        data_to_load.append("reordering")
    if requirements.needs_firewall_distribution:
        data_to_load.append("firewall_dist")
    if requirements.needs_security_controls:
        data_to_load.append("security_controls")
    
    logger.info(f"📦 Data to load: {', '.join(data_to_load)}")
