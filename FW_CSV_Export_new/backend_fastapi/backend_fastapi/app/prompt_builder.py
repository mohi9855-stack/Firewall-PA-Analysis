"""
Prompt Builder Module for NLM Queries
Builds minimal, intent-specific prompts to fit within token limits.
"""
import logging
from typing import Dict, Any
from app.query_router import QueryIntent

logger = logging.getLogger(__name__)


def build_minimal_prompt_for_count(query: str, analysis_data: Dict, dashboard_data: Dict) -> str:
    """
    Build a minimal prompt for COUNT queries.
    Only includes basic statistics, no examples or detailed data.
    """
    prompt = f"""You are a firewall rule analyst. Answer the user's COUNT question concisely.

STATISTICS:
- Total Rules: {analysis_data.get('totalRules', 0):,}
- Average Score: {analysis_data.get('averageScore', 0):.2f}
- High Risk (≥76): {analysis_data.get('highRisk', 0):,}
- Medium Risk (26-75): {analysis_data.get('mediumRisk', 0):,}
- Low Risk (<26): {analysis_data.get('lowRisk', 0):,}
"""
    
    if dashboard_data and dashboard_data.get('riskDashboard', {}).get('found'):
        risk = dashboard_data['riskDashboard']
        prompt += f"""
RISK LEVELS:
- Critical (175-200): {risk.get('critical', 0):,}
- High (100-174): {risk.get('high', 0):,}
- Medium (50-99): {risk.get('medium', 0):,}
- Low (1-49): {risk.get('low', 0):,}
- No Risk (0): {risk.get('none', 0):,}
"""
    
    if dashboard_data and dashboard_data.get('overpermissive'):
        op = dashboard_data['overpermissive']
        prompt += f"""
OVERPERMISSIVE COUNTS:
- Source Any: {op.get('sourceAny', {}).get('count', 0):,}
- Destination Any: {op.get('destinationAny', {}).get('count', 0):,}
- Service Broad: {op.get('serviceBroad', {}).get('count', 0):,}
- Insecure Ports: {op.get('insecurePorts', {}).get('count', 0):,}
- Risky Inbound: {op.get('riskyInbound', {}).get('count', 0):,}
- Risky Outbound: {op.get('riskyOutbound', {}).get('count', 0):,}
"""
    
    prompt += f"""
USER QUERY: {query}

INSTRUCTIONS:
1. Answer the specific count question with EXACT numbers
2. Provide context in this structure:

**Answer:** [Direct answer with number]

**Context:**
- What this number represents
- Severity assessment (if applicable)

**Immediate Actions:**
- If count is concerning, list 1-2 urgent actions

**Recommendation:**
- Brief suggestion for improvement (if needed)

Keep response concise (3-4 sentences total).

ANSWER:"""
    
    return prompt


def build_minimal_prompt_for_specific_rules(query: str, analysis_data: Dict, rule_examples: Dict, specific_categories: list) -> str:
    """
    Build a minimal prompt for SPECIFIC_RULES queries.
    Includes only relevant rule examples and minimal stats.
    """
    prompt = f"""You are a firewall rule analyst. Answer the user's question about specific rules.

STATISTICS:
- Total Rules: {analysis_data.get('totalRules', 0):,}
- High Risk Rules: {analysis_data.get('highRisk', 0):,}
"""

    # Add only relevant examples
    if rule_examples.get('found'):
        prompt += "\nRELEVANT RULE EXAMPLES:\n"
        examples_found = False
        
        # If specific categories are identified, prioritize them
        if specific_categories:
            for category in specific_categories:
                if category in rule_examples.get('examples', {}):
                    prompt += f"\n--- {category} Rules ---\n"
                    for i, example in enumerate(rule_examples['examples'][category], 1):
                        prompt += f"{i}. {example}\n"
                    examples_found = True
        
        # If no specific categories or none found, show a few high risk examples
        if not examples_found and 'highRisk' in rule_examples.get('examples', {}):
            prompt += "\n--- High Risk Rules ---\n"
            for i, example in enumerate(rule_examples['examples']['highRisk'][:3], 1):
                prompt += f"{i}. {example}\n"
    
    prompt += f"""
USER QUERY: {query}

INSTRUCTIONS:
Provide a structured response:

**Specific Rules:**
- List the requested rules with exact names and details

**Risk Analysis:**
- Why these rules are flagged
- Common patterns identified

**Immediate Actions:**
- 2-3 critical fixes needed NOW

**Recommendations:**
- How to remediate these specific rules
- Best practices to prevent similar issues

Keep each section concise but actionable.

ANSWER:"""
    
    return prompt


def build_minimal_prompt_for_overview(query: str, analysis_data: Dict, dashboard_data: Dict, rule_examples: Dict) -> str:
    """
    Build a minimal prompt for OVERVIEW queries.
    Includes high-level stats and limited examples (top 3 high risk).
    """
    prompt = f"""You are a firewall rule analyst. Provide a high-level executive summary.

STATISTICS:
- Total Rules: {analysis_data.get('totalRules', 0):,}
- Average Score: {analysis_data.get('averageScore', 0):.2f}
- High Risk Rules: {analysis_data.get('highRisk', 0):,}
- Medium Risk Rules: {analysis_data.get('mediumRisk', 0):,}
- Low Risk Rules: {analysis_data.get('lowRisk', 0):,}
"""

    if dashboard_data and dashboard_data.get('riskDashboard', {}).get('found'):
        risk = dashboard_data['riskDashboard']
        prompt += f"""
RISK DISTRIBUTION:
- Critical: {risk.get('critical', 0):,}
- High: {risk.get('high', 0):,}
- Medium: {risk.get('medium', 0):,}
- Low: {risk.get('low', 0):,}
"""

    # Add only top 3 high risk examples for context
    if rule_examples.get('found') and 'highRisk' in rule_examples.get('examples', {}):
        prompt += "\nTOP HIGH RISK EXAMPLES:\n"
        for i, example in enumerate(rule_examples['examples']['highRisk'][:3], 1):
            prompt += f"{i}. {example}\n"
    
    prompt += f"""
USER QUERY: {query}

INSTRUCTIONS:
Provide an executive summary with these sections:

**Executive Summary:**
- Overall security posture (2-3 sentences)
- Key risk metrics

**Top Risks Identified:**
- List top 3 risk categories with counts
- Severity assessment

**Root Cause Analysis:**
- Why these risks exist
- Common patterns across rules

**Immediate Actions Required:**
- 3 critical actions to take NOW
- Prioritized by severity

**Remediation Plan:**
- Short-term (1-2 weeks): Quick wins
- Medium-term (1-3 months): Structural improvements
- Long-term (3-6 months): Strategic changes

**Recommendations:**
- Best practices to implement
- Ongoing monitoring suggestions

Keep each section concise (2-3 sentences) but comprehensive.

ANSWER:"""
    
    return prompt

def build_minimal_prompt_for_comparison(query: str, analysis_data: Dict, firewall_analysis_distribution: Any) -> str:
    """
    Build a minimal prompt for COMPARISON queries.
    Includes firewall distribution data to compare risks across firewalls.
    """
    prompt = f"""You are a firewall rule analyst. Compare the risk levels between different firewalls.

STATISTICS:
- Total Rules: {analysis_data.get('totalRules', 0):,}
- High Risk Rules: {analysis_data.get('highRisk', 0):,}
"""

    if firewall_analysis_distribution:
        prompt += "\nFIREWALL RISK DISTRIBUTION:\n"
        
        # Data is already sorted by high risk count in analysis.py
        for stats in firewall_analysis_distribution:
            fw_name = stats.get('firewall', 'Unknown')
            prompt += f"""
Firewall: {fw_name}
RISK STATS:
- Critical Risk: {stats.get('critical', 0)}
- High Risk: {stats.get('high', 0)}
- Medium Risk: {stats.get('medium', 0)}
- Low Risk: {stats.get('low', 0)}
- Avg Score: {stats.get('average_score', 'N/A')}

POLICY ISSUES:
- Shadow Rules: {stats.get('shadow', 0)}
- Redundant Rules: {stats.get('redundant', 0)}
- Consolidation Candidates: {stats.get('consolidation', 0)}
- Total Rules: {stats.get('total_rules', stats.get('total', 0))}
"""
    else:
        prompt += "\nNo firewall distribution data available. Unable to compare firewalls.\n"
    
    prompt += f"""
USER QUERY: {query}

INSTRUCTIONS:
1. **ALWAYS mention the specific firewall names** (from the "Firewall:" field above) in your answer
2. Provide a COMPREHENSIVE analysis with the following sections:

**Most Risky Firewall:**
- Identify the firewall with highest Critical + High risk count
- State exact numbers and percentages

**Comparison Table:**
Create a markdown table with all firewalls sorted by risk:

| Firewall | Critical | High | Medium | Low | Shadow | Redundant | Total Rules |
|----------|----------|------|--------|-----|--------|-----------|-------------|
| [Name]   | X        | Y    | Z      | A   | B      | C         | D           |

**Root Cause Analysis (RCA):**
- Analyze WHY this firewall is most risky
- Identify common patterns (e.g., overpermissive rules, outdated policies)
- Highlight specific risk factors

**Immediate Actions Required:**
- List 2-3 critical actions to take NOW
- Prioritize by risk severity
- Be specific and actionable

**Remediation Plan:**
- Short-term fixes (1-2 weeks)
- Medium-term improvements (1-3 months)
- Long-term strategy (3-6 months)

**Recommendations:**
- Best practices to implement
- Policy improvements needed
- Monitoring and review suggestions

Keep each section concise (2-3 sentences max) but actionable. Use bullet points for clarity.

ANSWER:"""
    
    return prompt


def build_prompt_for_intent(
    query_intent: QueryIntent,
    query: str,
    analysis_data: Dict,
    dashboard_data: Dict,
    policy_analyzer_data: Dict,
    rule_examples: Dict,
    reordering_suggestions: Dict,
    firewall_analysis_distribution: Any,
    rule_control_failures: Dict,
    specific_categories: list = None
) -> str:
    """
    Build an intent-specific prompt that includes only necessary data.
    """
    # For COUNT queries, use minimal prompt
    if query_intent == QueryIntent.COUNT:
        return build_minimal_prompt_for_count(query, analysis_data, dashboard_data)
    
    # For SPECIFIC_RULES queries, use minimal specific prompt
    if query_intent == QueryIntent.SPECIFIC_RULES:
        return build_minimal_prompt_for_specific_rules(query, analysis_data, rule_examples, specific_categories)
    
    # For OVERVIEW queries, use minimal overview prompt
    if query_intent == QueryIntent.OVERVIEW:
        return build_minimal_prompt_for_overview(query, analysis_data, dashboard_data, rule_examples)
    
    # For COMPARISON queries, use minimal comparison prompt
    if query_intent == QueryIntent.COMPARISON:
        return build_minimal_prompt_for_comparison(query, analysis_data, firewall_analysis_distribution)
    
    # Default: build a standard prompt (existing logic)
    return build_standard_prompt(
        query, analysis_data, dashboard_data, policy_analyzer_data,
        rule_examples, reordering_suggestions, firewall_analysis_distribution,
        rule_control_failures
    )


def build_standard_prompt(
    query: str,
    analysis_data: Dict,
    dashboard_data: Dict,
    policy_analyzer_data: Dict,
    rule_examples: Dict,
    reordering_suggestions: Dict,
    firewall_analysis_distribution: Any,
    rule_control_failures: Dict
) -> str:
    """
    Build a standard comprehensive prompt (existing logic).
    This is used for OVERVIEW and other complex queries.
    """
    # This will contain the existing comprehensive prompt building logic
    # For now, return a placeholder - we'll integrate the existing logic
    return f"""You are a firewall rule analyst.

USER QUERY: {query}

[Standard comprehensive prompt - to be integrated with existing logic]

ANSWER:"""
