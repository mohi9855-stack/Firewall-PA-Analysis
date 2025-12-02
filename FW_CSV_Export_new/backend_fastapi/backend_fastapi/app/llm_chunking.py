"""
Helper functions for chunking large prompts and merging LLM responses.
"""

import logging
from typing import List, Dict, Any
import re

logger = logging.getLogger(__name__)


def chunk_rules_data(rules_data: List[Dict[str, Any]], chunk_size: int) -> List[List[Dict[str, Any]]]:
    """
    Split a list of rules into chunks of specified size.
    
    Args:
        rules_data: List of rule dictionaries
        chunk_size: Number of rules per chunk
        
    Returns:
        List of chunks, where each chunk is a list of rules
    """
    chunks = []
    for i in range(0, len(rules_data), chunk_size):
        chunk = rules_data[i:i + chunk_size]
        chunks.append(chunk)
    
    logger.info(f"📦 Split {len(rules_data)} rules into {len(chunks)} chunks of ~{chunk_size} rules each")
    return chunks


def merge_llm_responses(responses: List[str], query: str) -> str:
    """
    Intelligently merge multiple LLM responses from chunked prompts.
    
    Args:
        responses: List of LLM response strings
        query: The original user query
        
    Returns:
        Merged response string
    """
    if len(responses) == 1:
        return responses[0]
    
    logger.info(f"🔗 Merging {len(responses)} LLM responses...")
    
    # Extract sections from each response
    merged_sections = {
        "summary": [],
        "root_cause": [],
        "immediate_actions": [],
        "remediation": [],
        "recommendations": [],
        "security_controls": [],
        "suggestions": []
    }
    
    for idx, response in enumerate(responses):
        logger.info(f"📄 Processing response {idx + 1}/{len(responses)}")
        
        # Extract Summary section
        summary_match = re.search(r'\*\*1\.\s*Summary\*\*\s*(.*?)(?=\*\*2\.|$)', response, re.DOTALL | re.IGNORECASE)
        if summary_match:
            merged_sections["summary"].append(summary_match.group(1).strip())
        
        # Extract Root Cause section
        root_cause_match = re.search(r'\*\*2\.\s*Root Cause Analysis.*?\*\*\s*(.*?)(?=\*\*3\.|$)', response, re.DOTALL | re.IGNORECASE)
        if root_cause_match:
            merged_sections["root_cause"].append(root_cause_match.group(1).strip())
        
        # Extract Immediate Actions section
        actions_match = re.search(r'\*\*3\.\s*Immediate Actions.*?\*\*\s*(.*?)(?=\*\*4\.|$)', response, re.DOTALL | re.IGNORECASE)
        if actions_match:
            merged_sections["immediate_actions"].append(actions_match.group(1).strip())
        
        # Extract Remediation Plan section
        remediation_match = re.search(r'\*\*4\.\s*Remediation Plan.*?\*\*\s*(.*?)(?=\*\*5\.|$)', response, re.DOTALL | re.IGNORECASE)
        if remediation_match:
            merged_sections["remediation"].append(remediation_match.group(1).strip())
        
        # Extract Recommendations section
        recommendations_match = re.search(r'\*\*5\.\s*Recommendations.*?\*\*\s*(.*?)(?=\*\*6\.|$)', response, re.DOTALL | re.IGNORECASE)
        if recommendations_match:
            merged_sections["recommendations"].append(recommendations_match.group(1).strip())
        
        # Extract Security Controls section
        security_match = re.search(r'\*\*6\.\s*Security Controls.*?\*\*\s*(.*?)(?=\*\*7\.|$)', response, re.DOTALL | re.IGNORECASE)
        if security_match:
            merged_sections["security_controls"].append(security_match.group(1).strip())
        
        # Extract Suggestions section (the detailed rule list)
        suggestions_match = re.search(r'\*\*7\.\s*Suggestions.*?\*\*\s*(.*?)$', response, re.DOTALL | re.IGNORECASE)
        if suggestions_match:
            merged_sections["suggestions"].append(suggestions_match.group(1).strip())
    
    # Build merged response
    merged_response = f"**[MERGED RESPONSE FROM {len(responses)} CHUNKS]**\n\n"
    
    # 1. Summary - combine all summaries
    merged_response += "**1. Summary**\n"
    if merged_sections["summary"]:
        # Combine unique points from all summaries
        all_summary_text = "\n".join(merged_sections["summary"])
        merged_response += all_summary_text + "\n\n"
    else:
        merged_response += "Analysis completed across multiple data chunks.\n\n"
    
    # 2. Root Cause - combine all root causes
    merged_response += "**2. Root Cause Analysis - \"Why do these rules have these values?\"**\n"
    if merged_sections["root_cause"]:
        merged_response += "\n".join(merged_sections["root_cause"]) + "\n\n"
    else:
        merged_response += "See individual chunk analyses for root cause details.\n\n"
    
    # 3. Immediate Actions - combine and deduplicate
    merged_response += "**3. Immediate Actions Required - \"What action must the user take?\"**\n"
    if merged_sections["immediate_actions"]:
        merged_response += "\n".join(merged_sections["immediate_actions"]) + "\n\n"
    else:
        merged_response += "Review all flagged rules and prioritize remediation.\n\n"
    
    # 4. Remediation Plan - combine
    merged_response += "**4. Remediation Plan - \"What is the remediation plan?\"**\n"
    if merged_sections["remediation"]:
        merged_response += "\n".join(merged_sections["remediation"]) + "\n\n"
    else:
        merged_response += "Follow standard remediation procedures for each rule category.\n\n"
    
    # 5. Recommendations - combine
    merged_response += "**5. Recommendations - \"What are the recommendations?\"**\n"
    if merged_sections["recommendations"]:
        merged_response += "\n".join(merged_sections["recommendations"]) + "\n\n"
    else:
        merged_response += "Implement security best practices across all firewall rules.\n\n"
    
    # 6. Security Controls - merge and deduplicate control IDs
    merged_response += "**6. Security Controls - \"Which security controls are the rules failing?\"**\n"
    if merged_sections["security_controls"]:
        # Combine all security control sections
        all_controls_text = "\n".join(merged_sections["security_controls"])
        merged_response += all_controls_text + "\n\n"
    else:
        merged_response += "Security control failure analysis not available.\n\n"
    
    # 7. Suggestions - combine ALL rule suggestions from all chunks
    merged_response += "**7. Suggestions - \"List ALL specific rules with their names and reasons\"**\n"
    if merged_sections["suggestions"]:
        merged_response += f"\n**[Combined from {len(responses)} chunks - showing all rules]**\n\n"
        for idx, suggestions in enumerate(merged_sections["suggestions"]):
            merged_response += f"**Chunk {idx + 1}:**\n{suggestions}\n\n"
    else:
        merged_response += "No specific rule suggestions available.\n\n"
    
    logger.info(f"✅ Merged response created ({len(merged_response)} chars)")
    return merged_response
