"""
LLM Handler for ExcelGrid Cell Explanations.
Provides specific explanations for why a cell is marked as True/Risky.
"""
import logging
import httpx
from fastapi import HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
try:
    from .llm_config import (
        LLM_MODEL_NAME, LLM_BASE_URL, LLM_API_KEY, 
        LLM_TEMPERATURE, LLM_MAX_TOKENS, LLM_TIMEOUT
    )
except ImportError:
    # Fallback for direct execution
    from llm_config import (
        LLM_MODEL_NAME, LLM_BASE_URL, LLM_API_KEY, 
        LLM_TEMPERATURE, LLM_MAX_TOKENS, LLM_TIMEOUT
    )

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ExplainCellRequest(BaseModel):
    rule_name: str
    column_key: str
    firewall_name: str
    row_data: Optional[Dict[str, Any]] = None

async def explain_cell_value(request: ExplainCellRequest):
    """
    Generates an LLM explanation for why a specific cell is marked as True.
    """
    rule_name = request.rule_name
    column_key = request.column_key
    firewall_name = request.firewall_name
    row_data = request.row_data or {}

    logging.info(f"🧠 Generating explanation for {rule_name} - {column_key} on {firewall_name}")

    # Define logic descriptions for each column
    # This helps the LLM understand WHY the flag is likely true based on the code logic
    column_logic_map = {
        "Overpermissive_Source": """
        This flag is TRUE because one of the following conditions is met:
        1. Source is 'Any' (Src_IsAny = True)
        2. Source CIDR is /16 or smaller (Src_CIDR_Le_16 = True) - e.g., /8, /16
        3. Source CIDR is between /17 and /22 (Src_CIDR_17_22 = True)
        
        This indicates the rule allows traffic from a very large number of source IP addresses, increasing the attack surface.
        """,
        
        "Overpermissive_Destination": """
        This flag is TRUE because one of the following conditions is met:
        1. Destination is 'Any' (Dst_IsAny = True)
        2. Destination CIDR is /16 or smaller (Dst_CIDR_Le_16 = True)
        3. Destination CIDR is between /17 and /22 (Dst_CIDR_17_22 = True)
        
        This indicates the rule allows traffic to a very large number of destination IP addresses.
        """,
        
        "Service_App": """
        This flag is TRUE because one of the following conditions is met:
        1. Service is 'Any' or contains a port range > 1000 ports (Service_Any_OR_RangeGt1000 = True)
        2. Application is 'Any' or broad (App_Any_OR_RangeGt1000 = True)
        
        This indicates the rule allows a wide range of services or applications, violating the principle of least privilege.
        """,
        
        "Insecure_Ports": """
        This flag is TRUE because the rule allows traffic on known insecure ports (Service_Insecure_Match = True).
        Examples of insecure ports include:
        - Telnet (23)
        - FTP (21)
        - HTTP (80)
        - SMTP (25)
        - POP3 (110)
        - IMAP (143)
        - SNMP (161/162)
        
        These protocols transmit data in cleartext or have known vulnerabilities.
        """,
        
        "Risky_Inbound": """
        This flag is TRUE because the rule allows unsolicited inbound traffic from the Internet (Any/0.0.0.0) to internal assets.
        (Risky_Inbound = True)
        
        This is a critical risk as it exposes internal resources directly to potential attackers on the internet.
        """,
        
        "Risky_Outbound": """
        This flag is TRUE because the rule allows outbound traffic from internal assets to the Internet (Any/0.0.0.0) on risky ports or services.
        (Risky_Outbound = True)
        
        This can be used for data exfiltration or C2 (Command & Control) communication.
        """,
        
        "Rule_Usage": """
        This flag is TRUE because the rule has NOT been hit/used recently (Rule_Usage_Scoring > 0).
        
        Unused rules clutter the policy, degrade performance, and may open unnecessary access paths if they were intended to be decommissioned.
        """,
        
        "Rule_Description": """
        This flag is TRUE because the rule is missing a description or has an inadequate description (Rule_Usage_Description_Scoring > 0).
        
        Good descriptions are essential for auditability and understanding the business purpose of a rule.
        """,
        
        "Source_User": """
        This flag is TRUE because the rule does not restrict traffic based on Source User (Source_User_Scoring > 0).
        
        Modern firewalls should use User-ID to enforce policy based on user identity rather than just IP addresses.
        """,
        
        "Security_Profile": """
        This flag is TRUE because the rule is missing Security Profiles (Profile_Scoring > 0).
        
        Security Profiles (Antivirus, Anti-Spyware, Vulnerability Protection, URL Filtering, File Blocking) are critical for threat prevention.
        """,
        
        "Shadow_Rule": """
        This flag is TRUE because the rule is 'Shadowed' or 'Partially Shadowed' by an earlier rule.
        (Shadow_Rule = True OR Partial_Shadow_Rule = True)
        
        A shadowed rule is never evaluated because a preceding rule matches the same traffic. It is dead code.
        """,
        
        "Redundant_Rule": """
        This flag is TRUE because the rule is 'Redundant'.
        (Redundant_Rule = True)
        
        A redundant rule performs the same action as another rule and can be consolidated or removed.
        """,
        
        "Consolidation": """
        This flag is TRUE because the rule is a candidate for consolidation.
        (Consolidation_Candidate = True)
        
        This means it is similar enough to other rules that they could be merged to simplify the policy.
        """
    }

    logic_description = column_logic_map.get(column_key, "This flag is marked as True based on the firewall analysis logic.")

    # Construct the prompt
    prompt = f"""
You are an expert firewall security analyst.
Your task is to explain WHY a specific cell in a firewall analysis report is marked as "True" (Risky/Flagged).

CONTEXT:
- Rule Name: "{rule_name}"
- Firewall: "{firewall_name}"
- Column Flagged: "{column_key}"

LOGIC BEHIND THIS FLAG:
{logic_description}

SPECIFIC ROW DATA (Attributes of this rule):
{_format_row_data(row_data)}

INSTRUCTIONS:
1. Explain specifically why this rule "{rule_name}" triggered the "{column_key}" flag.
2. Use the "SPECIFIC ROW DATA" to pinpoint the exact values causing this (e.g., "Source is set to 'Any'", "Service includes 'tcp-23'", "Score is 0 indicating no usage").
3. Explain the security risk associated with this specific finding.
4. Keep the explanation concise (2-3 paragraphs max).
5. Do NOT provide generic advice; focus on this specific rule and value.
6. If the row data shows specific values (like Source IPs, Ports, etc.), cite them in your explanation.

ANSWER:
"""

    # Call LLM
    try:
        timeout_config = httpx.Timeout(connect=5.0, read=LLM_TIMEOUT, write=5.0, pool=5.0)
        async with httpx.AsyncClient(timeout=timeout_config) as client:
            
            # Prepare payload based on API type (similar to main.py logic)
            # Assuming OpenAI compatible for now as per recent changes
            
            headers = {"Content-Type": "application/json"}
            if LLM_API_KEY and LLM_API_KEY != "not-needed":
                headers["Authorization"] = f"Bearer {LLM_API_KEY}"

            # Try OpenAI format first (most common for local servers like LM Studio)
            payload = {
                "model": LLM_MODEL_NAME,
                "messages": [
                    {"role": "system", "content": "You are a helpful firewall security expert."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": LLM_TEMPERATURE,
                "max_tokens": LLM_MAX_TOKENS
            }
            
            url = f"{LLM_BASE_URL}/chat/completions"
            
            logging.info(f"🤖 Sending request to {url}")
            response = await client.post(url, json=payload, headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                content = ""
                # Extract content from OpenAI format
                if "choices" in result and len(result["choices"]) > 0:
                    content = result["choices"][0].get("message", {}).get("content", "")
                
                if not content:
                    # Fallback for other formats
                    content = result.get("response", "") or result.get("text", "") or str(result)
                
                return {"success": True, "response": content}
            else:
                logging.error(f"❌ LLM Error: {response.status_code} - {response.text}")
                return {"success": False, "response": f"Error calling LLM: {response.status_code}"}

    except Exception as e:
        logging.error(f"❌ Exception calling LLM: {e}")
        return {"success": False, "response": f"Error generating explanation: {str(e)}"}

def _format_row_data(row_data: Dict[str, Any]) -> str:
    """Helper to format row data for the prompt."""
    if not row_data:
        return "No specific row data provided."
    
    formatted = []
    # Prioritize important fields
    priority_fields = [
        'Source', 'Destination', 'Service', 'Application', 'Action', 
        'Src_IsAny', 'Dst_IsAny', 'Service_Any_OR_RangeGt1000', 
        'Service_Insecure_Match', 'Score_Total'
    ]
    
    for field in priority_fields:
        if field in row_data:
            formatted.append(f"- {field}: {row_data[field]}")
            
    # Add other fields if relevant (but skip internal scoring fields to reduce noise if needed)
    for k, v in row_data.items():
        if k not in priority_fields and not k.endswith('_Scoring') and len(formatted) < 20:
            formatted.append(f"- {k}: {v}")
            
    return "\n".join(formatted)
