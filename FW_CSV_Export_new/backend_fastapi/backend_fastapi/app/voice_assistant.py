"""
Voice Assistant Module for AI Analysis
Provides scope validation for voice queries to ensure they are related to firewall rules and security policies.
"""
import logging
import re
from typing import Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Keywords that indicate firewall/security-related queries
FIREWALL_KEYWORDS = [
    'firewall', 'rule', 'rules', 'security', 'policy', 'policies',
    'risk', 'risky', 'risks', 'shadow', 'redundant', 'redundancy',
    'generalization', 'correlation', 'consolidation', 'consolidate',
    'overpermissive', 'over-permissive', 'permissive', 'insecure',
    'port', 'ports', 'service', 'services', 'application', 'applications',
    'source', 'destination', 'src', 'dst', 'zone', 'zones',
    'threat', 'threats', 'vulnerability', 'vulnerabilities', 'attack',
    'traffic', 'network', 'protocol', 'protocols', 'ip', 'address',
    'cidr', 'subnet', 'subnets', 'access', 'control', 'acl',
    'palo', 'alto', 'pan-os', 'panos', 'paloalto', 'palo alto',
    'security profile', 'profile', 'log', 'logging', 'forwarding',
    'migrate', 'migration', 'app-id', 'appid', 'application-id',
    'user', 'users', 'group', 'groups', 'description', 'usage',
    'score', 'scoring', 'critical', 'high', 'medium', 'low',
    'inbound', 'outbound', 'internet', 'any', 'broad'
]

# Keywords that indicate out-of-scope queries (general knowledge, unrelated topics)
OUT_OF_SCOPE_KEYWORDS = [
    # Personal questions
    'my name', 'your name', 'who are you', 'what are you', 'who am i',
    'my age', 'how old', 'where am i', 'who is', 'tell me about yourself',
    # General knowledge
    'country', 'countries', 'capital', 'population', 'weather',
    'recipe', 'cooking', 'sports', 'movie', 'music', 'entertainment',
    'history', 'science', 'math', 'mathematics', 'physics', 'chemistry',
    'biology', 'geography', 'literature', 'art', 'philosophy',
    'religion', 'politics', 'economy', 'stock', 'market', 'trading',
    'news', 'current events', 'celebrity', 'famous', 'person',
    # Greetings and casual conversation
    'hello', 'hi', 'hey', 'good morning', 'good afternoon', 'good evening',
    'how are you', 'thank you', 'thanks', 'bye', 'goodbye'
]

# Keywords that indicate PDF/document-related queries (out of scope for NLM queries)
PDF_DOCUMENT_KEYWORDS = [
    'pdf', 'document', 'file', 'upload', 'uploaded', 'benchmark',
    'cis benchmark', 'nist', 'iso', 'pci', 'control document',
    'what is in the pdf', 'what does the pdf say', 'tell me about the pdf',
    'explain the pdf', 'summarize the pdf', 'read the pdf', 'pdf content',
    'benchmark document', 'security control document', 'what controls are in',
    'what is cis', 'what is nist', 'explain cis', 'explain nist',
    'cis controls', 'nist controls', 'iso controls', 'pci controls'
]


def validate_query_scope(query: str) -> Dict[str, Any]:
    """
    Validate if a query is within the scope of firewall rules and security policy analysis.
    
    Args:
        query: The user's query string
        
    Returns:
        Dictionary with:
        - in_scope: bool - Whether the query is in scope
        - reason: str - Explanation of the validation result
        - confidence: str - 'high', 'medium', or 'low' based on keyword matches
    """
    if not query or not query.strip():
        return {
            "in_scope": False,
            "reason": "Empty query",
            "confidence": "high"
        }
    
    query_lower = query.lower().strip()
    
    # Check for PDF/document-related queries first (highest priority - these are explicitly out of scope)
    pdf_matches = []
    for keyword in PDF_DOCUMENT_KEYWORDS:
        # Use word boundaries for better matching
        pattern = r'\b' + re.escape(keyword) + r'\b'
        if re.search(pattern, query_lower, re.IGNORECASE):
            pdf_matches.append(keyword)
    
    if pdf_matches:
        logger.info(f"❌ Query out of scope - PDF/document questions are not supported: {pdf_matches}")
        return {
            "in_scope": False,
            "reason": f"PDF/document-related questions are not supported. PDFs are only used for security controls analysis, not for answering questions about their content.",
            "confidence": "high"
        }
    
    # Check for out-of-scope keywords (general knowledge, unrelated topics)
    out_of_scope_matches = []
    for keyword in OUT_OF_SCOPE_KEYWORDS:
        if keyword in query_lower:
            out_of_scope_matches.append(keyword)
    
    if out_of_scope_matches:
        logger.info(f"❌ Query out of scope - found out-of-scope keywords: {out_of_scope_matches}")
        return {
            "in_scope": False,
            "reason": f"Query contains out-of-scope keywords: {', '.join(out_of_scope_matches)}",
            "confidence": "high"
        }
    
    # Check for firewall/security-related keywords
    firewall_matches = []
    for keyword in FIREWALL_KEYWORDS:
        # Use word boundaries to avoid partial matches
        pattern = r'\b' + re.escape(keyword) + r'\b'
        if re.search(pattern, query_lower, re.IGNORECASE):
            firewall_matches.append(keyword)
    
    if firewall_matches:
        logger.info(f"✅ Query in scope - found {len(firewall_matches)} firewall-related keywords")
        confidence = "high" if len(firewall_matches) >= 2 else "medium"
        return {
            "in_scope": True,
            "reason": f"Query contains firewall/security-related keywords: {', '.join(firewall_matches[:5])}",
            "confidence": confidence
        }
    
    # If no clear keywords found, check for question patterns that might be firewall-related
    question_patterns = [
        r'\b(how|what|which|where|when|why|who)\b.*\b(rule|rules|firewall|security|policy|risk)\b',
        r'\b(show|list|find|get|analyze|explain)\b.*\b(rule|rules|firewall|security|policy|risk)\b',
        r'\b(rule|rules|firewall|security|policy|risk)\b.*\b(how|what|which|where|when|why|who)\b'
    ]
    
    for pattern in question_patterns:
        if re.search(pattern, query_lower, re.IGNORECASE):
            logger.info(f"✅ Query in scope - matches firewall question pattern")
            return {
                "in_scope": True,
                "reason": "Query matches firewall-related question pattern",
                "confidence": "medium"
            }
    
    # If no clear indicators, default to OUT OF SCOPE (security-first approach)
    # Only firewall-related queries should be processed
    logger.info(f"🚫 Query rejected - no firewall-related keywords found")
    return {
        "in_scope": False,
        "reason": "Query does not contain firewall or security-related keywords",
        "confidence": "high"
    }


def get_out_of_scope_message() -> str:
    """
    Get the standard out-of-scope message.
    
    Returns:
        Standard message for out-of-scope queries
    """
    return "The Query you asked is Out of Scope. Please connect with PwC team or with your admin to know the query policy!!!"

