"""
CIS Benchmark Analyzer
Extracts CIS controls from PDF and matches them against firewall rules.
"""

import re
import logging
from typing import Dict, List, Any, Optional
import pathlib
import pandas as pd

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CISBenchmarkAnalyzer:
    """Analyzes CIS benchmark PDF and matches controls to firewall rules."""
    
    def __init__(self, pdf_path: pathlib.Path):
        self.pdf_path = pdf_path
        self.controls = []
        
    def extract_controls_from_pdf(self) -> List[Dict[str, Any]]:
        """
        Extract CIS controls from PDF using basic text extraction.
        For full implementation, install: pip install pdfplumber or pymupdf
        """
        controls = []
        
        try:
            # Try using pdfplumber first
            try:
                import pdfplumber
                with pdfplumber.open(self.pdf_path) as pdf:
                    full_text = ""
                    for page in pdf.pages:
                        page_text = page.extract_text()
                        if page_text:
                            full_text += page_text + "\n"
                logger.info(f"✅ Using pdfplumber to extract text from PDF")
            except ImportError:
                # Fallback to PyPDF2
                try:
                    import PyPDF2
                    with open(self.pdf_path, 'rb') as file:
                        pdf_reader = PyPDF2.PdfReader(file)
                        full_text = ""
                        for page in pdf_reader.pages:
                            full_text += page.extract_text() + "\n"
                    logger.info(f"✅ Using PyPDF2 to extract text from PDF")
                except ImportError:
                    # Fallback to pymupdf
                    try:
                        import fitz  # pymupdf
                        doc = fitz.open(self.pdf_path)
                        full_text = ""
                        for page in doc:
                            full_text += page.get_text() + "\n"
                        doc.close()
                        logger.info(f"✅ Using pymupdf to extract text from PDF")
                    except ImportError:
                        logger.warning("❌ No PDF library found. Install pdfplumber, PyPDF2, or pymupdf")
                        return []
            
            if not full_text or len(full_text.strip()) == 0:
                logger.warning("⚠️ No text extracted from PDF")
                return []
            
            logger.info(f"📄 Extracted {len(full_text)} characters from PDF")
            
            # Pattern to match CIS controls (e.g., "CIS 1.1", "CIS Control 1.1", "1.1", etc.)
            # More flexible pattern
            control_patterns = [
                r'(?:CIS\s*(?:Control\s*)?|Control\s+)(\d+\.\d+(?:\.\d+)?)\s*(.*?)(?=(?:CIS\s*(?:Control\s*)?|Control\s+)\d+\.\d+|$)',
                r'^(\d+\.\d+(?:\.\d+)?)\s+(.+?)(?=^\d+\.\d+|$)',
                r'Control\s+(\d+\.\d+(?:\.\d+)?)[:\s]+(.*?)(?=Control\s+\d+\.\d+|$)',
            ]
            
            for pattern in control_patterns:
                matches = re.finditer(pattern, full_text, re.IGNORECASE | re.DOTALL | re.MULTILINE)
                for match in matches:
                    control_id = f"CIS {match.group(1)}"
                    description = match.group(2).strip() if len(match.groups()) > 1 else ""
                    
                    # Clean up description
                    description = re.sub(r'\s+', ' ', description)
                    description = description[:500]  # Limit length
                    
                    # Avoid duplicates
                    if not any(c["id"] == control_id for c in controls) and description:
                        controls.append({
                            "id": control_id,
                            "description": description,
                            "full_text": match.group(0)[:1000]
                        })
            
            logger.info(f"✅ Extracted {len(controls)} CIS controls from PDF")
            return controls
            
        except Exception as e:
            logger.error(f"❌ Error extracting CIS controls: {e}")
            logger.exception("Full traceback:")
            return []
    
    def match_rules_to_controls(self, df: pd.DataFrame, controls: List[Dict[str, Any]], benchmark_type: str = "CIS") -> Dict[str, Any]:
        """
        Match firewall rules against CIS controls.
        Returns ONLY rules that fail specific controls (not all controls).
        """
        rule_control_matches = []
        failed_control_ids = set()  # Track which controls actually have failures
        
        if not controls:
            logger.warning("⚠️ No controls provided for matching")
            return {
                "total_rules_analyzed": len(df),
                "rules_with_failures": 0,
                "rule_control_matches": []
            }
        
        logger.info(f"🔍 Matching {len(df)} rules against {len(controls)} controls")
        
        # Analyze each rule against each control
        for idx, rule in df.iterrows():
            rule_name = str(rule.get('Name', 'Unknown'))
            rule_score = int(pd.to_numeric(rule.get('Score_Total', 0), errors='coerce') or 0)
            rule_failures = []
            
            # Get rule attributes
            source = str(rule.get('Source', '')).lower()
            destination = str(rule.get('Destination', '')).lower()
            service = str(rule.get('Service', '')).lower()
            action = str(rule.get('Action', '')).lower()
            source_zone = str(rule.get('Source_Zone', '')).lower()
            dest_zone = str(rule.get('Destination_Zone', '')).lower()
            
            # Check for risky patterns
            has_source_any = 'any' in source or source == '' or source == 'nan'
            has_dest_any = 'any' in destination or destination == '' or destination == 'nan'
            has_service_any = 'any' in service or service == '' or service == 'nan'
            is_allow = 'allow' in action or 'permit' in action
            
            for control in controls:
                control_id = control["id"]
                control_desc = control["description"].lower()
                
                # Determine if rule fails this control
                failure_reason = self._check_rule_fails_control(
                    rule, control, has_source_any, has_dest_any, has_service_any, is_allow,
                    source_zone, dest_zone, rule_score
                )
                
                if failure_reason:
                    failed_control_ids.add(control_id)
                    rule_failures.append({
                        "control_id": control_id,
                        "control_description": control["description"],
                        "benchmark_type": benchmark_type,
                        "reason": failure_reason
                    })
            
            if rule_failures:
                rule_control_matches.append({
                    "rule_name": rule_name,
                    "rule_score": rule_score,
                    "failed_controls": rule_failures
                })
        
        logger.info(f"✅ Found {len(rule_control_matches)} rules with control failures")
        logger.info(f"📊 Only {len(failed_control_ids)} controls out of {len(controls)} have failures")
        return {
            "total_rules_analyzed": len(df),
            "rules_with_failures": len(rule_control_matches),
            "rule_control_matches": rule_control_matches,
            "failed_control_count": len(failed_control_ids)  # Only controls that have failures
        }
    
    def _check_rule_fails_control(self, rule: pd.Series, control: Dict[str, Any], 
                                  has_source_any: bool, has_dest_any: bool, 
                                  has_service_any: bool, is_allow: bool,
                                  source_zone: str, dest_zone: str, rule_score: int) -> Optional[str]:
        """
        Determine if a rule fails a specific CIS control.
        Returns failure reason if it fails, None otherwise.
        Only matches controls that are clearly related to firewall/network security rules.
        """
        control_desc = control["description"].lower()
        control_id = control["id"].lower()
        
        # First, check if this control is even related to firewall/network security
        firewall_keywords = [
            'firewall', 'network security', 'security rule', 'access rule', 
            'traffic rule', 'packet filter', 'acl', 'access control list',
            'network policy', 'security policy', 'firewall rule', 'rule base',
            'source address', 'destination address', 'source ip', 'destination ip',
            'source port', 'destination port', 'service port', 'protocol',
            'network access', 'traffic control', 'network filter'
        ]
        
        # If control doesn't mention firewall/network security, skip it
        if not any(keyword in control_desc for keyword in firewall_keywords):
            return None
        
        reasons = []
        
        # Check for source any violations - must be specific to firewall rules
        if has_source_any:
            source_keywords = ['source address', 'source ip', 'source network', 'traffic source', 'source zone']
            restrict_keywords = ['restrict', 'limit', 'specific', 'deny any', 'block any', 'should not', 'must not', 'prohibit', 'must be specific']
            if any(sk in control_desc for sk in source_keywords):
                if any(rk in control_desc for rk in restrict_keywords):
                    reasons.append("Source is set to 'any'")
        
        # Check for destination any violations - must be specific to firewall rules
        if has_dest_any:
            dest_keywords = ['destination address', 'destination ip', 'destination network', 'destination zone', 'target address']
            restrict_keywords = ['restrict', 'limit', 'specific', 'deny any', 'block any', 'should not', 'must not', 'prohibit', 'must be specific']
            if any(dk in control_desc for dk in dest_keywords):
                if any(rk in control_desc for rk in restrict_keywords):
                    reasons.append("Destination is set to 'any'")
        
        # Check for service any violations - must be specific to firewall rules
        if has_service_any:
            service_keywords = ['service port', 'destination port', 'protocol', 'application port', 'service protocol']
            restrict_keywords = ['restrict', 'limit', 'specific', 'deny any', 'block any', 'should not', 'must not', 'prohibit', 'must be specific']
            if any(sk in control_desc for sk in service_keywords):
                if any(rk in control_desc for rk in restrict_keywords):
                    reasons.append("Service is set to 'any'")
        
        # Check for high risk score - only if control explicitly mentions risk/vulnerability
        if rule_score >= 100:  # High/Critical risk
            risk_keywords = ['high risk', 'critical risk', 'vulnerable rule', 'overpermissive rule', 'permissive rule', 'security risk']
            if any(rk in control_desc for rk in risk_keywords):
                reasons.append(f"High risk score ({rule_score})")
        
        # Check for internet exposure - must be specific to firewall/network
        if 'internet' in source_zone or 'internet' in dest_zone or 'untrust' in source_zone or 'untrust' in dest_zone:
            internet_keywords = ['internet traffic', 'external traffic', 'public network', 'untrust zone', 'dmz zone', 'external access']
            restrict_keywords = ['restrict', 'limit', 'block', 'deny', 'should not', 'must not', 'prohibit']
            if any(ik in control_desc for ik in internet_keywords):
                if any(rk in control_desc for rk in restrict_keywords):
                    reasons.append("Rule allows internet/untrust zone traffic")
        
        # Check for specific CIS control IDs that are known to be firewall-related
        # Only match if we have a clear violation AND the control is firewall-related
        firewall_control_patterns = {
            '1.1': ('source', has_source_any),
            '1.2': ('source', has_source_any),
            '1.3': ('destination', has_dest_any),
            '1.4': ('destination', has_dest_any),
            '1.5': ('service', has_service_any),
            '1.6': ('service', has_service_any),
            '4.1': ('source', has_source_any),
            '4.2': ('destination', has_dest_any),
            '4.3': ('service', has_service_any),
        }
        
        for pattern, (control_type, has_violation) in firewall_control_patterns.items():
            if pattern in control_id and has_violation:
                if control_type == 'source':
                    reasons.append(f"Source should be restricted per {control_id}")
                elif control_type == 'destination':
                    reasons.append(f"Destination should be restricted per {control_id}")
                elif control_type == 'service':
                    reasons.append(f"Service should be restricted per {control_id}")
                break  # Only match one pattern per control
        
        return "; ".join(reasons) if reasons else None

