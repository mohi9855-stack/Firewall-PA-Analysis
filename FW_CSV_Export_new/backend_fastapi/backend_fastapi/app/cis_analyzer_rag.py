"""
CIS Benchmark Analyzer using RAG (Retrieval Augmented Generation)
Uses LLM to semantically extract controls from PDF and match them against firewall rules.
"""

import re
import logging
from typing import Dict, List, Any, Optional
import pathlib
import pandas as pd
import httpx
import json
import asyncio

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CISBenchmarkAnalyzerRAG:
    """Analyzes CIS benchmark PDF using RAG/LLM for semantic understanding."""
    
    def __init__(self, pdf_path: pathlib.Path, llm_config: Dict[str, Any]):
        self.pdf_path = pdf_path
        self.llm_config = llm_config
        self.pdf_text = ""
        self.controls = []
        
    def extract_text_from_pdf(self) -> str:
        """Extract text from PDF using pdfplumber (text extraction only)."""
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
                        return ""
            
            if not full_text or len(full_text.strip()) == 0:
                logger.warning("⚠️ No text extracted from PDF")
                return ""
            
            logger.info(f"📄 Extracted {len(full_text)} characters from PDF")
            self.pdf_text = full_text
            return full_text
            
        except Exception as e:
            logger.error(f"❌ Error extracting text from PDF: {e}")
            logger.exception("Full traceback:")
            return ""
    
    async def extract_controls_using_llm(self) -> List[Dict[str, Any]]:
        """
        Use LLM to semantically extract security controls from PDF text.
        This provides better understanding than regex patterns.
        """
        if not self.pdf_text:
            logger.info("📄 Extracting text from PDF first...")
            self.extract_text_from_pdf()
        
        if not self.pdf_text:
            logger.error("❌ No PDF text available for LLM extraction")
            return []
        
        logger.info(f"📄 PDF text length: {len(self.pdf_text)} characters")
        logger.info(f"📄 First 500 chars of PDF: {self.pdf_text[:500]}")
        
        # Chunk the PDF text if it's too long (LLM context limits)
        max_chunk_size = 50000  # Leave room for prompt
        chunks = []
        if len(self.pdf_text) > max_chunk_size:
            # Split by paragraphs or sections
            paragraphs = self.pdf_text.split('\n\n')
            current_chunk = ""
            for para in paragraphs:
                if len(current_chunk) + len(para) > max_chunk_size:
                    if current_chunk:
                        chunks.append(current_chunk)
                    current_chunk = para
                else:
                    current_chunk += "\n\n" + para if current_chunk else para
            if current_chunk:
                chunks.append(current_chunk)
        else:
            chunks = [self.pdf_text]
        
        logger.info(f"📚 Split PDF into {len(chunks)} chunks for LLM processing")
        
        all_controls = []
        
        for chunk_idx, chunk in enumerate(chunks):
            prompt = f"""You are a security compliance expert. Extract ALL security controls from the following PDF text.

The text contains Palo Alto Firewall CIS Controls or similar security benchmark controls.

For EACH control you find, extract:
1. Control ID (e.g., "CIS 1.1", "CIS 1.2", "CIS Control 2.1", etc. - extract the EXACT ID format used in the document)
2. Control Description (the COMPLETE, FULL description of what the control requires - do not truncate)
3. Control Type (CIS, NIST, ISO, PCI, or OTHER - based on the document)

CRITICAL REQUIREMENTS:
- Extract EVERY SINGLE control mentioned in the text - do not skip any
- Include the FULL description for each control - do not summarize or truncate
- If a control has multiple parts or sub-requirements, include ALL of them in the description
- Preserve the exact control ID format as it appears in the document
- If controls are numbered (1.1, 1.2, 2.1, etc.), extract ALL of them

Return the results as a JSON array with this exact format:
[
  {{
    "control_id": "CIS 1.1",
    "description": "Complete full description of the control requirement including all details and sub-requirements...",
    "type": "CIS"
  }},
  {{
    "control_id": "CIS 1.2",
    "description": "Another complete control description with all details...",
    "type": "CIS"
  }}
]

IMPORTANT:
- Extract ALL controls you find, not just a few
- Include the COMPLETE description for each control (do not truncate)
- Return ONLY valid JSON, no additional text
- If you find no controls, return an empty array: []

PDF Text:
{chunk[:max_chunk_size]}

Extract ALL controls and return as JSON array:"""

            try:
                logger.info(f"🤖 Calling LLM for chunk {chunk_idx + 1}/{len(chunks)} (chunk size: {len(chunk)} chars)...")
                controls = await self._call_llm_for_extraction(prompt)
                if controls:
                    all_controls.extend(controls)
                    logger.info(f"✅ Extracted {len(controls)} controls from chunk {chunk_idx + 1}/{len(chunks)}")
                else:
                    logger.warning(f"⚠️ No controls extracted from chunk {chunk_idx + 1}/{len(chunks)}")
            except Exception as e:
                logger.error(f"❌ Error extracting controls from chunk {chunk_idx + 1}: {e}")
                logger.exception("Full traceback:")
                continue
        
        # Remove duplicates based on control_id
        unique_controls = {}
        for control in all_controls:
            control_id = control.get('control_id', '')
            if control_id and control_id not in unique_controls:
                unique_controls[control_id] = control
        
        self.controls = list(unique_controls.values())
        logger.info(f"✅ Extracted {len(self.controls)} unique controls using LLM")
        return self.controls
    
    async def _call_llm_for_extraction(self, prompt: str) -> List[Dict[str, Any]]:
        """Call LLM to extract controls from text."""
        try:
            timeout_config = httpx.Timeout(connect=10.0, read=90.0, write=10.0, pool=5.0)
            
            async with httpx.AsyncClient(timeout=timeout_config) as client:
                # Use Gemini API
                if "generativelanguage.googleapis.com" in self.llm_config['base_url']:
                    model_name = self.llm_config['model']
                    gemini_url = f"{self.llm_config['base_url']}/models/{model_name}:generateContent?key={self.llm_config['api_key']}"
                    
                    payload = {
                        "contents": [{
                            "parts": [{"text": prompt}]
                        }],
                        "generationConfig": {
                            "temperature": 0.3,  # Lower temperature for more consistent extraction
                            "maxOutputTokens": 8000  # Increased for larger PDFs
                        }
                    }
                    
                    logger.info(f"📤 Sending request to Gemini API (model: {model_name})...")
                    response = await client.post(gemini_url, json=payload)
                    
                    if response.status_code != 200:
                        logger.error(f"❌ Gemini API returned status {response.status_code}: {response.text[:500]}")
                        return []
                    
                    result = response.json()
                    logger.info(f"📥 Received response from Gemini API")
                    
                    # Check for errors in response
                    if 'error' in result:
                        logger.error(f"❌ Gemini API error: {result['error']}")
                        return []
                    
                    if 'candidates' in result and len(result['candidates']) > 0:
                        candidate = result['candidates'][0]
                        finish_reason = candidate.get('finishReason', '')
                        
                        if finish_reason == 'SAFETY':
                            logger.warning("⚠️ Gemini blocked response due to safety filters")
                            return []
                        elif finish_reason == 'MAX_TOKENS':
                            logger.warning("⚠️ Gemini response truncated due to token limit")
                        
                        content = candidate.get('content', {})
                        parts = content.get('parts', [])
                        if parts:
                            text_response = parts[0].get('text', '')
                            logger.info(f"📝 LLM response length: {len(text_response)} characters")
                            logger.info(f"📝 LLM response preview: {text_response[:300]}...")
                            
                            # Try to extract JSON from response
                            # Look for JSON array pattern
                            json_match = re.search(r'\[[\s\S]*\]', text_response, re.DOTALL)
                            if json_match:
                                json_str = json_match.group(0)
                                try:
                                    controls = json.loads(json_str)
                                    if isinstance(controls, list):
                                        logger.info(f"✅ Successfully parsed {len(controls)} controls from JSON")
                                        return controls
                                    else:
                                        logger.warning(f"⚠️ Parsed JSON is not a list: {type(controls)}")
                                except json.JSONDecodeError as je:
                                    logger.error(f"❌ JSON decode error: {je}")
                                    logger.error(f"❌ Problematic JSON string: {json_str[:500]}")
                            else:
                                logger.warning(f"⚠️ LLM response doesn't contain JSON array")
                                logger.warning(f"⚠️ Full response: {text_response[:1000]}")
                        else:
                            logger.warning(f"⚠️ No parts in Gemini response content")
                    else:
                        logger.warning(f"⚠️ No candidates in Gemini response")
                        logger.warning(f"⚠️ Response structure: {list(result.keys())}")
                
                # Fallback to OpenAI format
                else:
                    openai_url = f"{self.llm_config['base_url']}/v1/chat/completions"
                    headers = {"Content-Type": "application/json"}
                    if self.llm_config.get('api_key'):
                        headers["Authorization"] = f"Bearer {self.llm_config['api_key']}"
                    
                    payload = {
                        "model": self.llm_config['model'],
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.3,
                        "max_tokens": 8000
                    }
                    
                    logger.info(f"📤 Sending request to OpenAI-compatible API...")
                    response = await client.post(openai_url, json=payload, headers=headers)
                    response.raise_for_status()
                    result = response.json()
                    
                    if 'choices' in result and len(result['choices']) > 0:
                        text_response = result['choices'][0]['message']['content']
                        json_match = re.search(r'\[[\s\S]*\]', text_response, re.DOTALL)
                        if json_match:
                            json_str = json_match.group(0)
                            controls = json.loads(json_str)
                            return controls
            
            return []
            
        except httpx.TimeoutException:
            logger.error("❌ LLM request timed out")
            return []
        except httpx.HTTPStatusError as e:
            logger.error(f"❌ HTTP error calling LLM: {e.response.status_code} - {e.response.text[:500]}")
            return []
        except Exception as e:
            logger.error(f"❌ Error calling LLM for control extraction: {e}")
            logger.exception("Full traceback:")
            return []
    
    async def match_rules_to_controls_using_llm(self, df: pd.DataFrame, controls: List[Dict[str, Any]], benchmark_type: str = "CIS") -> Dict[str, Any]:
        """
        Use LLM to semantically match firewall rules against controls.
        This provides better understanding than keyword matching.
        """
        if not controls:
            logger.warning("⚠️ No controls provided for matching")
            return {
                "total_rules_analyzed": len(df),
                "rules_with_failures": 0,
                "rule_control_matches": []
            }
        
        logger.info(f"🔍 Using LLM to match {len(df)} rules against {len(controls)} controls")
        
        rule_control_matches = []
        failed_control_ids = set()
        
        # Process rules in batches to avoid overwhelming the LLM
        batch_size = 50
        total_batches = (len(df) + batch_size - 1) // batch_size
        
        for batch_idx in range(total_batches):
            start_idx = batch_idx * batch_size
            end_idx = min(start_idx + batch_size, len(df))
            batch_df = df.iloc[start_idx:end_idx]
            
            logger.info(f"📦 Processing batch {batch_idx + 1}/{total_batches} ({len(batch_df)} rules)")
            
            # Prepare rule data for LLM
            rules_data = []
            for _, rule in batch_df.iterrows():
                rule_name = str(rule.get('Name', 'Unknown'))
                rule_score = int(pd.to_numeric(rule.get('Score_Total', 0), errors='coerce') or 0)
                source = str(rule.get('Source', ''))
                destination = str(rule.get('Destination', ''))
                service = str(rule.get('Service', ''))
                action = str(rule.get('Action', ''))
                source_zone = str(rule.get('Source_Zone', ''))
                dest_zone = str(rule.get('Destination_Zone', ''))
                
                rules_data.append({
                    "rule_name": rule_name,
                    "rule_score": rule_score,
                    "source": source,
                    "destination": destination,
                    "service": service,
                    "action": action,
                    "source_zone": source_zone,
                    "destination_zone": dest_zone
                })
            
            # Prepare controls summary for LLM
            controls_summary = "\n".join([
                f"- {c.get('control_id', 'Unknown')}: {c.get('description', '')[:200]}"
                for c in controls[:20]  # Limit to first 20 controls per batch to avoid token limits
            ])
            
            prompt = f"""You are a firewall security compliance expert. Analyze the following firewall rules against the security controls.

For each firewall rule, determine if it FAILS any of the security controls. A rule fails a control if it violates the control's requirements.

Security Controls:
{controls_summary}

Firewall Rules:
{json.dumps(rules_data, indent=2)}

For each rule that fails a control, return:
- rule_name: The exact rule name
- failed_controls: Array of controls it fails, each with:
  - control_id: The control ID (e.g., "CIS 1.1")
  - reason: Why the rule fails this control (be specific)

Return ONLY rules that have failures. If a rule doesn't fail any control, don't include it.

Return as JSON array:
[
  {{
    "rule_name": "Rule_Name_123",
    "rule_score": 150,
    "failed_controls": [
      {{
        "control_id": "CIS 1.1",
        "reason": "Source is set to 'any' which violates the control requirement to restrict source addresses"
      }}
    ]
  }}
]

Return ONLY valid JSON array, no additional text:"""

            try:
                matches = await self._call_llm_for_matching(prompt)
                if matches:
                    for match in matches:
                        rule_name = match.get('rule_name', 'Unknown')
                        rule_score = match.get('rule_score', 0)
                        failed_controls = match.get('failed_controls', [])
                        
                        # Get full control descriptions
                        enhanced_failed_controls = []
                        for fc in failed_controls:
                            control_id = fc.get('control_id', '')
                            # Find the full control description
                            full_control = next((c for c in controls if c.get('control_id') == control_id), None)
                            
                            enhanced_failed_controls.append({
                                "control_id": control_id,
                                "control_description": full_control.get('description', '') if full_control else '',
                                "benchmark_type": benchmark_type,
                                "reason": fc.get('reason', 'No reason provided')
                            })
                            failed_control_ids.add(control_id)
                        
                        rule_control_matches.append({
                            "rule_name": rule_name,
                            "rule_score": rule_score,
                            "failed_controls": enhanced_failed_controls
                        })
                    
                    logger.info(f"✅ Batch {batch_idx + 1}: Found {len(matches)} rules with failures")
                
            except Exception as e:
                logger.error(f"❌ Error processing batch {batch_idx + 1}: {e}")
                continue
        
        logger.info(f"✅ Found {len(rule_control_matches)} total rules with control failures")
        logger.info(f"📊 Only {len(failed_control_ids)} controls out of {len(controls)} have failures")
        
        return {
            "total_rules_analyzed": len(df),
            "rules_with_failures": len(rule_control_matches),
            "rule_control_matches": rule_control_matches,
            "failed_control_count": len(failed_control_ids)
        }
    
    async def _call_llm_for_matching(self, prompt: str) -> List[Dict[str, Any]]:
        """Call LLM to match rules against controls."""
        try:
            timeout_config = httpx.Timeout(connect=10.0, read=90.0, write=10.0, pool=5.0)
            
            async with httpx.AsyncClient(timeout=timeout_config) as client:
                # Use Gemini API
                if "generativelanguage.googleapis.com" in self.llm_config['base_url']:
                    model_name = self.llm_config['model']
                    gemini_url = f"{self.llm_config['base_url']}/models/{model_name}:generateContent?key={self.llm_config['api_key']}"
                    
                    payload = {
                        "contents": [{
                            "parts": [{"text": prompt}]
                        }],
                        "generationConfig": {
                            "temperature": 0.3,
                            "maxOutputTokens": 4000
                        }
                    }
                    
                    response = await client.post(gemini_url, json=payload)
                    response.raise_for_status()
                    result = response.json()
                    
                    if 'candidates' in result and len(result['candidates']) > 0:
                        content = result['candidates'][0].get('content', {})
                        parts = content.get('parts', [])
                        if parts:
                            text_response = parts[0].get('text', '')
                            # Try to extract JSON from response
                            json_match = re.search(r'\[.*\]', text_response, re.DOTALL)
                            if json_match:
                                json_str = json_match.group(0)
                                matches = json.loads(json_str)
                                return matches
                
                # Fallback to OpenAI format
                else:
                    openai_url = f"{self.llm_config['base_url']}/v1/chat/completions"
                    headers = {"Content-Type": "application/json"}
                    if self.llm_config.get('api_key'):
                        headers["Authorization"] = f"Bearer {self.llm_config['api_key']}"
                    
                    payload = {
                        "model": self.llm_config['model'],
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.3,
                        "max_tokens": 4000
                    }
                    
                    response = await client.post(openai_url, json=payload, headers=headers)
                    response.raise_for_status()
                    result = response.json()
                    
                    if 'choices' in result and len(result['choices']) > 0:
                        text_response = result['choices'][0]['message']['content']
                        json_match = re.search(r'\[.*\]', text_response, re.DOTALL)
                        if json_match:
                            json_str = json_match.group(0)
                            matches = json.loads(json_str)
                            return matches
            
            return []
            
        except Exception as e:
            logger.error(f"❌ Error calling LLM for rule matching: {e}")
            logger.exception("Full traceback:")
            return []

