from __future__ import annotations
import re
import ipaddress
import logging
from typing import Dict, List, Tuple, Optional, Callable, Any
from functools import lru_cache
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count
import pickle
import io
import pandas as pd

# CPU throttling configuration - use max 50% of available cores to reduce CPU usage
MAX_CPU_USAGE_RATIO = 0.5  # Use 50% of available cores
MIN_WORKERS = 2  # Always use at least 2 workers
MAX_WORKERS_FIREWALL_GROUPS = 4  # Max workers for firewall group processing
MAX_WORKERS_PAIRS = 4  # Max workers for pair processing

# Column mapping (aliases)
DEFAULT_COLS: Dict[str, List[str]] = {
    "rule_name":   ["Rule_Name","Name","Rule Name","Rule"],
    "action":      ["Action"],
    "rule_order":  ["Rule_Order","Order","Seq","Sequence","Priority"],
    "src_addr":    ["Source Address","Src Address","SrcAddr","Source_Address"],
    "dst_addr":    ["Destination Address","Dst Address","DstAddr","Destination_Address"],
    "service":     ["Service","Port","Ports","Dst Port","Destination Port","App Port"],
    "source_file": ["Source_File","Firewall","Device","Policy_File"],
}

def resolve_columns(df: pd.DataFrame, overrides: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    out: Dict[str, str] = {}
    overrides = overrides or {}
    for key, candidates in DEFAULT_COLS.items():
        if key in overrides and overrides[key] in df.columns:
            out[key] = overrides[key]
            continue
        out[key] = next((c for c in candidates if c in df.columns), None)  # type: ignore
    missing = [k for k in ["rule_name","action","src_addr","dst_addr","service"] if out.get(k) is None]
    if missing:
        raise ValueError(f"Missing required columns: {missing}. Available: {list(df.columns)}")
    return out  # type: ignore

# ---- Cell splitting (supports ; and ,) ----
def split_cell_to_list(val) -> List[str]:
    if pd.isna(val):
        return ["any"]
    s = str(val).replace("[Disabled]","{}").replace("[Negate]","{}").strip()
    if not s:
        return ["any"]
    parts: List[str] = []
    for chunk in re.split(r"[;,]", s):
        token = chunk.strip()
        if token:
            parts.append(token.lower())
    return parts if parts else ["any"]

# ---- IP helpers with caching ----
@lru_cache(maxsize=50000)
def _ipnet(token: str) -> Optional[ipaddress._BaseNetwork]:
    """Cached IP network parser - huge performance boost"""
    t = (token or "").strip().lower()
    if t in ("", "any"):
        return None
    if "/" not in t:
        t = f"{t}/32"
    try:
        return ipaddress.ip_network(t, strict=False)
    except Exception:
        return None

def ip_covers_any(a_tokens: List[str], b_token: str) -> bool:
    """Standard version - parses on each call (cached by @lru_cache on _ipnet)"""
    b = _ipnet(b_token)
    for a_tok in a_tokens:
        if a_tok == "any":
            return True
        a = _ipnet(a_tok)
        if a is not None and b is not None:
            # Check if IP versions match before comparing
            try:
                if (a.supernet_of(b) or a == b):
                    return True
            except ValueError:
                # Different IP versions (IPv4 vs IPv6) - skip comparison
                continue
    return False

def ip_overlap_any(a_tokens: List[str], b_token: str) -> bool:
    """Standard version - parses on each call (cached by @lru_cache on _ipnet)"""
    b = _ipnet(b_token)
    for a_tok in a_tokens:
        if a_tok == "any":
            return True
        a = _ipnet(a_tok)
        if a is not None and b is not None:
            # Check if IP versions match before comparing
            try:
                if a.overlaps(b):
                    return True
            except ValueError:
                # Different IP versions (IPv4 vs IPv6) - skip comparison
                continue
    return False

def ip_covers_any_parsed(a_networks: List, has_any_a: bool, b_network) -> bool:
    """Optimized version using pre-computed networks"""
    if has_any_a:
        return True
    if b_network is None:
        return False
    for a_net in a_networks:
        try:
            if a_net.supernet_of(b_network) or a_net == b_network:
                return True
        except ValueError:
            # Different IP versions (IPv4 vs IPv6) - skip comparison
            continue
    return False

def ip_overlap_any_parsed(a_networks: List, has_any_a: bool, b_network) -> bool:
    """Optimized version using pre-computed networks"""
    if has_any_a:
        return True
    if b_network is None:
        return False
    for a_net in a_networks:
        try:
            if a_net.overlaps(b_network):
                return True
        except ValueError:
            # Different IP versions (IPv4 vs IPv6) - skip comparison
            continue
    return False

# ---- Service helpers (protocol-aware) with caching ----
_service_num = re.compile(r"^\d+$")
_service_rng = re.compile(r"^(\d+)\s*-\s*(\d+)$")
_proto_pref = re.compile(r"^(tcp|udp)\s*/\s*(.+)$", re.IGNORECASE)

@lru_cache(maxsize=50000)
def _parse_service(token: str) -> Tuple[str, Optional[Tuple[int, int]], Optional[str]]:
    """
    Cached service parser - huge performance boost
    Returns (kind, port_range, protocol)
    kind: any | label | range
    protocol: 'tcp' | 'udp' | None
    """
    t = (token or "").strip().lower()
    if t in ("", "any"):
        return ("any", None, None)
    mproto = _proto_pref.match(t)
    proto: Optional[str] = None
    payload = t
    if mproto:
        proto = mproto.group(1).lower()
        payload = mproto.group(2).strip()
    if _service_num.match(payload):
        p = int(payload)
        return ("range", (p, p), proto)
    mrng = _service_rng.match(payload)
    if mrng:
        a, b = int(mrng.group(1)), int(mrng.group(2))
        if a > b:
            a, b = b, a
        return ("range", (a, b), proto)
    return ("label", None, proto)

def _service_proto_match(proto_a: Optional[str], proto_b: Optional[str]) -> bool:
    if proto_a is None and proto_b is None:
        return True
    return proto_a is not None and proto_b is not None and proto_a == proto_b

def service_covers_any(a_tokens: List[str], b_token: str) -> bool:
    b_kind, b_rng, b_proto = _parse_service(b_token)
    for a_tok in a_tokens:
        a_kind, a_rng, a_proto = _parse_service(a_tok)
        if a_kind == "any":
            return True
        if not _service_proto_match(a_proto, b_proto):
            continue
        if a_kind == "label" and b_kind == "label" and a_tok == b_token.lower():
            return True
        if a_kind == "range" and b_kind == "range" and a_rng and b_rng:
            (a1, a2), (b1, b2) = a_rng, b_rng
            if a1 <= b1 and a2 >= b2:
                return True
    return False

def service_overlap_any(a_tokens: List[str], b_token: str) -> bool:
    b_kind, b_rng, b_proto = _parse_service(b_token)
    for a_tok in a_tokens:
        a_kind, a_rng, a_proto = _parse_service(a_tok)
        if a_kind == "any":
            return True
        if not _service_proto_match(a_proto, b_proto):
            continue
        if a_kind == "label" and b_kind == "label" and a_tok == b_token.lower():
            return True
        if a_kind == "range" and b_kind == "range" and a_rng and b_rng:
            (a1, a2), (b1, b2) = a_rng, b_rng
            if not (a2 < b1 or b2 < a1):
                return True
    return False

# ---- Helpers for per-field and classification ----
def list_covered_by(A: List[str], B: List[str], covers_any_fn, overlap_any_fn) -> Tuple[bool, bool, List[str]]:
    misses: List[str] = []
    all_overlap = True
    all_cover = True
    for b in B:
        covered = covers_any_fn(A, b)
        overlap = overlap_any_fn(A, b)
        if not covered:
            all_cover = False
            misses.append(b)
        if not overlap:
            all_overlap = False
    return all_cover, all_overlap, misses

@lru_cache(maxsize=1000)
def normalize_action(s: str) -> str:
    """Cached action normalizer"""
    t = (s or "").strip().lower()
    if t in ("permit","allow","accept","allow-all","accept-all"):
        return "allow"
    if t in ("deny","block","drop"):
        return "deny"
    return t or "deny"

def _row_sig(row: dict) -> Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...], str]:
    A_sa = tuple(split_cell_to_list(row.get("Source Address")))
    A_da = tuple(split_cell_to_list(row.get("Destination Address")))
    A_svc = tuple(split_cell_to_list(row.get("Service")))
    act = normalize_action(row.get("Action", ""))
    return A_sa, A_da, A_svc, act

def classify_pair(ruleA: dict, ruleB: dict) -> Tuple[str, str]:
    """Original classify_pair using raw row dicts - kept for backward compatibility"""
    actA, actB = normalize_action(ruleA.get("Action")), normalize_action(ruleB.get("Action"))
    try:
        ordA = int(ruleA.get("Rule_Order", 0))
        ordB = int(ruleB.get("Rule_Order", 0))
    except Exception:
        ordA, ordB = 0, 0
    if ordA >= ordB:
        return "", ""
    A_sa = split_cell_to_list(ruleA.get("Source Address"))
    A_da = split_cell_to_list(ruleA.get("Destination Address"))
    A_svc = split_cell_to_list(ruleA.get("Service"))
    B_sa = split_cell_to_list(ruleB.get("Source Address"))
    B_da = split_cell_to_list(ruleB.get("Destination Address"))
    B_svc = split_cell_to_list(ruleB.get("Service"))
    sa_full, sa_over, sa_miss = list_covered_by(A_sa, B_sa, ip_covers_any, ip_overlap_any)
    da_full, da_over, da_miss = list_covered_by(A_da, B_da, ip_covers_any, ip_overlap_any)
    sv_full, sv_over, sv_miss = list_covered_by(A_svc, B_svc, service_covers_any, service_overlap_any)
    if actA != actB and sa_full and da_full and sv_full:
        reason = (
            f"Earlier rule ({ruleA.get('Rule_Name')}, {actA}) fully covers later rule "
            f"({ruleB.get('Rule_Name')}, {actB}) across Source, Destination, and Service."
        )
        return "Shadow", reason
    if actA != actB and sa_over and da_over and sv_over and not (sa_full and da_full and sv_full):
        missing_bits: List[str] = []
        if not sa_full and sa_miss:
            missing_bits.append(f"uncovered Source {sa_miss}")
        if not da_full and da_miss:
            missing_bits.append(f"uncovered Destination {da_miss}")
        if not sv_full and sv_miss:
            missing_bits.append(f"uncovered Service {sv_miss}")
        miss_str = "; ".join(missing_bits) if missing_bits else "some portions not covered"
        reason = (
            f"Earlier rule ({ruleA.get('Rule_Name')}, {actA}) overlaps with later rule "
            f"({ruleB.get('Rule_Name')}, {actB}) in all fields but does not fully cover: {miss_str}."
        )
        return "Partial Shadow", reason
    return "", ""

def _process_pair_chunk(args):
    """
    Worker function to process a chunk of pairs in parallel.
    Args: (pair_chunk, parsed_rules, idxs, chunk_index, total_chunks, total_pairs, is_reverse=False)
    Returns: dict with updates and counters
    """
    if len(args) >= 7:
        pair_chunk, parsed_rules, idxs, chunk_index, total_chunks, total_pairs, is_reverse = args
    else:
        pair_chunk, parsed_rules, idxs, chunk_index, total_chunks, total_pairs = args
        is_reverse = False
    
    shadow_updates = {}
    partial_shadow_updates = {}
    shadow_reasons = {}
    redundant_updates = {}
    redundant_reasons = {}
    generalization_updates = {}
    generalization_reasons = {}
    correlation_updates = {}
    correlation_reasons = {}
    
    shadow_found = 0
    partial_shadow_found = 0
    redundant_found = 0
    generalization_found = 0
    correlation_found = 0
    
    pairs_in_chunk = len(pair_chunk)
    
    for idx_in_chunk, (i, j) in enumerate(pair_chunk):
        try:
            # Determine rule order based on indices
            # Forward pass: i > j (i is later, j is earlier)
            # Reverse pass: j > i (j is later, i is earlier) 
            if is_reverse:
                # Reverse pass: j > i, so j is later rule, i is earlier rule
                A = parsed_rules[i]  # Earlier rule (lower index)
                B = parsed_rules[j]  # Later rule (higher index)
            else:
                # Forward pass: i > j, so i is later rule, j is earlier rule  
                A = parsed_rules[j]  # Earlier rule (lower index)
                B = parsed_rules[i]  # Later rule (higher index)
            
            # ⚡ OPTIMIZATION: Early termination - skip if rule order invalid
            if A['ord'] >= B['ord']:
                continue
            
            # ⚡ OPTIMIZATION: Early exit - check actions first to avoid unnecessary work
            actions_differ = A['act'] != B['act']
            
            if is_reverse:
                # Reverse pass: Check if later rule B affects earlier rule A
                # Note: A = earlier (index i), B = later (index j)
                # Shadow / Partial shadow (only if actions differ)
                if actions_differ:
                    label, reason = classify_pair_parsed(B, A)  # Check if later rule B affects earlier rule A
                    if label == "Shadow":
                        shadow_updates[idxs[i]] = True  # Mark earlier rule A (at index i)
                        shadow_reasons[idxs[i]] = reason
                        shadow_found += 1
                        continue
                    elif label == "Partial Shadow":
                        # Only mark as Partial Shadow if not already marked as Shadow (Shadow takes precedence)
                        if idxs[i] not in shadow_updates:
                            partial_shadow_updates[idxs[i]] = True  # Mark earlier rule A
                            shadow_reasons[idxs[i]] = reason
                            partial_shadow_found += 1
                
                # Separate logic paths for same/different actions
                if not actions_differ:  # Same action
                    # Redundancy: Is earlier rule A redundant to later rule B?
                    sa_full, _, _ = list_covered_by(B['sa_list'], A['sa_list'], ip_covers_any, ip_overlap_any)
                    if sa_full:
                        da_full, _, _ = list_covered_by(B['da_list'], A['da_list'], ip_covers_any, ip_overlap_any)
                        if da_full:
                            sv_full, _, _ = list_covered_by(B['sv_list'], A['sv_list'], service_covers_any, service_overlap_any)
                            if sv_full:
                                ruleA_name = A['row'].get('Rule_Name', 'Unknown')
                                ruleB_name = B['row'].get('Rule_Name', 'Unknown')
                                redundant_updates[idxs[i]] = True  # Mark earlier rule A
                                redundant_reasons[idxs[i]] = f"{ruleA_name} / Same action and fully covered by later rule {ruleB_name}"
                                redundant_found += 1
                                continue
                else:
                    # Actions differ - check generalization
                    # Does earlier rule A generalize later rule B?
                    sa_ba, _, _ = list_covered_by(A['sa_list'], B['sa_list'], ip_covers_any, ip_overlap_any)
                    if sa_ba:
                        da_ba, _, _ = list_covered_by(A['da_list'], B['da_list'], ip_covers_any, ip_overlap_any)
                        if da_ba:
                            sv_ba, _, _ = list_covered_by(A['sv_list'], B['sv_list'], service_covers_any, service_overlap_any)
                            if sv_ba:
                                broader = False
                                if not ip_covers_any(B['sa_list'], A['sa_list'][0]) if A['sa_list'] else False:
                                    broader = True
                                elif not ip_covers_any(B['da_list'], A['da_list'][0]) if A['da_list'] else False:
                                    broader = True
                                elif not service_covers_any(B['sv_list'], A['sv_list'][0]) if A['sv_list'] else False:
                                    broader = True
                                if broader:
                                    ruleA_name = A['row'].get('Rule_Name', 'Unknown')
                                    ruleB_name = B['row'].get('Rule_Name', 'Unknown')
                                    generalization_updates[idxs[i]] = True  # Mark earlier rule A
                                    generalization_reasons[idxs[i]] = f"{ruleA_name} / Generalizes later rule {ruleB_name}"
                                    generalization_found += 1
                    
                    # Correlation check (bidirectional - same logic both directions)
                    if idxs[i] not in shadow_updates and idxs[i] not in partial_shadow_updates:
                        sa_over = ip_overlap_any(A['sa_list'], B['sa_list'][0]) if B['sa_list'] else False
                        if sa_over:
                            da_over = ip_overlap_any(A['da_list'], B['da_list'][0]) if B['da_list'] else False
                            if da_over:
                                sv_over = service_overlap_any(A['sv_list'], B['sv_list'][0]) if B['sv_list'] else False
                                if sv_over:
                                    sa_full = ip_covers_any(A['sa_list'], B['sa_list'][0]) if B['sa_list'] else False
                                    da_full = ip_covers_any(A['da_list'], B['da_list'][0]) if B['da_list'] else False
                                    sv_full = service_covers_any(A['sv_list'], B['sv_list'][0]) if B['sv_list'] else False
                                    if not (sa_full and da_full and sv_full):
                                        ruleA_name = A['row'].get('Rule_Name', 'Unknown')
                                        ruleB_name = B['row'].get('Rule_Name', 'Unknown')
                                        correlation_updates[idxs[i]] = True  # Mark earlier rule A
                                        correlation_reasons[idxs[i]] = f"{ruleA_name} & {ruleB_name} / Partially overlap with different actions"
                                        correlation_found += 1
            else:
                # Forward pass: Check if earlier rule A affects later rule B (original logic)
                # Shadow / Partial shadow (only if actions differ)
                if actions_differ:
                    label, reason = classify_pair_parsed(A, B)
                    if label == "Shadow":
                        shadow_updates[idxs[i]] = True
                        shadow_reasons[idxs[i]] = reason
                        shadow_found += 1
                        continue
                    elif label == "Partial Shadow":
                        # Only mark as Partial Shadow if not already marked as Shadow (Shadow takes precedence)
                        if idxs[i] not in shadow_updates:
                            partial_shadow_updates[idxs[i]] = True
                            shadow_reasons[idxs[i]] = reason
                            partial_shadow_found += 1
                
                # Separate logic paths for same/different actions
                if not actions_differ:  # Same action
                    # Redundancy check (same action, B fully covered by A)
                    sa_full, _, _ = list_covered_by(A['sa_list'], B['sa_list'], ip_covers_any, ip_overlap_any)
                    if sa_full:
                        da_full, _, _ = list_covered_by(A['da_list'], B['da_list'], ip_covers_any, ip_overlap_any)
                        if da_full:
                            sv_full, _, _ = list_covered_by(A['sv_list'], B['sv_list'], service_covers_any, service_overlap_any)
                            if sv_full:
                                ruleA_name = A['row'].get('Rule_Name', 'Unknown')
                                ruleB_name = B['row'].get('Rule_Name', 'Unknown')
                                redundant_updates[idxs[i]] = True
                                redundant_reasons[idxs[i]] = f"{ruleB_name} / Same action and fully covered by earlier rule {ruleA_name}"
                                redundant_found += 1
                                continue
                else:
                    # Actions differ - check generalization (already checked shadow/partial shadow above)
                    sa_ba, _, _ = list_covered_by(B['sa_list'], A['sa_list'], ip_covers_any, ip_overlap_any)
                    if sa_ba:
                        da_ba, _, _ = list_covered_by(B['da_list'], A['da_list'], ip_covers_any, ip_overlap_any)
                        if da_ba:
                            sv_ba, _, _ = list_covered_by(B['sv_list'], A['sv_list'], service_covers_any, service_overlap_any)
                            if sv_ba:
                                # Check if B is broader than A
                                broader = False
                                if not ip_covers_any(A['sa_list'], B['sa_list'][0]) if B['sa_list'] else False:
                                    broader = True
                                elif not ip_covers_any(A['da_list'], B['da_list'][0]) if B['da_list'] else False:
                                    broader = True
                                elif not service_covers_any(A['sv_list'], B['sv_list'][0]) if B['sv_list'] else False:
                                    broader = True
                                if broader:
                                    ruleA_name = A['row'].get('Rule_Name', 'Unknown')
                                    ruleB_name = B['row'].get('Rule_Name', 'Unknown')
                                    generalization_updates[idxs[i]] = True
                                    generalization_reasons[idxs[i]] = f"{ruleB_name} / Generalizes earlier rule {ruleA_name}"
                                    generalization_found += 1
                    
                    # Correlation check (partial overlap, not full coverage)
                    # Only check if not already shadow/partial shadow
                    if idxs[i] not in shadow_updates and idxs[i] not in partial_shadow_updates:
                        sa_over = ip_overlap_any(A['sa_list'], B['sa_list'][0]) if B['sa_list'] else False
                        if sa_over:
                            da_over = ip_overlap_any(A['da_list'], B['da_list'][0]) if B['da_list'] else False
                            if da_over:
                                sv_over = service_overlap_any(A['sv_list'], B['sv_list'][0]) if B['sv_list'] else False
                                if sv_over:
                                    sa_full = ip_covers_any(A['sa_list'], B['sa_list'][0]) if B['sa_list'] else False
                                    da_full = ip_covers_any(A['da_list'], B['da_list'][0]) if B['da_list'] else False
                                    sv_full = service_covers_any(A['sv_list'], B['sv_list'][0]) if B['sv_list'] else False
                                    if not (sa_full and da_full and sv_full):
                                        ruleA_name = A['row'].get('Rule_Name', 'Unknown')
                                        ruleB_name = B['row'].get('Rule_Name', 'Unknown')
                                        correlation_updates[idxs[i]] = True
                                        correlation_reasons[idxs[i]] = f"{ruleA_name} & {ruleB_name} / Partially overlap with different actions"
                                        correlation_found += 1
        except Exception as e:
            # Skip this pair if there's an error (e.g., IP version mismatch)
            # Suppress expected IPv4/IPv6 version mismatch warnings
            error_msg = str(e)
            if "not of the same version" in error_msg:
                # This is expected - IPv4 and IPv6 addresses don't compare
                # Only log at DEBUG level to reduce noise
                import logging
                logging.debug(f"Skipping pair ({i}, {j}) - IPv4/IPv6 version mismatch: {e}")
            elif isinstance(e, ValueError):
                # Other ValueError (also likely IP-related) - log at DEBUG
                import logging
                logging.debug(f"Skipping pair ({i}, {j}) due to IP error: {e}")
            else:
                # Unexpected errors - log as warning
                import logging
                logging.warning(f"Skipping pair ({i}, {j}) due to error: {e}")
            continue
    
    return {
        'shadow_updates': shadow_updates,
        'partial_shadow_updates': partial_shadow_updates,
        'shadow_reasons': shadow_reasons,
        'redundant_updates': redundant_updates,
        'redundant_reasons': redundant_reasons,
        'generalization_updates': generalization_updates,
        'generalization_reasons': generalization_reasons,
        'correlation_updates': correlation_updates,
        'correlation_reasons': correlation_reasons,
        'shadow_found': shadow_found,
        'partial_shadow_found': partial_shadow_found,
        'redundant_found': redundant_found,
        'generalization_found': generalization_found,
        'correlation_found': correlation_found,
        'chunk_index': chunk_index,
        'pairs_processed': pairs_in_chunk
    }

def classify_pair_parsed(parsed_A: dict, parsed_B: dict) -> Tuple[str, str]:
    """Optimized classify_pair using pre-parsed data - avoids redundant parsing"""
    actA, actB = parsed_A['act'], parsed_B['act']
    if parsed_A['ord'] >= parsed_B['ord']:
        return "", ""
    
    # Use pre-parsed lists directly - no need to re-parse
    A_sa = parsed_A['sa_list']
    A_da = parsed_A['da_list']
    A_svc = parsed_A['sv_list']
    B_sa = parsed_B['sa_list']
    B_da = parsed_B['da_list']
    B_svc = parsed_B['sv_list']
    
    sa_full, sa_over, sa_miss = list_covered_by(A_sa, B_sa, ip_covers_any, ip_overlap_any)
    da_full, da_over, da_miss = list_covered_by(A_da, B_da, ip_covers_any, ip_overlap_any)
    sv_full, sv_over, sv_miss = list_covered_by(A_svc, B_svc, service_covers_any, service_overlap_any)
    
    ruleA_name = parsed_A['row'].get('Rule_Name', 'Unknown')
    ruleB_name = parsed_B['row'].get('Rule_Name', 'Unknown')
    
    if actA != actB and sa_full and da_full and sv_full:
        # Format: "Rule Name / reason"
        reason = f"{ruleA_name} / Fully covers later rule {ruleB_name} ({actA} vs {actB})"
        return "Shadow", reason
    if actA != actB and sa_over and da_over and sv_over and not (sa_full and da_full and sv_full):
        missing_bits: List[str] = []
        if not sa_full and sa_miss:
            missing_bits.append(f"uncovered Source {sa_miss}")
        if not da_full and da_miss:
            missing_bits.append(f"uncovered Destination {da_miss}")
        if not sv_full and sv_miss:
            missing_bits.append(f"uncovered Service {sv_miss}")
        miss_str = "; ".join(missing_bits) if missing_bits else "some portions not covered"
        # Format: "Rule Name / reason"
        reason = f"{ruleA_name} / Overlaps with later rule {ruleB_name} ({actA} vs {actB}) but does not fully cover: {miss_str}"
        return "Partial Shadow", reason
    return "", ""

# Worker function for parallel processing (must be at module level for multiprocessing)
def _process_firewall_group_worker(args):
    """
    Worker function for parallel processing of a single firewall group.
    Must be a standalone function that can be pickled.
    
    Args:
        args: Tuple of (group_key, sub_df_bytes, group_index, total_groups, idxs_bytes)
    
    Returns:
        Tuple of (group_key, updates_dict, summary_dict)
    """
    group_key, sub_df_bytes, group_index, total_groups, idxs_bytes = args
    
    # Import necessary modules in worker process
    import pandas as pd
    import io
    import pickle
    
    # Deserialize DataFrame and indices
    sub = pd.read_pickle(io.BytesIO(sub_df_bytes))
    idxs = pickle.loads(idxs_bytes)
    
    firewall_name = group_key if group_key else "All Rules"
    
    # Counters for progress tracking
    shadow_found = 0
    partial_shadow_found = 0
    redundant_found = 0
    generalization_found = 0
    correlation_found = 0
    
    # Batch DataFrame updates
    shadow_updates = {}
    partial_shadow_updates = {}
    shadow_reasons = {}
    redundant_updates = {}
    redundant_reasons = {}
    generalization_updates = {}
    generalization_reasons = {}
    correlation_updates = {}
    correlation_reasons = {}
    consolidation_updates = {}
    
    rows = sub.to_dict("records")
    
    # Pre-parse ALL rule data once with pre-computed IP networks and service parsings
    # This reduces CPU usage by avoiding repeated parsing in hot loops
    parsed_rules = []
    for row in rows:
        sa_list = split_cell_to_list(row.get("Source Address"))
        da_list = split_cell_to_list(row.get("Destination Address"))
        sv_list = split_cell_to_list(row.get("Service"))
        act = normalize_action(row.get("Action", ""))
        ord_val = int(row.get("Rule_Order", 0))
        
        # Pre-compute IP networks for faster comparisons (RAM-based optimization)
        sa_networks = []
        has_any_sa = 'any' in sa_list
        for sa_tok in sa_list:
            if sa_tok != "any":
                net = _ipnet(sa_tok)
                if net:
                    sa_networks.append(net)
        
        da_networks = []
        has_any_da = 'any' in da_list
        for da_tok in da_list:
            if da_tok != "any":
                net = _ipnet(da_tok)
                if net:
                    da_networks.append(net)
        
        # Pre-parse services for faster comparisons
        sv_parsed = []
        for sv_tok in sv_list:
            sv_parsed.append(_parse_service(sv_tok))
        
        parsed_rules.append({
            'row': row,
            'sa_list': sa_list,
            'da_list': da_list,
            'sv_list': sv_list,
            'act': act,
            'ord': ord_val,
            # Pre-computed lookups stored in RAM
            'sa_networks': sa_networks,
            'da_networks': da_networks,
            'sv_parsed': sv_parsed,
            'has_any_sa': has_any_sa,
            'has_any_da': has_any_da
        })
    
    total_pairs = sum(range(len(parsed_rules))) if len(parsed_rules) > 0 else 0
    
    # Pairwise analyses
    pairs_processed = 0
    for i in range(len(parsed_rules)):
        B = parsed_rules[i]
        for j in range(i):
            A = parsed_rules[j]
            pairs_processed += 1
            
            # Early termination - skip if rule order invalid
            if A['ord'] >= B['ord']:
                continue
            
            # Shadow / Partial shadow (only if actions differ)
            if A['act'] != B['act']:
                label, reason = classify_pair(A['row'], B['row'])
                if label == "Shadow":
                    shadow_updates[idxs[i]] = True
                    shadow_reasons[idxs[i]] = reason
                    shadow_found += 1
                elif label == "Partial Shadow":
                    # Only mark as Partial Shadow if not already marked as Shadow (Shadow takes precedence)
                    if idxs[i] not in shadow_updates:
                        partial_shadow_updates[idxs[i]] = True
                        shadow_reasons[idxs[i]] = reason
                        partial_shadow_found += 1
            
            # Separate logic paths for same/different actions
            if A['act'] == B['act']:
                # Redundancy check (same action, B fully covered by A)
                sa_full, _, _ = list_covered_by(A['sa_list'], B['sa_list'], ip_covers_any, ip_overlap_any)
                if sa_full:
                    da_full, _, _ = list_covered_by(A['da_list'], B['da_list'], ip_covers_any, ip_overlap_any)
                    if da_full:
                        sv_full, _, _ = list_covered_by(A['sv_list'], B['sv_list'], service_covers_any, service_overlap_any)
                        if sv_full:
                            redundant_updates[idxs[i]] = True
                            redundant_reasons[idxs[i]] = f"Same action as earlier rule {A['row'].get('Rule_Name')} and fully covered."
                            redundant_found += 1
            else:
                # Actions differ - check generalization
                sa_ba, _, _ = list_covered_by(B['sa_list'], A['sa_list'], ip_covers_any, ip_overlap_any)
                if sa_ba:
                    da_ba, _, _ = list_covered_by(B['da_list'], A['da_list'], ip_covers_any, ip_overlap_any)
                    if da_ba:
                        sv_ba, _, _ = list_covered_by(B['sv_list'], A['sv_list'], service_covers_any, service_overlap_any)
                        if sv_ba:
                            # Check if B is broader than A
                            broader = False
                            if not ip_covers_any(A['sa_list'], B['sa_list'][0]) if B['sa_list'] else False:
                                broader = True
                            elif not ip_covers_any(A['da_list'], B['da_list'][0]) if B['da_list'] else False:
                                broader = True
                            elif not service_covers_any(A['sv_list'], B['sv_list'][0]) if B['sv_list'] else False:
                                broader = True
                            if broader:
                                generalization_updates[idxs[i]] = True
                                generalization_reasons[idxs[i]] = f"Later rule {B['row'].get('Rule_Name')} generalizes earlier {A['row'].get('Rule_Name')}."
                                generalization_found += 1
                
                # Correlation check (partial overlap, not full coverage)
                if idxs[i] not in shadow_updates and idxs[i] not in partial_shadow_updates:
                    sa_over = ip_overlap_any(A['sa_list'], B['sa_list'][0]) if B['sa_list'] else False
                    if sa_over:
                        da_over = ip_overlap_any(A['da_list'], B['da_list'][0]) if B['da_list'] else False
                        if da_over:
                            sv_over = service_overlap_any(A['sv_list'], B['sv_list'][0]) if B['sv_list'] else False
                            if sv_over:
                                sa_full = ip_covers_any(A['sa_list'], B['sa_list'][0]) if B['sa_list'] else False
                                da_full = ip_covers_any(A['da_list'], B['da_list'][0]) if B['da_list'] else False
                                sv_full = service_covers_any(A['sv_list'], B['sv_list'][0]) if B['sv_list'] else False
                                if not (sa_full and da_full and sv_full):
                                    correlation_updates[idxs[i]] = True
                                    correlation_reasons[idxs[i]] = f"Rules {A['row'].get('Rule_Name')} and {B['row'].get('Rule_Name')} partially overlap with different actions."
                                    correlation_found += 1
    
    # Consolidation candidates
    sub_rows = sub.to_dict("records")
    buckets: Dict[Tuple[str, str, str], List[int]] = {}
    
    # Create a mapping from DataFrame index to rule name for consolidation
    sub_idx_to_name = {idx: row.get('Rule_Name', 'Unknown') for idx, row in zip(sub.index.tolist(), sub_rows)}
    
    for idx, row in zip(sub.index.tolist(), sub_rows):
        act = normalize_action(row.get("Action"))
        sa = tuple(sorted(split_cell_to_list(row.get("Source Address"))))
        da = tuple(sorted(split_cell_to_list(row.get("Destination Address"))))
        sv = tuple(sorted(split_cell_to_list(row.get("Service"))))
        # three bucket keys (fix two, vary one)
        for key in [("SA", act, da, sv), ("DA", act, sa, sv), ("SV", act, sa, da)]:
            buckets.setdefault(tuple(map(str, key)), []).append(idx)
    
    consolidation_count = 0
    for key, idcs in buckets.items():
        if len(idcs) >= 2:
            consolidation_count += len(idcs)
            # Get all rule names in this consolidation bucket
            rule_names = [sub_idx_to_name.get(idx, 'Unknown') for idx in idcs]
            rule_names_str = ", ".join(rule_names) if rule_names else "Unknown"
            
            # Determine which field differs based on the key
            key_parts = list(key)
            differing_field = key_parts[0]  # First element indicates which field varies
            field_name_map = {
                "SA": "Source Address",
                "DA": "Destination Address", 
                "SV": "Service"
            }
            differing_field_name = field_name_map.get(differing_field, "one field")
            
            # Build list of identical fields
            identical_fields = [f for f in ['Source Address', 'Destination Address', 'Service'] if f != differing_field_name]
            identical_fields_str = ' and '.join(identical_fields) if len(identical_fields) == 2 else identical_fields[0]
            
            consolidation_reason = f"{rule_names_str} / These rules have the same Action and identical {identical_fields_str}, but differ in {differing_field_name}. They can be consolidated into a single rule."
            
            # Consolidation_Key should contain rule names for easy identification
            consolidation_key = rule_names_str
            
            for idx in idcs:
                consolidation_updates[idx] = {
                    'Consolidation_Candidate': True,
                    'Consolidation_Key': consolidation_key,  # Use rule names instead of technical key
                    'Consolidation_Reason': consolidation_reason
                }
    
    # Return results
    updates = {
        'shadow_updates': shadow_updates,
        'partial_shadow_updates': partial_shadow_updates,
        'shadow_reasons': shadow_reasons,
        'redundant_updates': redundant_updates,
        'redundant_reasons': redundant_reasons,
        'generalization_updates': generalization_updates,
        'generalization_reasons': generalization_reasons,
        'correlation_updates': correlation_updates,
        'correlation_reasons': correlation_reasons,
        'consolidation_updates': consolidation_updates
    }
    
    summary = {
        'shadow_found': shadow_found,
        'partial_shadow_found': partial_shadow_found,
        'redundant_found': redundant_found,
        'generalization_found': generalization_found,
        'correlation_found': correlation_found,
        'consolidation_count': consolidation_count,
        'total_pairs': total_pairs,
        'total_rules': len(rows)
    }
    
    return (group_key, updates, summary)


def detect_policy(df: pd.DataFrame, column_overrides: Optional[Dict[str, str]] = None, 
                 group_by_file: bool = True, progress_callback: Optional[Callable] = None,
                 max_parallel: int = 50, batch_size: int = 50, use_parallel: bool = True) -> pd.DataFrame:
    logging.info("  🔧 Resolving column names...")
    if progress_callback:
        progress_callback("column_resolution", "📋 Resolving column names from Excel...", 10)
    
    df = df.copy()
    cols = resolve_columns(df, overrides=column_overrides)
    logging.info(f"     Found columns: Rule_Name={cols.get('rule_name')}, Action={cols.get('action')}, "
                 f"Source={cols.get('src_addr')}, Destination={cols.get('dst_addr')}, Service={cols.get('service')}")
    
    df = df.rename(columns={
        cols["rule_name"]: "Rule_Name",
        cols["action"]:   "Action",
        cols["src_addr"]: "Source Address",
        cols["dst_addr"]: "Destination Address",
        cols["service"]:  "Service",
        **({cols["rule_order"]: "Rule_Order"} if cols.get("rule_order") else {}),
        **({cols["source_file"]: "Source_File"} if cols.get("source_file") else {}),
    })
    
    if "Rule_Order" not in df.columns:
        if "Source_File" in df.columns:
            logging.info("  📝 Generating Rule_Order per Source_File...")
            df["Rule_Order"] = df.groupby("Source_File").cumcount() + 1
        else:
            logging.info("  📝 Generating sequential Rule_Order...")
            df["Rule_Order"] = range(1, len(df) + 1)
    
    # Initialize output columns
    logging.info("  📋 Initializing analysis result columns...")
    if progress_callback:
        progress_callback("initializing", "⚙️ Initializing analysis result columns (Shadow, Redundancy, Generalization, Correlation, Consolidation)...", 12)
    df["Shadow_Rule"] = False
    df["Partial_Shadow_Rule"] = False
    df["Shadow_Reason"] = ""
    df["Redundant_Rule"] = False
    df["Redundancy_Reason"] = ""
    df["Generalization_Risk"] = False
    df["Generalization_Reason"] = ""
    df["Correlation_Risk"] = False
    df["Correlation_Reason"] = ""
    df["Consolidation_Candidate"] = False
    df["Consolidation_Key"] = ""
    df["Consolidation_Reason"] = ""
    
    groups = (
        [(k, g.sort_values("Rule_Order")) for k, g in df.groupby("Source_File")]
        if group_by_file and "Source_File" in df.columns
        else [(None, df.sort_values("Rule_Order"))]
    )
    
    total_groups = len(groups)
    logging.info(f"  🔍 Processing {total_groups} firewall group(s)...")
    
    if progress_callback:
        progress_callback("firewall_analysis_start", 
                         f"🔍 Starting analysis of {total_groups} firewall group(s)...", 
                         15, 
                         total_firewalls=total_groups)
    
    # Determine if we should use parallel processing
    use_parallel_processing = (use_parallel and total_groups > 1)
    
    if use_parallel_processing:
        # ⚡ OPTIMIZATION: Parallel batch processing
        # Split groups into batches
        batches = []
        for i in range(0, len(groups), batch_size):
            batch = groups[i:i + batch_size]
            batches.append(batch)
        
        logging.info(f"  🔀 Using parallel processing: {len(batches)} batch(es) of up to {batch_size} firewall(s) each")
        
        all_updates = {}
        all_summaries = {}
        # CPU throttling: Use max 50% of cores or configured max, whichever is smaller
        available_cores = max(MIN_WORKERS, int(cpu_count() * MAX_CPU_USAGE_RATIO))
        process_count = min(max_parallel, MAX_WORKERS_FIREWALL_GROUPS, available_cores, total_groups)
        logging.info(f"  ⚙️ CPU throttling: Using {process_count} workers (out of {cpu_count()} available cores)")
        
        completed_groups = 0
        
        for batch_num, batch in enumerate(batches):
            logging.info(f"  📦 Processing batch {batch_num + 1}/{len(batches)} ({len(batch)} firewall group(s))...")
            
            # Prepare arguments for each firewall in batch
            batch_args = []
            for idx, (group_key, sub) in enumerate(batch):
                group_index = completed_groups + idx + 1
                idxs = sub.index.tolist()
                
                # Serialize DataFrame and indices for multiprocessing
                sub_bytes = io.BytesIO()
                sub.to_pickle(sub_bytes)
                sub_bytes.seek(0)
                idxs_bytes = pickle.dumps(idxs)
                
                batch_args.append((
                    group_key,
                    sub_bytes.getvalue(),
                    group_index,
                    total_groups,
                    idxs_bytes
                ))
            
            # Process batch in parallel
            with ProcessPoolExecutor(max_workers=min(process_count, len(batch))) as executor:
                futures = {executor.submit(_process_firewall_group_worker, args): args[0] 
                          for args in batch_args}
                
                batch_results = {}
                for future in as_completed(futures):
                    group_key = futures[future]
                    try:
                        result_group_key, updates, summary = future.result()
                        batch_results[result_group_key] = (updates, summary)
                        completed_groups += 1
                        
                        # Update progress callback (approximate progress)
                        if progress_callback:
                            progress_percent = int(15 + (completed_groups / total_groups) * 80)
                            progress_callback("firewall_complete",
                                            f"✅ [{completed_groups}/{total_groups}] Firewall '{result_group_key if result_group_key else 'All Rules'}' analysis complete.",
                                            progress_percent,
                                            firewall_name=result_group_key if result_group_key else "All Rules",
                                            firewall_percent=100,
                                            firewall_index=completed_groups,
                                            total_firewalls=total_groups)
                    except Exception as e:
                        logging.error(f"❌ Error processing firewall {group_key}: {e}")
                        import traceback
                        logging.error(traceback.format_exc())
                
                # Store batch results
                all_updates.update({k: v[0] for k, v in batch_results.items()})
                all_summaries.update({k: v[1] for k, v in batch_results.items()})
        
        # Apply all updates to DataFrame in batch
        logging.info(f"  💾 Applying updates from {len(all_updates)} firewall(s) to DataFrame...")
        
        total_issues = 0
        for group_key, updates in all_updates.items():
            summary = all_summaries.get(group_key, {})
            total_issues += (len(updates.get('shadow_updates', {})) + 
                           len(updates.get('partial_shadow_updates', {})) +
                           len(updates.get('redundant_updates', {})) +
                           len(updates.get('generalization_updates', {})) +
                           len(updates.get('correlation_updates', {})))
            
            # Apply all updates
            for idx, val in updates.get('shadow_updates', {}).items():
                df.loc[idx, "Shadow_Rule"] = val
                df.loc[idx, "Shadow_Reason"] = updates.get('shadow_reasons', {}).get(idx, "")
                # Clear Partial Shadow if Shadow is set (Shadow takes precedence)
                if val:
                    df.loc[idx, "Partial_Shadow_Rule"] = False
            
            for idx, val in updates.get('partial_shadow_updates', {}).items():
                # Only set Partial Shadow if not already marked as Shadow (Shadow takes precedence)
                if idx not in updates.get('shadow_updates', {}):
                    df.loc[idx, "Partial_Shadow_Rule"] = val
                    df.loc[idx, "Shadow_Reason"] = updates.get('shadow_reasons', {}).get(idx, "")
            
            for idx, val in updates.get('redundant_updates', {}).items():
                df.loc[idx, "Redundant_Rule"] = val
                df.loc[idx, "Redundancy_Reason"] = updates.get('redundant_reasons', {}).get(idx, "")
            
            for idx, val in updates.get('generalization_updates', {}).items():
                df.loc[idx, "Generalization_Risk"] = val
                df.loc[idx, "Generalization_Reason"] = updates.get('generalization_reasons', {}).get(idx, "")
            
            for idx, val in updates.get('correlation_updates', {}).items():
                df.loc[idx, "Correlation_Risk"] = val
                df.loc[idx, "Correlation_Reason"] = updates.get('correlation_reasons', {}).get(idx, "")
            
            for idx, consolidation_data in updates.get('consolidation_updates', {}).items():
                df.loc[idx, "Consolidation_Candidate"] = consolidation_data.get('Consolidation_Candidate', False)
                df.loc[idx, "Consolidation_Key"] = consolidation_data.get('Consolidation_Key', "")
                df.loc[idx, "Consolidation_Reason"] = consolidation_data.get('Consolidation_Reason', "")
            
            # Log summary
            logging.info(f"        '{group_key if group_key else 'All Rules'}': "
                        f"Shadow={summary.get('shadow_found', 0)}, Partial Shadow={summary.get('partial_shadow_found', 0)}, "
                        f"Redundant={summary.get('redundant_found', 0)}, Generalization={summary.get('generalization_found', 0)}, "
                        f"Correlation={summary.get('correlation_found', 0)}, Consolidation={summary.get('consolidation_count', 0)}")
        
        logging.info(f"  ✅ Applied {total_issues} detected issues from parallel processing")
        
    else:
        # Fallback to sequential processing (original code)
        logging.info("  🔄 Using sequential processing (parallel processing disabled or not beneficial)")
        group_num = 0
        for group_key, sub in groups:
            group_num += 1
            firewall_name = group_key if group_key else "All Rules"
        
        if group_key:
            logging.info(f"     [{group_num}/{total_groups}] Analyzing firewall: '{group_key}' ({len(sub)} rules)...")
        else:
            logging.info(f"     [{group_num}/{total_groups}] Analyzing all rules ({len(sub)} rules)...")
        
        # Calculate base progress for this firewall (15% start + 80% for all firewalls)
        # Each firewall gets 80/total_groups percent of overall progress
        firewall_progress_range = 80 / max(total_groups, 1)
        firewall_base_progress = 15 + (group_num - 1) * firewall_progress_range
        
        if progress_callback:
            progress_callback("firewall_start", 
                            f"🔧 [{group_num}/{total_groups}] Starting analysis of firewall: '{firewall_name}' ({len(sub)} rules)...", 
                            int(firewall_base_progress), 
                            firewall_name=firewall_name, 
                            firewall_percent=0,
                            firewall_index=group_num, 
                            total_firewalls=total_groups,
                            rules_processed=0, 
                            total_rules=len(sub))
        
        rows = sub.to_dict("records")
        idxs = sub.index.tolist()
        
        # ⚡ OPTIMIZATION 1: Pre-parse ALL rule data once (50-70% speedup)
        # ⚡ OPTIMIZATION 3: Pre-compute IP networks for faster comparisons
        logging.info(f"        Pre-parsing {len(rows)} rules (IP networks, services, actions)...")
        parsed_rules = []
        for row in rows:
            # Parse once, reuse everywhere - avoids repeated parsing
            sa_list = split_cell_to_list(row.get("Source Address"))
            da_list = split_cell_to_list(row.get("Destination Address"))
            sv_list = split_cell_to_list(row.get("Service"))
            act = normalize_action(row.get("Action", ""))
            ord_val = int(row.get("Rule_Order", 0))
            
            # Pre-compute IP networks for all source and destination IPs (RAM-based optimization)
            sa_networks = []
            has_any_sa = 'any' in sa_list
            for sa_tok in sa_list:
                if sa_tok != "any":
                    net = _ipnet(sa_tok)
                    if net:
                        sa_networks.append(net)
            
            da_networks = []
            has_any_da = 'any' in da_list
            for da_tok in da_list:
                if da_tok != "any":
                    net = _ipnet(da_tok)
                    if net:
                        da_networks.append(net)
            
            # Pre-parse services for faster comparisons (RAM-based optimization)
            sv_parsed = []
            for sv_tok in sv_list:
                sv_parsed.append(_parse_service(sv_tok))
            
            parsed_rules.append({
                'row': row,
                'sa_list': sa_list,
                'da_list': da_list,
                'sv_list': sv_list,
                'act': act,
                'ord': ord_val,
                # Pre-computed lookups stored in RAM
                'sa_networks': sa_networks,
                'da_networks': da_networks,
                'sv_parsed': sv_parsed,
                'has_any_sa': has_any_sa,
                'has_any_da': has_any_da
            })
        
        total_pairs = sum(range(len(parsed_rules))) if len(parsed_rules) > 0 else 0
        logging.info(f"        Comparing {total_pairs} rule pairs (this may take a moment)...")
        
        # Counters for progress tracking
        shadow_found = 0
        partial_shadow_found = 0
        redundant_found = 0
        generalization_found = 0
        correlation_found = 0
        
        # ⚡ OPTIMIZATION 2: Batch DataFrame updates (collect changes, apply at end)
        shadow_updates = {}
        partial_shadow_updates = {}
        shadow_reasons = {}
        redundant_updates = {}
        redundant_reasons = {}
        generalization_updates = {}
        generalization_reasons = {}
        correlation_updates = {}
        correlation_reasons = {}
        
        # ⚡ OPTIMIZATION 5: Early skipping for large datasets
        # Track which rules are already fully processed (marked as issues)
        skip_rules = set()  # Rules that are already marked and can skip remaining comparisons
        
        # ⚡ OPTIMIZATION 7: Parallel processing for pairs within single firewall (for large datasets)
        use_parallel_pairs = total_pairs > 100000  # Enable parallel pair processing for >100K pairs
        # CPU throttling: Use max 50% of cores or configured max
        available_cores = max(MIN_WORKERS, int(cpu_count() * MAX_CPU_USAGE_RATIO))
        max_workers_pairs = min(MAX_WORKERS_PAIRS, available_cores)  # Limit workers to reduce CPU usage
        if use_parallel_pairs:
            logging.info(f"        ⚙️ CPU throttling: Using {max_workers_pairs} workers for pair processing (out of {cpu_count()} available cores)")
        
        if use_parallel_pairs:
            logging.info(f"        ⚡ Using parallel processing for {total_pairs} pairs ({max_workers_pairs} workers)...")
            
            # Generate all pairs upfront
            all_pairs = []
            for i in range(len(parsed_rules)):
                B = parsed_rules[i]
                if i in skip_rules:
                    continue
                for j in range(i):
                    A = parsed_rules[j]
                    if A['ord'] < B['ord']:  # Only add valid pairs
                        all_pairs.append((i, j))
            
            # Split pairs into chunks for parallel processing
            # Smaller chunks for better load balancing (reduced multiplier from 4 to 2)
            chunk_size = max(5000, total_pairs // (max_workers_pairs * 2))  # More chunks for better distribution
            pair_chunks = [all_pairs[i:i + chunk_size] for i in range(0, len(all_pairs), chunk_size)]
            total_chunks = len(pair_chunks)
            
            logging.info(f"        Split into {total_chunks} chunks (~{chunk_size} pairs each)")
            
            # Process chunks in parallel
            shadow_updates = {}
            partial_shadow_updates = {}
            shadow_reasons = {}
            redundant_updates = {}
            redundant_reasons = {}
            generalization_updates = {}
            generalization_reasons = {}
            correlation_updates = {}
            correlation_reasons = {}
            
            shadow_found = 0
            partial_shadow_found = 0
            redundant_found = 0
            generalization_found = 0
            correlation_found = 0
            
            pairs_processed = 0
            completed_chunks = 0
            
            # ⚡ Use ProcessPoolExecutor for true parallelism (bypasses Python GIL)
            # Note: parsed_rules and idxs need to be passed to workers (they're already in the closure)
            with ProcessPoolExecutor(max_workers=max_workers_pairs) as executor:
                # Submit all chunks
                future_to_chunk = {
                    executor.submit(_process_pair_chunk, (chunk, parsed_rules, idxs, idx, total_chunks, total_pairs)): idx
                    for idx, chunk in enumerate(pair_chunks)
                }
                
                # Process results as they complete
                for future in as_completed(future_to_chunk):
                    chunk_index = future_to_chunk[future]
                    try:
                        result = future.result()
                        
                        # Merge results
                        shadow_updates.update(result['shadow_updates'])
                        partial_shadow_updates.update(result['partial_shadow_updates'])
                        shadow_reasons.update(result['shadow_reasons'])
                        redundant_updates.update(result['redundant_updates'])
                        redundant_reasons.update(result['redundant_reasons'])
                        generalization_updates.update(result['generalization_updates'])
                        generalization_reasons.update(result['generalization_reasons'])
                        correlation_updates.update(result['correlation_updates'])
                        correlation_reasons.update(result['correlation_reasons'])
                        
                        shadow_found += result['shadow_found']
                        partial_shadow_found += result['partial_shadow_found']
                        redundant_found += result['redundant_found']
                        generalization_found += result['generalization_found']
                        correlation_found += result['correlation_found']
                        
                        pairs_processed += result['pairs_processed']
                        completed_chunks += 1
                        
                        # Update progress
                        if completed_chunks % max(1, total_chunks // 20) == 0 or completed_chunks == total_chunks:
                            pair_progress = int((pairs_processed / total_pairs) * 80) if total_pairs > 0 else 0
                            overall_progress = int(firewall_base_progress + (pair_progress / 100) * firewall_progress_range)
                            
                            logging.info(f"        [{group_num}/{total_groups}] Progress: {completed_chunks}/{total_chunks} chunks ({pairs_processed}/{total_pairs} pairs, {pair_progress}%) - '{firewall_name}'")
                            
                            if progress_callback and total_pairs > 0:
                                progress_callback("pair_processing", 
                                                 f"[{group_num}/{total_groups}] Analyzing '{firewall_name}': {pairs_processed}/{total_pairs} pairs ({pair_progress}%)...",
                                                 overall_progress,
                                                 firewall_name=firewall_name, 
                                                 firewall_percent=pair_progress,
                                                 firewall_index=group_num, 
                                                 total_firewalls=total_groups,
                                                 pairs_processed=pairs_processed, 
                                                 total_pairs=total_pairs)
                    except Exception as e:
                        logging.error(f"        ❌ Error processing chunk {chunk_index}: {e}")
            
            logging.info(f"        ✓ Forward pass (top-to-bottom) complete: {pairs_processed} pairs processed")
            
            # ⚡ BIDIRECTIONAL ANALYSIS: Add reverse pass (bottom-to-top) for complete analysis
            logging.info(f"        ⚡ Starting reverse pass (bottom-to-top) for bidirectional analysis ({max_workers_pairs} workers)...")
            
            # Generate reverse pairs (bottom-to-top)
            # For reverse pass, we want to check if later rules affect earlier rules
            reverse_all_pairs = []
            for i in range(len(parsed_rules) - 1, -1, -1):  # Start from end, go backwards
                B = parsed_rules[i]  # Later rule (higher index in original list)
                if i in skip_rules:
                    continue
                for j in range(i + 1, len(parsed_rules)):  # Compare to rules that come after in original list
                    A = parsed_rules[j]  # Earlier rule (lower index in original list)
                    if A['ord'] < B['ord']:  # Only add if A comes before B in rule order
                        # Store pairs normally (i, j) where i > j, then pass is_reverse=True flag
                        reverse_all_pairs.append((i, j))  # Store as (later_idx, earlier_idx)
            
            reverse_total_pairs = len(reverse_all_pairs)
            logging.info(f"        Generated {reverse_total_pairs} reverse pairs for bottom-to-top analysis")
            
            if reverse_total_pairs > 0:
                # Split reverse pairs into chunks
                reverse_chunk_size = max(5000, reverse_total_pairs // (max_workers_pairs * 2))
                reverse_pair_chunks = [reverse_all_pairs[i:i + reverse_chunk_size] for i in range(0, len(reverse_all_pairs), reverse_chunk_size)]
                reverse_total_chunks = len(reverse_pair_chunks)
                
                logging.info(f"        Split into {reverse_total_chunks} reverse chunks (~{reverse_chunk_size} pairs each)")
                
                reverse_pairs_processed = 0
                reverse_completed_chunks = 0
                
                with ProcessPoolExecutor(max_workers=max_workers_pairs) as executor:
                    # Submit all reverse chunks with is_reverse=True flag
                    reverse_future_to_chunk = {
                        executor.submit(_process_pair_chunk, (chunk, parsed_rules, idxs, idx, reverse_total_chunks, reverse_total_pairs, True)): idx
                        for idx, chunk in enumerate(reverse_pair_chunks)
                    }
                    
                    # Process results as they complete
                    for future in as_completed(reverse_future_to_chunk):
                        chunk_index = reverse_future_to_chunk[future]
                        try:
                            result = future.result()
                            
                            # Merge results into existing dictionaries
                            shadow_updates.update(result['shadow_updates'])
                            partial_shadow_updates.update(result['partial_shadow_updates'])
                            shadow_reasons.update(result['shadow_reasons'])
                            redundant_updates.update(result['redundant_updates'])
                            redundant_reasons.update(result['redundant_reasons'])
                            generalization_updates.update(result['generalization_updates'])
                            generalization_reasons.update(result['generalization_reasons'])
                            correlation_updates.update(result['correlation_updates'])
                            correlation_reasons.update(result['correlation_reasons'])
                            
                            shadow_found += result['shadow_found']
                            partial_shadow_found += result['partial_shadow_found']
                            redundant_found += result['redundant_found']
                            generalization_found += result['generalization_found']
                            correlation_found += result['correlation_found']
                            
                            reverse_pairs_processed += result['pairs_processed']
                            reverse_completed_chunks += 1
                            
                            # Update progress
                            if reverse_completed_chunks % max(1, reverse_total_chunks // 20) == 0 or reverse_completed_chunks == reverse_total_chunks:
                                reverse_pair_progress = int((reverse_pairs_processed / reverse_total_pairs) * 80) if reverse_total_pairs > 0 else 0
                                overall_progress = int(firewall_base_progress + (reverse_pair_progress / 100) * firewall_progress_range)
                                
                                logging.info(f"        [{group_num}/{total_groups}] Reverse pass: {reverse_completed_chunks}/{reverse_total_chunks} chunks ({reverse_pairs_processed}/{reverse_total_pairs} pairs, {reverse_pair_progress}%) - '{firewall_name}'")
                                
                                if progress_callback and reverse_total_pairs > 0:
                                    progress_callback("pair_processing_reverse", 
                                                     f"[{group_num}/{total_groups}] Reverse analysis '{firewall_name}': {reverse_pairs_processed}/{reverse_total_pairs} pairs ({reverse_pair_progress}%)...",
                                                     overall_progress,
                                                     firewall_name=firewall_name, 
                                                     firewall_percent=reverse_pair_progress,
                                                     firewall_index=group_num, 
                                                     total_firewalls=total_groups,
                                                     pairs_processed=reverse_pairs_processed, 
                                                     total_pairs=reverse_total_pairs)
                        except Exception as e:
                            logging.error(f"        ❌ Error processing reverse chunk {chunk_index}: {e}")
                
                logging.info(f"        ✓ Reverse pass (bottom-to-top) complete: {reverse_pairs_processed} pairs processed")
                pairs_processed += reverse_pairs_processed
            else:
                logging.info(f"        ℹ No reverse pairs to process")
        else:
            # Sequential processing (original code)
            # Pairwise analyses
            pairs_processed = 0
            
            # Counters for progress tracking
            shadow_found = 0
            partial_shadow_found = 0
            redundant_found = 0
            generalization_found = 0
            correlation_found = 0
            
            # ⚡ OPTIMIZATION 2: Batch DataFrame updates (collect changes, apply at end)
            shadow_updates = {}
            partial_shadow_updates = {}
            shadow_reasons = {}
            redundant_updates = {}
            redundant_reasons = {}
            generalization_updates = {}
            generalization_reasons = {}
            correlation_updates = {}
            correlation_reasons = {}
            
        if not use_parallel_pairs:
            # Sequential processing continues here
            # Calculate update interval: update every 1% of progress or every 50 pairs, whichever is more frequent
            # For better UX, update more frequently for large datasets
            if total_pairs > 0:
                # Update at least every 1% of pairs (but not more than every 10 pairs for very large datasets)
                percent_based_interval = max(1, total_pairs // 100)  # 1% of total
                # Also update every N pairs for large datasets
                fixed_interval = max(10, min(100, total_pairs // 50))  # Adaptive interval
                update_interval = min(percent_based_interval, fixed_interval)
            else:
                update_interval = 1
            
            if progress_callback and total_pairs > 0:
                progress_callback("pair_processing_start", 
                               f"[{group_num}/{total_groups}] Starting pairwise comparison for '{firewall_name}': {total_pairs} pairs to analyze...",
                               int(firewall_base_progress),
                               firewall_name=firewall_name, 
                               firewall_percent=0,
                               firewall_index=group_num, 
                               total_firewalls=total_groups,
                               pairs_processed=0, 
                               total_pairs=total_pairs)
            
            # Track last reported progress percentage to avoid too-frequent updates
            last_reported_pair_percent = -1
            
            for i in range(len(parsed_rules)):
                B = parsed_rules[i]
                
                # ⚡ OPTIMIZATION 6: Early skip - if rule B is already marked, skip all remaining comparisons
                # (For large datasets, this can save significant time)
                if i in skip_rules and total_pairs > 50000:
                    continue  # Skip this rule entirely if already processed
                
                for j in range(i):
                    A = parsed_rules[j]
                    pairs_processed += 1
                    
                    # ⚡ OPTIMIZATION 3: Early termination - skip if rule order invalid
                    if A['ord'] >= B['ord']:
                        continue
                    
                    # Update progress more frequently with clearer messages
                    if pairs_processed % update_interval == 0 or pairs_processed == total_pairs:
                        pair_progress = int((pairs_processed / total_pairs) * 80) if total_pairs > 0 else 0
                        overall_progress = int(firewall_base_progress + (pair_progress / 100) * firewall_progress_range)
                        
                        # Only log and update if progress percentage actually changed (to reduce spam)
                        if pair_progress != last_reported_pair_percent:
                            logging.info(f"        [{group_num}/{total_groups}] Progress: {pairs_processed}/{total_pairs} pairs ({pair_progress}%) - '{firewall_name}'")
                            
                            if progress_callback and total_pairs > 0:
                                progress_callback("pair_processing", 
                                                 f"[{group_num}/{total_groups}] Analyzing '{firewall_name}': {pairs_processed}/{total_pairs} pairs ({pair_progress}%)...",
                                                 overall_progress,
                                                 firewall_name=firewall_name, 
                                                 firewall_percent=pair_progress,
                                                 firewall_index=group_num, 
                                                 total_firewalls=total_groups,
                                                 pairs_processed=pairs_processed, 
                                                 total_pairs=total_pairs)
                            last_reported_pair_percent = pair_progress
                    
                    # Shadow / Partial shadow (only if actions differ)
                    if A['act'] != B['act']:
                        # ⚡ Use optimized classify_pair_parsed instead of classify_pair
                        label, reason = classify_pair_parsed(A, B)
                        if label == "Shadow":
                            shadow_updates[idxs[i]] = True
                            shadow_reasons[idxs[i]] = reason
                            shadow_found += 1
                            if total_pairs > 50000:
                                skip_rules.add(i)  # Mark rule as fully processed
                        elif label == "Partial Shadow":
                            # Only mark as Partial Shadow if not already marked as Shadow (Shadow takes precedence)
                            if idxs[i] not in shadow_updates:
                                partial_shadow_updates[idxs[i]] = True
                                shadow_reasons[idxs[i]] = reason
                                partial_shadow_found += 1
                    
                    # ⚡ OPTIMIZATION 4: Separate logic paths for same/different actions
                    if A['act'] == B['act']:
                        # Redundancy check (same action, B fully covered by A)
                        sa_full, _, _ = list_covered_by(A['sa_list'], B['sa_list'], ip_covers_any, ip_overlap_any)
                        if sa_full:  # Early exit if source doesn't cover
                            da_full, _, _ = list_covered_by(A['da_list'], B['da_list'], ip_covers_any, ip_overlap_any)
                            if da_full:  # Early exit if dest doesn't cover
                                sv_full, _, _ = list_covered_by(A['sv_list'], B['sv_list'], service_covers_any, service_overlap_any)
                                if sv_full:
                                    redundant_updates[idxs[i]] = True
                                    redundant_reasons[idxs[i]] = f"Same action as earlier rule {A['row'].get('Rule_Name')} and fully covered."
                                    redundant_found += 1
                                    if total_pairs > 50000:
                                        skip_rules.add(i)  # Mark rule as fully processed
                    else:
                        # Actions differ - check generalization
                        sa_ba, _, _ = list_covered_by(B['sa_list'], A['sa_list'], ip_covers_any, ip_overlap_any)
                        if sa_ba:  # Early exit check
                            da_ba, _, _ = list_covered_by(B['da_list'], A['da_list'], ip_covers_any, ip_overlap_any)
                            if da_ba:  # Early exit check
                                sv_ba, _, _ = list_covered_by(B['sv_list'], A['sv_list'], service_covers_any, service_overlap_any)
                                if sv_ba:
                                    # Check if B is broader than A
                                    broader = False
                                    if not ip_covers_any(A['sa_list'], B['sa_list'][0]) if B['sa_list'] else False:
                                        broader = True
                                    elif not ip_covers_any(A['da_list'], B['da_list'][0]) if B['da_list'] else False:
                                        broader = True
                                    elif not service_covers_any(A['sv_list'], B['sv_list'][0]) if B['sv_list'] else False:
                                        broader = True
                                    if broader:
                                        ruleA_name = A['row'].get('Rule_Name', 'Unknown')
                                        ruleB_name = B['row'].get('Rule_Name', 'Unknown')
                                        generalization_updates[idxs[i]] = True
                                        generalization_reasons[idxs[i]] = f"{ruleB_name} / Generalizes earlier rule {ruleA_name}"
                                        generalization_found += 1
                        
                        # Correlation check (partial overlap, not full coverage)
                        # Only check if not already shadow/partial shadow
                        if idxs[i] not in shadow_updates and idxs[i] not in partial_shadow_updates:
                            sa_over = ip_overlap_any(A['sa_list'], B['sa_list'][0]) if B['sa_list'] else False
                            if sa_over:  # Early exit check
                                da_over = ip_overlap_any(A['da_list'], B['da_list'][0]) if B['da_list'] else False
                                if da_over:  # Early exit check
                                    sv_over = service_overlap_any(A['sv_list'], B['sv_list'][0]) if B['sv_list'] else False
                                    if sv_over:
                                        sa_full = ip_covers_any(A['sa_list'], B['sa_list'][0]) if B['sa_list'] else False
                                        da_full = ip_covers_any(A['da_list'], B['da_list'][0]) if B['da_list'] else False
                                        sv_full = service_covers_any(A['sv_list'], B['sv_list'][0]) if B['sv_list'] else False
                                        if not (sa_full and da_full and sv_full):
                                            ruleA_name = A['row'].get('Rule_Name', 'Unknown')
                                            ruleB_name = B['row'].get('Rule_Name', 'Unknown')
                                            correlation_updates[idxs[i]] = True
                                            correlation_reasons[idxs[i]] = f"{ruleA_name} & {ruleB_name} / Partially overlap with different actions"
                                            correlation_found += 1
            
            # ⚡ BIDIRECTIONAL ANALYSIS: Add reverse pass (bottom-to-top) for sequential processing
            logging.info(f"        Starting reverse pass (bottom-to-top) for bidirectional analysis...")
            reverse_pairs_processed = 0
            reverse_total_pairs = 0
            
            # Generate reverse pairs count for progress
            for i in range(len(parsed_rules) - 1, -1, -1):
                B = parsed_rules[i]
                if i in skip_rules and total_pairs > 50000:
                    continue
                for j in range(i + 1, len(parsed_rules)):
                    A = parsed_rules[j]
                    if A['ord'] < B['ord']:
                        reverse_total_pairs += 1
            
            # Note: For reverse pass, we iterate backwards but still compare in the same logical direction
            # The key is checking if later rules (higher index) affect earlier rules (lower index)
            
            if reverse_total_pairs > 0:
                logging.info(f"        Processing {reverse_total_pairs} reverse pairs (bottom-to-top)...")
                reverse_update_interval = max(1, reverse_total_pairs // 100) if reverse_total_pairs > 0 else 1
                reverse_last_reported_percent = -1
                
                # For reverse pass: check if later rules affect earlier rules
                # Iterate backwards to process later rules first
                for i in range(len(parsed_rules) - 1, -1, -1):
                    B = parsed_rules[i]  # Later rule (higher index, comes later in list)
                    
                    if i in skip_rules and total_pairs > 50000:
                        continue
                    
                    for j in range(i + 1, len(parsed_rules)):
                        A = parsed_rules[j]  # Earlier rule (lower index, comes earlier in list)
                        reverse_pairs_processed += 1
                        
                        # Early termination - skip if rule order invalid
                        if A['ord'] >= B['ord']:
                            continue
                        
                        # For reverse pass: we want to check if B (later rule) affects A (earlier rule)
                        # But our functions expect (A, B) where A is earlier. So we need to swap logic.
                        # Instead of swapping everywhere, we'll use the functions correctly by treating
                        # this as: does later rule B affect earlier rule A?
                        
                        # Update progress
                        if reverse_pairs_processed % reverse_update_interval == 0 or reverse_pairs_processed == reverse_total_pairs:
                            reverse_pair_progress = int((reverse_pairs_processed / reverse_total_pairs) * 80) if reverse_total_pairs > 0 else 0
                            overall_progress = int(firewall_base_progress + (reverse_pair_progress / 100) * firewall_progress_range)
                            
                            if reverse_pair_progress != reverse_last_reported_percent:
                                logging.info(f"        [{group_num}/{total_groups}] Reverse pass: {reverse_pairs_processed}/{reverse_total_pairs} pairs ({reverse_pair_progress}%) - '{firewall_name}'")
                                
                                if progress_callback and reverse_total_pairs > 0:
                                    progress_callback("pair_processing_reverse", 
                                                     f"[{group_num}/{total_groups}] Reverse analysis '{firewall_name}': {reverse_pairs_processed}/{reverse_total_pairs} pairs ({reverse_pair_progress}%)...",
                                                     overall_progress,
                                                     firewall_name=firewall_name, 
                                                     firewall_percent=reverse_pair_progress,
                                                     firewall_index=group_num, 
                                                     total_firewalls=total_groups,
                                                     pairs_processed=reverse_pairs_processed, 
                                                     total_pairs=reverse_total_pairs)
                                reverse_last_reported_percent = reverse_pair_progress
                        
                        # For reverse pass: Check if later rule B affects earlier rule A
                        # Note: A is earlier (j), B is later (i) - we're checking reverse direction
                        # So we need to check if B covers/shadow/redundant with A
                        # When B affects A, we update A's index (idxs[j])
                        
                        # Shadow / Partial shadow (only if actions differ)
                        if A['act'] != B['act']:
                            # Check if later rule B shadows earlier rule A
                            label, reason = classify_pair_parsed(B, A)  # Swap B and A to check if B affects A
                            if label == "Shadow":
                                shadow_updates[idxs[j]] = True  # Mark earlier rule A as shadowed
                                shadow_reasons[idxs[j]] = reason
                                shadow_found += 1
                                if total_pairs > 50000:
                                    skip_rules.add(j)  # Mark earlier rule as processed
                            elif label == "Partial Shadow":
                                # Only mark as Partial Shadow if not already marked as Shadow (Shadow takes precedence)
                                if idxs[j] not in shadow_updates:
                                    partial_shadow_updates[idxs[j]] = True  # Mark earlier rule A as partially shadowed
                                    shadow_reasons[idxs[j]] = reason
                                    partial_shadow_found += 1
                        
                        # Separate logic paths for same/different actions
                        if A['act'] == B['act']:
                            # Redundancy check: Is earlier rule A redundant to later rule B?
                            # Check if B fully covers A (reverse of forward check)
                            sa_full, _, _ = list_covered_by(B['sa_list'], A['sa_list'], ip_covers_any, ip_overlap_any)
                            if sa_full:
                                da_full, _, _ = list_covered_by(B['da_list'], A['da_list'], ip_covers_any, ip_overlap_any)
                                if da_full:
                                    sv_full, _, _ = list_covered_by(B['sv_list'], A['sv_list'], service_covers_any, service_overlap_any)
                                    if sv_full:
                                        ruleA_name = A['row'].get('Rule_Name', 'Unknown')
                                        ruleB_name = B['row'].get('Rule_Name', 'Unknown')
                                        redundant_updates[idxs[j]] = True  # Mark earlier rule A as redundant
                                        redundant_reasons[idxs[j]] = f"{ruleA_name} / Same action and fully covered by later rule {ruleB_name}"
                                        redundant_found += 1
                                        if total_pairs > 50000:
                                            skip_rules.add(j)
                        else:
                            # Actions differ - check generalization
                            # Check if earlier rule A generalizes later rule B (reverse)
                            sa_ba, _, _ = list_covered_by(A['sa_list'], B['sa_list'], ip_covers_any, ip_overlap_any)
                            if sa_ba:
                                da_ba, _, _ = list_covered_by(A['da_list'], B['da_list'], ip_covers_any, ip_overlap_any)
                                if da_ba:
                                    sv_ba, _, _ = list_covered_by(A['sv_list'], B['sv_list'], service_covers_any, service_overlap_any)
                                    if sv_ba:
                                        broader = False
                                        if not ip_covers_any(B['sa_list'], A['sa_list'][0]) if A['sa_list'] else False:
                                            broader = True
                                        elif not ip_covers_any(B['da_list'], A['da_list'][0]) if A['da_list'] else False:
                                            broader = True
                                        elif not service_covers_any(B['sv_list'], A['sv_list'][0]) if A['sv_list'] else False:
                                            broader = True
                                        if broader:
                                            ruleA_name = A['row'].get('Rule_Name', 'Unknown')
                                            ruleB_name = B['row'].get('Rule_Name', 'Unknown')
                                            generalization_updates[idxs[j]] = True  # Mark earlier rule A as generalizing later rule B
                                            generalization_reasons[idxs[j]] = f"{ruleA_name} / Generalizes later rule {ruleB_name}"
                                            generalization_found += 1
                            
                            # Correlation check (bidirectional - same logic both directions)
                            if idxs[j] not in shadow_updates and idxs[j] not in partial_shadow_updates:
                                sa_over = ip_overlap_any(A['sa_list'], B['sa_list'][0]) if B['sa_list'] else False
                                if sa_over:
                                    da_over = ip_overlap_any(A['da_list'], B['da_list'][0]) if B['da_list'] else False
                                    if da_over:
                                        sv_over = service_overlap_any(A['sv_list'], B['sv_list'][0]) if B['sv_list'] else False
                                        if sv_over:
                                            sa_full = ip_covers_any(A['sa_list'], B['sa_list'][0]) if B['sa_list'] else False
                                            da_full = ip_covers_any(A['da_list'], B['da_list'][0]) if B['da_list'] else False
                                            sv_full = service_covers_any(A['sv_list'], B['sv_list'][0]) if B['sv_list'] else False
                                            if not (sa_full and da_full and sv_full):
                                                ruleA_name = A['row'].get('Rule_Name', 'Unknown')
                                                ruleB_name = B['row'].get('Rule_Name', 'Unknown')
                                                correlation_updates[idxs[j]] = True  # Mark earlier rule A as correlated
                                                correlation_reasons[idxs[j]] = f"{ruleA_name} & {ruleB_name} / Partially overlap with different actions"
                                                correlation_found += 1
                
                pairs_processed += reverse_pairs_processed
                logging.info(f"        ✓ Reverse pass (bottom-to-top) complete: {reverse_pairs_processed} pairs processed")
            else:
                logging.info(f"        ℹ No reverse pairs to process")
        
        # ⚡ OPTIMIZATION 2 (continued): Apply all DataFrame updates in batch (for both parallel and sequential)
        logging.info(f"        Applying {len(shadow_updates) + len(partial_shadow_updates) + len(redundant_updates) + len(generalization_updates) + len(correlation_updates)} detected issues to DataFrame...")
        
        for idx, val in shadow_updates.items():
            df.loc[idx, "Shadow_Rule"] = val
            df.loc[idx, "Shadow_Reason"] = shadow_reasons[idx]
            # Clear Partial Shadow if Shadow is set (Shadow takes precedence)
            if val:
                df.loc[idx, "Partial_Shadow_Rule"] = False
        
        for idx, val in partial_shadow_updates.items():
            # Only set Partial Shadow if not already marked as Shadow (Shadow takes precedence)
            if idx not in shadow_updates:
                df.loc[idx, "Partial_Shadow_Rule"] = val
                df.loc[idx, "Shadow_Reason"] = shadow_reasons[idx]
        
        for idx, val in redundant_updates.items():
            df.loc[idx, "Redundant_Rule"] = val
            df.loc[idx, "Redundancy_Reason"] = redundant_reasons[idx]
        
        for idx, val in generalization_updates.items():
            df.loc[idx, "Generalization_Risk"] = val
            df.loc[idx, "Generalization_Reason"] = generalization_reasons[idx]
        
        for idx, val in correlation_updates.items():
            df.loc[idx, "Correlation_Risk"] = val
            df.loc[idx, "Correlation_Reason"] = correlation_reasons[idx]
        
        logging.info(f"        [{group_num}/{total_groups}] Pairwise analysis complete for '{firewall_name}':")
        logging.info(f"           Shadow: {shadow_found}, Partial Shadow: {partial_shadow_found}, "
                    f"Redundant: {redundant_found}, Generalization: {generalization_found}, "
                    f"Correlation: {correlation_found}")
        
        if progress_callback:
            # Pair processing done, now consolidation (20% of firewall work)
            pair_complete_progress = int(firewall_base_progress + (80 / 100) * firewall_progress_range)
            progress_callback("pair_processing_complete",
                            f"✓ [{group_num}/{total_groups}] Pairwise analysis complete for '{firewall_name}': {shadow_found} shadows, {partial_shadow_found} partial shadows, {redundant_found} redundancies, {generalization_found} generalizations, {correlation_found} correlations",
                            pair_complete_progress,
                            firewall_name=firewall_name, 
                            firewall_percent=80,
                            firewall_index=group_num, 
                            total_firewalls=total_groups,
                            pairs_processed=total_pairs, 
                            total_pairs=total_pairs)
        
        # Consolidation candidates (same action, differ by only one attribute)
        logging.info(f"        [{group_num}/{total_groups}] Identifying consolidation candidates for '{firewall_name}'...")
        if progress_callback:
            consolidation_start_progress = int(firewall_base_progress + (85 / 100) * firewall_progress_range)
            progress_callback("consolidation_start", 
                            f"🔗 [{group_num}/{total_groups}] Identifying consolidation candidates for '{firewall_name}' (rules that can be merged)...",
                            consolidation_start_progress,
                            firewall_name=firewall_name, 
                            firewall_percent=85,
                            firewall_index=group_num, 
                            total_firewalls=total_groups)
        
        # Build signatures for two fixed fields
        sub_rows = sub.to_dict("records")
        sub_idx_to_name = {}  # Map DataFrame index to rule name for consolidation
        for idx, row in zip(sub.index.tolist(), sub_rows):
            sub_idx_to_name[idx] = row.get('Rule_Name', 'Unknown')
        
        buckets: Dict[Tuple[str, str, str], List[int]] = {}
        total_rules_for_consolidation = len(sub_rows)
        rules_processed_consolidation = 0
        
        for idx, row in zip(sub.index.tolist(), sub_rows):
            rules_processed_consolidation += 1
            act = normalize_action(row.get("Action"))
            sa = tuple(sorted(split_cell_to_list(row.get("Source Address"))))
            da = tuple(sorted(split_cell_to_list(row.get("Destination Address"))))
            sv = tuple(sorted(split_cell_to_list(row.get("Service"))))
            # three bucket keys (fix two, vary one)
            for key in [("SA", act, da, sv), ("DA", act, sa, sv), ("SV", act, sa, da)]:
                buckets.setdefault(tuple(map(str, key)), []).append(idx)
            
            # Update progress during consolidation (every 10% of rules)
            if progress_callback and total_rules_for_consolidation > 0:
                if rules_processed_consolidation % max(1, total_rules_for_consolidation // 10) == 0:
                    consolidation_progress = int(85 + (rules_processed_consolidation / total_rules_for_consolidation) * 10)
                    overall_consolidation_progress = int(firewall_base_progress + (consolidation_progress / 100) * firewall_progress_range)
                    progress_callback("consolidation_processing",
                                    f"🔗 [{group_num}/{total_groups}] Processing consolidation for '{firewall_name}': {rules_processed_consolidation}/{total_rules_for_consolidation} rules...",
                                    overall_consolidation_progress,
                                    firewall_name=firewall_name,
                                    firewall_percent=consolidation_progress,
                                    firewall_index=group_num,
                                    total_firewalls=total_groups)
        
        consolidation_count = 0
        for key, idcs in buckets.items():
            if len(idcs) >= 2:
                consolidation_count += len(idcs)
                # Get all rule names in this consolidation bucket
                rule_names = [sub_idx_to_name.get(idx, 'Unknown') for idx in idcs]
                rule_names_str = ", ".join(rule_names) if rule_names else "Unknown"
                
                # Determine which field differs based on the key
                key_parts = list(key)
                differing_field = key_parts[0]  # First element indicates which field varies
                field_name_map = {
                    "SA": "Source Address",
                    "DA": "Destination Address", 
                    "SV": "Service"
                }
                differing_field_name = field_name_map.get(differing_field, "one field")
                
                # Build list of identical fields
                identical_fields = [f for f in ['Source Address', 'Destination Address', 'Service'] if f != differing_field_name]
                identical_fields_str = ' and '.join(identical_fields) if len(identical_fields) == 2 else identical_fields[0]
                
                consolidation_reason = f"{rule_names_str} / These rules have the same Action and identical {identical_fields_str}, but differ in {differing_field_name}. They can be consolidated into a single rule."
                
                # Consolidation_Key should contain rule names for easy identification
                consolidation_key = rule_names_str
                
                for idx in idcs:
                    df.loc[idx, "Consolidation_Candidate"] = True
                    df.loc[idx, "Consolidation_Key"] = consolidation_key  # Use rule names instead of technical key
                    df.loc[idx, "Consolidation_Reason"] = consolidation_reason
        logging.info(f"        [{group_num}/{total_groups}] Found {consolidation_count} consolidation candidate(s) for '{firewall_name}'")
        
        if progress_callback:
            # Consolidation complete
            consolidation_complete_progress = int(firewall_base_progress + (95 / 100) * firewall_progress_range)
            progress_callback("consolidation_complete",
                            f"✓ [{group_num}/{total_groups}] Consolidation analysis complete for '{firewall_name}'. Found {consolidation_count} candidate(s) that can be merged.",
                            consolidation_complete_progress,
                            firewall_name=firewall_name, 
                            firewall_percent=95,
                            firewall_index=group_num, 
                            total_firewalls=total_groups)
        
        if progress_callback:
            # Firewall complete
            firewall_complete_progress = int(firewall_base_progress + firewall_progress_range)
            progress_callback("firewall_complete",
                            f"✅ [{group_num}/{total_groups}] Firewall '{firewall_name}' analysis complete. Summary: {shadow_found} shadows, {partial_shadow_found} partial shadows, {redundant_found} redundancies, {generalization_found} generalizations, {correlation_found} correlations, {consolidation_count} consolidation candidates.",
                            firewall_complete_progress,
                            firewall_name=firewall_name, 
                            firewall_percent=100,
                            firewall_index=group_num, 
                            total_firewalls=total_groups)
    
    logging.info("  ✅ Policy analysis complete for all groups")
    if progress_callback:
        progress_callback("analysis_complete", 
                         f"✅ Policy analysis complete for all {total_groups} firewall group(s)", 
                         95)
    
    # Clear caches to free memory
    _ipnet.cache_clear()
    _parse_service.cache_clear()
    normalize_action.cache_clear()
    
    return df


def suggest_rule_reordering(df: pd.DataFrame) -> Tuple[List[Dict[str, Any]], pd.DataFrame]:
    """
    Suggest a safe rule reordering plan based on analysis flags, grouped by firewall.
    Also adds a 'Suggested_Order' column to the DataFrame.
    
    Principles:
    1. Preserve behavior: do not change allow/deny outcomes
    2. Place specific rules above broader ones
    3. Move general or catch-all rules to the end
    4. Group redundant rules together; suggest merges
    5. Include a short reason for each move
    6. Process each firewall separately (rules are reordered within each firewall)
    
    Returns:
        Tuple of (suggestions_list, updated_dataframe)
        suggestions_list contains dicts with 'firewall' field indicating which firewall the suggestion applies to
    """
    all_suggestions = []
    
    # Ensure Rule_Order column exists
    if "Rule_Order" not in df.columns:
        df["Rule_Order"] = range(1, len(df) + 1)
    
    # Create a working copy
    df_work = df.copy()
    df_work["_original_order"] = df_work["Rule_Order"]
    
    # Initialize Suggested_Order column with current order
    df_work["Suggested_Order"] = df_work["Rule_Order"].copy()
    
    # Get rule name column
    rule_name_col = None
    for col in ["Rule_Name", "Name", "Rule Name", "Rule"]:
        if col in df_work.columns:
            rule_name_col = col
            break
    
    if not rule_name_col:
        return all_suggestions, df_work  # Can't proceed without rule names
    
    # Get firewall/source file column
    firewall_col = None
    for col in ["Source_File", "Source File", "Firewall", "Device", "Policy_File"]:
        if col in df_work.columns:
            firewall_col = col
            break
    
    # Group by firewall if available, otherwise process all rules together
    if firewall_col:
        firewall_groups = df_work.groupby(firewall_col)
        logging.info(f"  🔀 Processing {len(firewall_groups)} firewall(s) for reordering suggestions...")
    else:
        # No firewall column, treat as single group
        firewall_groups = [("All Rules", df_work)]
        logging.info(f"  🔀 Processing all rules as single group (no firewall column found)...")
    
    # Process each firewall separately
    for firewall_name, firewall_df in firewall_groups:
        firewall_name_str = str(firewall_name) if firewall_name else "All Rules"
        logging.info(f"     Processing firewall: '{firewall_name_str}' ({len(firewall_df)} rules)")
        
        # Create a working copy for this firewall
        df_fw = firewall_df.copy()
        
        # Reset suggested order to be sequential within this firewall (starting from 1)
        df_fw["Suggested_Order"] = range(1, len(df_fw) + 1)
        df_fw["_original_order"] = df_fw["Rule_Order"]
        
        # Create a mapping: rule_name -> current suggested order (within this firewall)
        rule_to_suggested_order = {}
        for idx, row in df_fw.iterrows():
            rule_name = str(row.get(rule_name_col, f"Rule_{idx}"))
            rule_to_suggested_order[rule_name] = int(row["Suggested_Order"])
        
        # Track which rules have been moved (within this firewall)
        moved_rules = set()
        firewall_suggestions = []
        
        # 1. Move shadowed rules up
        shadow_col = "Shadow_Rule"
        if shadow_col in df_fw.columns:
            shadowed_rules = df_fw[df_fw[shadow_col] == True].copy()
            for idx, row in shadowed_rules.iterrows():
                rule_name = str(row.get(rule_name_col, f"Rule_{idx}"))
                if rule_name in moved_rules:
                    continue
                
                current_order = int(row["Suggested_Order"])
                shadow_reason = str(row.get("Shadow_Reason", ""))
                
                # Move up by 1 position (but not below 1)
                new_order = max(1, current_order - 1)
                rule_to_suggested_order[rule_name] = new_order
                
                firewall_suggestions.append({
                    "rule": rule_name,
                    "firewall": firewall_name_str,
                    "from": int(row["_original_order"]),
                    "to": new_order,
                    "reason": f"Moved up: {rule_name} is shadowed by an earlier rule. {shadow_reason[:100] if shadow_reason else 'Rule is fully covered by a preceding rule with different action.'}"
                })
                moved_rules.add(rule_name)
        
        # 2. Move partial shadow rules up
        partial_shadow_col = "Partial_Shadow_Rule"
        if partial_shadow_col in df_fw.columns:
            partial_shadowed = df_fw[
                (df_fw[partial_shadow_col] == True) & 
                (~df_fw[rule_name_col].astype(str).isin(moved_rules))
            ].copy()
            
            for idx, row in partial_shadowed.iterrows():
                rule_name = str(row.get(rule_name_col, f"Rule_{idx}"))
                current_order = int(row["Suggested_Order"])
                shadow_reason = str(row.get("Shadow_Reason", ""))
                
                new_order = max(1, current_order - 1)
                rule_to_suggested_order[rule_name] = new_order
                
                firewall_suggestions.append({
                    "rule": rule_name,
                    "firewall": firewall_name_str,
                    "from": int(row["_original_order"]),
                    "to": new_order,
                    "reason": f"Moved up: {rule_name} is partially shadowed. {shadow_reason[:100] if shadow_reason else 'Rule partially overlaps with a preceding rule with different action.'}"
                })
                moved_rules.add(rule_name)
        
        # 3. Group redundant rules together
        redundant_col = "Redundant_Rule"
        if redundant_col in df_fw.columns:
            redundant_rules = df_fw[df_fw[redundant_col] == True].copy()
            
            redundancy_groups = {}
            for idx, row in redundant_rules.iterrows():
                reason = str(row.get("Redundancy_Reason", ""))
                if reason:
                    parts = reason.split("/")
                    group_key = parts[1].strip() if len(parts) > 1 else "general_redundancy"
                else:
                    group_key = "general_redundancy"
                
                if group_key not in redundancy_groups:
                    redundancy_groups[group_key] = []
                redundancy_groups[group_key].append((idx, row))
            
            for group_key, rules in redundancy_groups.items():
                if len(rules) < 2:
                    continue
                
                rule_names_in_group = [str(r[1].get(rule_name_col, f"Rule_{r[0]}")) for r in rules]
                earliest_order = min(int(r[1]["Suggested_Order"]) for r in rules)
                
                for idx, row in rules:
                    rule_name = str(row.get(rule_name_col, f"Rule_{idx}"))
                    if rule_name in moved_rules:
                        continue
                    
                    rule_to_suggested_order[rule_name] = earliest_order
                    
                    firewall_suggestions.append({
                        "rule": rule_name,
                        "firewall": firewall_name_str,
                        "from": int(row["_original_order"]),
                        "to": earliest_order,
                        "reason": f"Grouped with redundant rules: {', '.join(rule_names_in_group[:3])}{'...' if len(rule_names_in_group) > 3 else ''}. These rules have the same action and are fully covered by an earlier rule.",
                        "merge_suggestions": {
                            "rules": rule_names_in_group,
                            "reason": "These redundant rules can be merged or removed as they are fully covered by an earlier rule."
                        }
                    })
                    moved_rules.add(rule_name)
        
        # 4. Group consolidation candidates together
        consolidation_col = "Consolidation_Candidate"
        if consolidation_col in df_fw.columns:
            consolidation_rules = df_fw[df_fw[consolidation_col] == True].copy()
            
            consolidation_groups = {}
            for idx, row in consolidation_rules.iterrows():
                key = str(row.get("Consolidation_Key", ""))
                if not key:
                    continue
                
                if key not in consolidation_groups:
                    consolidation_groups[key] = []
                consolidation_groups[key].append((idx, row))
            
            for key, rules in consolidation_groups.items():
                if len(rules) < 2:
                    continue
                
                rule_names_in_group = [str(r[1].get(rule_name_col, f"Rule_{r[0]}")) for r in rules]
                consolidation_reason = str(rules[0][1].get("Consolidation_Reason", ""))
                earliest_order = min(int(r[1]["Suggested_Order"]) for r in rules)
                
                for idx, row in rules:
                    rule_name = str(row.get(rule_name_col, f"Rule_{idx}"))
                    if rule_name in moved_rules:
                        continue
                    
                    rule_to_suggested_order[rule_name] = earliest_order
                    
                    firewall_suggestions.append({
                        "rule": rule_name,
                        "firewall": firewall_name_str,
                        "from": int(row["_original_order"]),
                        "to": earliest_order,
                        "reason": f"Grouped for consolidation: {consolidation_reason[:150] if consolidation_reason else 'Rules can be merged into a single rule.'}",
                        "merge_suggestions": {
                            "rules": rule_names_in_group,
                            "reason": consolidation_reason if consolidation_reason else "These rules can be consolidated into a single rule."
                        }
                    })
                    moved_rules.add(rule_name)
        
        # 5. Move catch-all rules to the end (within this firewall)
        src_col = None
        dst_col = None
        svc_col = None
        
        for col in ["Source Address", "Src Address", "Source_Address"]:
            if col in df_fw.columns:
                src_col = col
                break
        
        for col in ["Destination Address", "Dst Address", "Destination_Address"]:
            if col in df_fw.columns:
                dst_col = col
                break
        
        for col in ["Service", "Port", "Ports"]:
            if col in df_fw.columns:
                svc_col = col
                break
        
        catch_all_rules = []
        if src_col and dst_col and svc_col:
            for idx, row in df_fw.iterrows():
                rule_name = str(row.get(rule_name_col, f"Rule_{idx}"))
                if rule_name in moved_rules:
                    continue
                
                src = str(row.get(src_col, "")).lower()
                dst = str(row.get(dst_col, "")).lower()
                svc = str(row.get(svc_col, "")).lower()
                
                any_count = sum([
                    "any" in src,
                    "any" in dst,
                    "any" in svc
                ])
                
                if any_count >= 2:
                    catch_all_rules.append((idx, row, any_count))
        
        catch_all_rules.sort(key=lambda x: x[2], reverse=True)
        total_rules_fw = len(df_fw)
        
        for i, (idx, row, any_count) in enumerate(catch_all_rules):
            rule_name = str(row.get(rule_name_col, f"Rule_{idx}"))
            new_order = total_rules_fw - len(catch_all_rules) + i + 1
            rule_to_suggested_order[rule_name] = new_order
            
            firewall_suggestions.append({
                "rule": rule_name,
                "firewall": firewall_name_str,
                "from": int(row["_original_order"]),
                "to": new_order,
                "reason": f"Moved to end: {rule_name} is a catch-all rule (has 'any' in {any_count} field(s)). Catch-all rules should be placed at the end to allow specific rules to match first."
            })
            moved_rules.add(rule_name)
        
        # 6. Move generalization risks up
        generalization_col = "Generalization_Risk"
        if generalization_col in df_fw.columns:
            generalization_rules = df_fw[
                (df_fw[generalization_col] == True) & 
                (~df_fw[rule_name_col].astype(str).isin(moved_rules))
            ].copy()
            
            for idx, row in generalization_rules.iterrows():
                rule_name = str(row.get(rule_name_col, f"Rule_{idx}"))
                current_order = int(row["Suggested_Order"])
                gen_reason = str(row.get("Generalization_Reason", ""))
                
                new_order = max(1, current_order - 1)
                rule_to_suggested_order[rule_name] = new_order
                
                firewall_suggestions.append({
                    "rule": rule_name,
                    "firewall": firewall_name_str,
                    "from": int(row["_original_order"]),
                    "to": new_order,
                    "reason": f"Moved up: {rule_name} generalizes later rules. {gen_reason[:100] if gen_reason else 'This rule is more permissive than later rules and should be evaluated first.'}"
                })
                moved_rules.add(rule_name)
        
        # Apply suggested orders to this firewall's DataFrame
        for idx, row in df_fw.iterrows():
            rule_name = str(row.get(rule_name_col, f"Rule_{idx}"))
            if rule_name in rule_to_suggested_order:
                df_fw.loc[idx, "Suggested_Order"] = rule_to_suggested_order[rule_name]
        
        # Handle conflicts: if multiple rules have the same suggested order, adjust them
        # Sort by suggested order and reassign sequential orders (within this firewall)
        df_fw = df_fw.sort_values(["Suggested_Order", "_original_order"])
        df_fw["Suggested_Order"] = range(1, len(df_fw) + 1)
        
        # Update the main DataFrame with this firewall's suggested orders
        for idx in df_fw.index:
            df_work.loc[idx, "Suggested_Order"] = df_fw.loc[idx, "Suggested_Order"]
        
        # Sort suggestions by target position and add to all suggestions
        firewall_suggestions.sort(key=lambda x: x["to"])
        all_suggestions.extend(firewall_suggestions)
        
        logging.info(f"     Generated {len(firewall_suggestions)} suggestions for '{firewall_name_str}'")
    
    # Sort all suggestions by firewall, then by target position
    all_suggestions.sort(key=lambda x: (x.get("firewall", ""), x["to"]))
    
    return all_suggestions, df_work



