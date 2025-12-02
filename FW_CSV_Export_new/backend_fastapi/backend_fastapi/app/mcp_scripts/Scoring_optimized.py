#!/usr/bin/env python3
"""
Optimized version of scoring functions with performance improvements:
1. Pre-compile regex patterns
2. Use itertuples instead of iterrows
3. Parallel processing with multiprocessing
4. Cache expensive operations
5. Vectorize where possible
"""
import re
from functools import lru_cache
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import multiprocessing as mp

# Pre-compile regex patterns (moved to module level)
_PORT_NUM_PATTERN = re.compile(r"^\d+$")
_PORT_RANGE_PATTERN = re.compile(r"^(\d+)\s*-\s*(\d+)$")
_PROTO_PREF_PATTERN = re.compile(r"^(tcp|udp)\s*/\s*(.+)$", re.IGNORECASE)
_ANY_WORD_PATTERN = re.compile(r'\bany\b', re.IGNORECASE)
_SEP_SPLIT_PATTERN = re.compile(r'[,;]')

# Cache for IP network parsing
@lru_cache(maxsize=10000)
def _cached_cidr_bucket_v4(tok: str) -> str:
    """Cached version of CIDR bucket check"""
    try:
        net = ipaddress.ip_network(str(tok).strip(), strict=False)
        if net.version != 4:
            return None
        p = net.prefixlen
        if p <= 16:
            return "le16"
        if 17 <= p <= 22:
            return "17_22"
        return None
    except Exception:
        return None

# Optimized token splitting with pre-compiled regex
def _split_tokens_fast(val: str, sep: str) -> List[str]:
    """Optimized token splitting"""
    if not val or pd.isna(val):
        return ["any"]
    s = str(val).replace("[Disabled]", "{}").replace("[Negate]", "{}").strip()
    if not s:
        return ["any"]
    # Use pre-compiled regex for faster splitting
    parts = [p.strip().lower() for p in _SEP_SPLIT_PATTERN.split(s) if p.strip()]
    return parts if parts else ["any"]

def _evaluate_row_optimized(row_tuple, column_map, sep: str, weights: Dict[str, int]) -> dict:
    """
    Optimized row evaluation using namedtuple access (faster than dict.get)
    row_tuple: namedtuple from itertuples()
    column_map: dict mapping logical names to column indices/names
    """
    # Fast column access
    get_col = lambda name: getattr(row_tuple, column_map.get(name, name), "")
    
    # Token splitting (optimized)
    src = _split_tokens_fast(get_col("Source Address"), sep)
    dst = _split_tokens_fast(get_col("Destination Address"), sep)
    app = _split_tokens_fast(get_col("Application"), sep)
    svc = _split_tokens_fast(get_col("Service"), sep)
    act = str(get_col("Action")).strip().lower()
    src_zone = _split_tokens_fast(get_col("Source Zone") or "", sep)
    dst_zone = _split_tokens_fast(get_col("Destination Zone") or "", sep)

    # Fast any check
    src_is_any = any(t == "any" for t in src)
    dst_is_any = any(t == "any" for t in dst)
    srcz_is_any = any(t == "any" for t in src_zone)
    dstz_is_any = any(t == "any" for t in dst_zone)
    
    # CIDR buckets (cached)
    src_buckets = [_cached_cidr_bucket_v4(t) for t in src]
    dst_buckets = [_cached_cidr_bucket_v4(t) for t in dst]
    src_le16 = any(b == "le16" for b in src_buckets)
    src_17_22 = (not src_le16) and any(b == "17_22" for b in src_buckets)
    dst_le16 = any(b == "le16" for b in dst_buckets)
    dst_17_22 = (not dst_le16) and any(b == "17_22" for b in dst_buckets)

    # Port metrics (optimized)
    svc_total, svc_any, svc_gt1k = _port_metrics(svc)
    app_total, app_any, app_gt1k = _port_metrics(app)
    svc_or = bool(svc_any or svc_gt1k)
    app_or = bool(app_any or app_gt1k)

    # Insecure matching
    insecure_hit = _insecure_match(svc)

    # Risky traffic (optimized)
    src_public = _is_public_ip(src)
    src_risky_zone = _is_risky_zone(src_zone)
    risky_inbound = (insecure_hit and src_public and src_risky_zone)
    
    dst_public = _is_public_ip(dst)
    dst_risky_zone = _is_risky_zone(dst_zone)
    risky_outbound = (insecure_hit and dst_public and dst_risky_zone)

    # Rule usage (fast string operations)
    rule_usage = str(get_col("Rule Usage Rule Usage") or "").strip().lower()
    rule_usage_points = 5 if not rule_usage or rule_usage == "unused" else (2 if rule_usage == "partially used" else 0)
    
    profile = str(get_col("Profile") or "").strip().lower()
    profile_points = 5 if profile in ("none", "") else 0
    
    options = str(get_col("Options") or "").strip().lower()
    options_points = 5 if options in ("none", "", "nan", "null", "n/a", "na") else 0
    
    rule_usage_desc = str(get_col("Rule Usage Description") or "").strip().upper()
    ticket_keywords = ("INC", "CHG", "RITM", "TASK")
    rule_usage_desc_points = 0 if any(kw in rule_usage_desc for kw in ticket_keywords) else 5

    # Source User (optimized with pre-compiled regex)
    source_user = str(get_col("Source User") or "").strip()
    source_user_lower = source_user.lower()
    has_disabled = "[Disabled]" in source_user
    has_any = (source_user_lower == "any") or bool(_ANY_WORD_PATTERN.search(source_user_lower)) if source_user_lower else False
    is_empty = source_user == ""
    is_unsafe_source_user = not (has_disabled or has_any or is_empty)

    is_deny = act in ("deny", "drop")
    scoring_weights = weights or SCORING_WEIGHTS
    penalty_points = scoring_weights.get("Source_User_Scoring", -10) if is_unsafe_source_user else 0

    # Build output
    out = {
        "Src_IsAny": _cell(src_is_any, scoring_weights.get("Src_IsAny", 25)),
        "Src_CIDR_Le_16": _cell(src_le16, scoring_weights.get("Src_CIDR_Le_16", 25)),
        "Src_CIDR_17_22": _cell(src_17_22, scoring_weights.get("Src_CIDR_17_22", 15)),
        "Dst_IsAny": _cell(dst_is_any, scoring_weights.get("Dst_IsAny", 25)),
        "Dst_CIDR_Le_16": _cell(dst_le16, scoring_weights.get("Dst_CIDR_Le_16", 25)),
        "Dst_CIDR_17_22": _cell(dst_17_22, scoring_weights.get("Dst_CIDR_17_22", 15)),
        "SrcZone_IsAny": _cell(srcz_is_any, scoring_weights.get("SrcZone_IsAny", 5)),
        "DstZone_IsAny": _cell(dstz_is_any, scoring_weights.get("DstZone_IsAny", 5)),
        "Service_Any_OR_RangeGt1000": _cell(svc_or, scoring_weights.get("Service_Any_OR_RangeGt1000", 25)),
        "App_Any_OR_RangeGt1000": _cell(app_or, scoring_weights.get("App_Any_OR_RangeGt1000", 25)),
        "Service_Insecure_Match": _cell(insecure_hit, scoring_weights.get("Service_Insecure_Match", 20)),
        "Risky_Inbound": _cell(risky_inbound, scoring_weights.get("Risky_Inbound", 20) if risky_inbound else 0),
        "Risky_Outbound": _cell(risky_outbound, scoring_weights.get("Risky_Outbound", 15) if risky_outbound else 0),
        "Rule_Usage_Scoring": _cell(rule_usage_points > 0, rule_usage_points),
        "Rule_Usage_Description_Scoring": _cell(rule_usage_desc_points > 0, rule_usage_desc_points),
        "Source_User_Scoring": _cell(is_unsafe_source_user, penalty_points),
        "Profile_Scoring": _cell(profile_points > 0, profile_points),
        "Options_Scoring": _cell(options_points > 0, options_points),
        "Service_IsAny": _cell(svc_any, 0),
        "Service_UniquePorts_Total": int(svc_total),
        "Service_RangeGt1000": _cell(svc_gt1k, 0),
        "App_IsAny": _cell(app_any, 0),
        "App_UniquePorts_Total": int(app_total),
        "App_RangeGt1000": _cell(app_gt1k, 0),
        "Action_IsDenyOrDrop": _cell(is_deny, 0),
    }

    # Score total
    if is_deny:
        out["Score_Total"] = 0
    else:
        total = 0
        for key in scoring_weights.keys():
            val = str(out.get(key, "False,0"))
            try:
                pts = int(val.split(",")[1])
            except Exception:
                pts = 0
            total += pts
        out["Score_Total"] = int(total)

    return out


def _score_df_optimized(payload: dict) -> pd.DataFrame:
    """
    Optimized scoring function with:
    1. Column resolution done once
    2. itertuples instead of iterrows (much faster)
    3. Optional parallel processing
    """
    df: pd.DataFrame = payload["df"]
    sep: str = payload["sep"]
    input_path: str = payload.get("input_path", "")
    output_path: str = payload.get("output_path", "")
    progress_callback = payload.get("progress_callback")
    use_parallel = payload.get("use_parallel", True)  # Enable parallel by default
    max_workers = payload.get("max_workers", None)  # Auto-detect

    # Resolve columns ONCE (not per row)
    def pick(col): return _resolve(df, col) or col
    
    column_map = {
        "Source Address": pick("Source Address"),
        "Destination Address": pick("Destination Address"),
        "Application": pick("Application"),
        "Service": pick("Service"),
        "Action": pick("Action"),
        "Source Zone": pick("Source Zone"),
        "Source User": pick("Source User"),
        "Destination Zone": pick("Destination Zone"),
        "Rule Usage Rule Usage": pick("Rule Usage Rule Usage"),
        "Rule Usage Description": pick("Rule Usage Description"),
        "Profile": pick("Profile"),
        "Options": pick("Options"),
    }

    need = ["Source Address","Destination Address","Application","Service","Action"]
    miss = [c for c in need if column_map.get(c) is None]
    if miss:
        raise ValueError(f"Missing required columns: {', '.join(miss)}")

    if progress_callback:
        progress_callback("Loading scoring configuration", 5)

    weights = _get_scoring_weights(input_path, output_path)

    if progress_callback:
        progress_callback("Preparing rule data", 10)

    total_rows = len(df)
    
    # Prepare arguments for processing
    # Use itertuples (much faster than iterrows)
    rows_data = list(df.itertuples(index=False, name='Rule'))
    
    if progress_callback:
        progress_callback("Calculating scores", 15)

    # Option 1: Parallel processing (for large datasets)
    if use_parallel and total_rows > 500:
        num_workers = max_workers or min(mp.cpu_count(), 8)
        print(f"🚀 Using parallel processing with {num_workers} workers for {total_rows} rows")
        
        # Split rows into chunks
        chunk_size = max(100, total_rows // (num_workers * 4))
        chunks = [rows_data[i:i+chunk_size] for i in range(0, total_rows, chunk_size)]
        
        def process_chunk(chunk):
            return [_evaluate_row_optimized(row, column_map, sep, weights) for row in chunk]
        
        evals = []
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(process_chunk, chunk) for chunk in chunks]
            
            completed = 0
            for future in futures:
                chunk_results = future.result()
                evals.extend(chunk_results)
                completed += len(chunk_results)
                if progress_callback:
                    progress = 15 + int((completed / total_rows) * 75)
                    progress_callback(f"Processing rule {completed}/{total_rows}", progress)
    
    # Option 2: Sequential but optimized (for smaller datasets or when parallel disabled)
    else:
        evals = []
        for i, row in enumerate(rows_data):
            if progress_callback and i % 100 == 0:
                progress = 15 + int((i / total_rows) * 75)
                progress_callback(f"Processing rule {i+1}/{total_rows}", progress)
            evals.append(_evaluate_row_optimized(row, column_map, sep, weights))

    if progress_callback:
        progress_callback("Finalizing scores", 90)

    # Convert to DataFrame (optimized)
    facts = pd.DataFrame(evals)
    out = pd.concat([df.reset_index(drop=True), facts], axis=1)
    cols = [c for c in out.columns if c != "Score_Total"] + ["Score_Total"]
    return out.reindex(columns=cols)

