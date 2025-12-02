#!/usr/bin/env python3
from __future__ import annotations
import os, re, json, argparse, asyncio, logging, sys
from typing import Optional, List, Dict, Tuple, Set, Callable
from pathlib import Path
from functools import lru_cache
from concurrent.futures import ProcessPoolExecutor
import multiprocessing as mp
import pandas as pd
import ipaddress
from xlsxwriter.utility import xl_rowcol_to_cell

# Pre-compile regex patterns for performance (module-level)
_PORT_NUM_PATTERN = re.compile(r"^\d+$")
_PORT_RANGE_PATTERN = re.compile(r"^(\d+)\s*-\s*(\d+)$")
_PROTO_PREF_PATTERN = re.compile(r"^(tcp|udp)\s*/\s*(.+)$", re.IGNORECASE)
_ANY_WORD_PATTERN = re.compile(r'\bany\b', re.IGNORECASE)


from langchain_core.runnables import RunnableLambda, RunnablePassthrough
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("PA-OverPermissive-Points-Inline-Scorer")

# ----------------------------
# Defaults / config
# ----------------------------
SEP_DEFAULT = "; "                      # matches your expanders/joiners. :contentReference[oaicite:4]{index=4} :contentReference[oaicite:5]{index=5}
OUT_DIR = "./expansions"
OUT_BASENAME = "over_permissive_scored.xlsx"
SHEET_GUESS = ["rules_curated", "rules_expanded", 0]  # curated sheet created by your API. :contentReference[oaicite:6]{index=6} :contentReference[oaicite:7]{index=7}

# ----------------------------
# Helpers
# ----------------------------
def _norm_col(s: str) -> str:
    return re.sub(r"[\s_]+", " ", str(s)).strip().casefold()

def _resolve(df: pd.DataFrame, want: str) -> Optional[str]:
    cmap = {_norm_col(c): c for c in df.columns}
    return cmap.get(_norm_col(want))

# Pre-compile separator pattern for common case
_SEP_COMMA_SEMI = re.compile(r'\s*[,;]\s*')

def _split_tokens(val: str, sep: str) -> List[str]:
    if val is None: return []
    raw = str(val).strip()
    if not raw: return []
    
    # Special case: if the entire value is "any" (case-insensitive), return it directly
    raw_lower = raw.lower()
    if raw_lower == "any":
        return ["any"]
    
    # Check if raw contains "any" as a standalone word (before splitting)
    # This handles cases like "any", "any;", "; any", "any, 10.0.0.1", etc.
    has_any_standalone = bool(re.search(r'\bany\b', raw_lower))
    
    # Optimize for common case (sep is "; " which matches ";")
    if sep.strip() in (",", ";") or sep == "; ":
        # Use pre-compiled pattern for common separators
        parts = _SEP_COMMA_SEMI.split(raw)
    else:
        # Handle multiple separators: comma, semicolon, and the provided separator
        separators = [sep.strip(), ",", ";"]
        pattern = "|".join(re.escape(s) for s in separators)
        parts = re.split(rf"\s*({pattern})\s*", raw)
    
    # Filter out empty parts and separators, convert to lowercase
    result = []
    for p in parts:
        p_clean = p.strip()
        if p_clean:
            p_lower = p_clean.lower()
            # Skip if it's just the separator
            if p_lower != sep.strip().lower():
                result.append(p_lower)
    
    # If splitting didn't find "any" but we detected it in the original, add it
    # This handles edge cases where splitting might have removed it
    if has_any_standalone and "any" not in result:
        result.append("any")
    
    # If we end up with no valid tokens after splitting but original had content, return ["any"] if "any" was detected
    if not result and has_any_standalone:
        return ["any"]
    
    return result if result else []

def _any_is_any(tokens: List[str]) -> bool:
    return any(str(t).strip().lower() == "any" for t in tokens)

@lru_cache(maxsize=10000)  # Cache IP network parsing (major bottleneck)
def _cidr_bucket_v4(tok: str) -> Optional[str]:
    try:
        net = ipaddress.ip_network(str(tok).strip(), strict=False)
        if net.version != 4: return None
        p = net.prefixlen
        if p <= 16: return "le16"
        if 17 <= p <= 22: return "17_22"
        return None
    except Exception:
        return None

def _is_public_ip(tokens: List[str]) -> bool:
    """Check if any token contains a public IP address."""
    for tok in tokens:
        try:
            net = ipaddress.ip_network(str(tok).strip(), strict=False)
            if net.version == 4:
                # Check if it's a public IP (not private, not loopback, not link-local)
                if not (net.is_private or net.is_loopback or net.is_link_local):
                    return True
        except Exception:
            continue
    return False

def _is_risky_zone(tokens: List[str]) -> bool:
    """Check if any token contains risky zone names."""
    risky_zones = {"internet", "untrust", "external", "any"}
    for tok in tokens:
        if str(tok).strip().lower() in risky_zones:
            return True
    return False

# ---------- Exact port math via interval union ----------
def _port_intervals_from_tokens(tokens: List[str]) -> List[Tuple[int,int]]:
    ivals: List[Tuple[int,int]] = []
    for tok in tokens:
        s = str(tok).strip().lower()
        if not s: continue
        rhs = s.split("/", 1)[1].strip() if "/" in s else s
        if rhs == "any":
            ivals.append((1, 65535)); continue
        if m := _PORT_NUM_PATTERN.fullmatch(rhs):
            v = int(m.group(0))
            if 1 <= v <= 65535: ivals.append((v, v)); continue
        if m := _PORT_RANGE_PATTERN.fullmatch(rhs):
            lo, hi = int(m.group(1)), int(m.group(2))
            if lo > hi: lo, hi = hi, lo
            lo = max(1, lo); hi = min(65535, hi)
            if lo <= hi: ivals.append((lo, hi))
    return ivals

def _union_length(ivals: List[Tuple[int,int]]) -> int:
    if not ivals: return 0
    ivals = sorted(ivals)
    total = 0
    lo, hi = ivals[0]
    for a, b in ivals[1:]:
        if a <= hi + 1:
            hi = max(hi, b)
        else:
            total += hi - lo + 1
            lo, hi = a, b
    total += hi - lo + 1
    return total

def _port_metrics(tokens: List[str]) -> Tuple[int, bool, bool]:
    """Return (unique_ports_total, is_any, range_gt_1000)."""
    any_flag = _any_is_any(tokens)
    ivals = _port_intervals_from_tokens(tokens)
    unique_total = _union_length(ivals) if ivals else (65535 if any_flag else 0)
    return unique_total, any_flag, unique_total > 1000

# ---------- Insecure ports detection ----------
INSECURE_ANY: List[Tuple[int,int]] = [
    (20,21), (23,23), (80,80), (161,161), (445,445),
    (1080,1080), (3389,3389), (4444,4444), (6660,6669),
]
INSECURE_TCP_UDP: List[Tuple[int,int]] = [(135,135), (137,137), (139,139)]
INSECURE_TCP_ONLY: List[Tuple[int,int]] = [(110,110), (145,145), (5900,5900)]



def _parse_ports_blob(blob: str) -> List[int]:
    """
    Parse ports from strings like:
      'tcp/80; udp/53; 443, 80-82; ANY'
    Returns a list of discrete port numbers (1..65535).
    """
    if blob is None or str(blob).strip() == "":
        return []
    s = str(blob).replace(";", ",").strip()
    out: Set[int] = set()
    for token in [t.strip() for t in s.split(",") if t.strip()]:
        rhs = token.split("/", 1)[1] if "/" in token else token  # drop proto if present
        if rhs.strip().lower() == "any":
            out.update(range(1, 65536))
            continue
        if m := re.fullmatch(r"\s*(\d+)\s*-\s*(\d+)\s*", rhs):
            lo, hi = int(m.group(1)), int(m.group(2))
            if lo > hi:
                lo, hi = hi, lo
            lo, hi = max(1, lo), min(65535, hi)
            out.update(range(lo, hi + 1))
            continue
        if m := re.fullmatch(r"\s*(\d+)\s*", rhs):
            v = int(m.group(1))
            if 1 <= v <= 65535:
                out.add(v)
    return sorted(out)

def _insecure_port_set() -> Set[int]:
    """
    Use your existing insecure port ranges (from INSECURE_*).
    """
    s: Set[int] = set()
    for (lo, hi) in (INSECURE_ANY + INSECURE_TCP_UDP + INSECURE_TCP_ONLY):
        s.update(range(lo, hi + 1))
    return s

def _build_port_to_apps_from_catalog(catalog_df: pd.DataFrame) -> Dict[int, Set[str]]:
    """
    catalog_df must have columns: 'Application', 'Standard Ports'
    Build an index: port -> set(app names)
    """
    mapping: Dict[int, Set[str]] = {}
    for _, row in catalog_df.iterrows():
        app = str(row["Application"]).strip()
        for p in _parse_ports_blob(row["Standard Ports"]):
            mapping.setdefault(p, set()).add(app)
    return mapping

def _intervals_overlap(a: Tuple[int,int], b: Tuple[int,int]) -> bool:
    return not (a[1] < b[0] or b[1] < a[0])

def _normalize_proto(proto_raw: str) -> str:
    r = (proto_raw or "").strip().upper()
    if r in ("TCP","UDP"): return r
    if r in ("ANY",""): return "ANY"
    return r

def _proto_and_port_intervals(tokens: List[str]) -> List[Tuple[Set[str], Tuple[int,int]]]:
    out: List[Tuple[Set[str], Tuple[int,int]]] = []
    for tok in tokens:
        s = str(tok).strip()
        if not s: continue
        proto = "ANY"
        rhs = s
        
        # Handle both formats: "TCP/80" and "80,tcp"
        if "/" in s:
            # Format: "TCP/80" - use pre-compiled regex
            if m := _PROTO_PREF_PATTERN.match(s):
                proto = _normalize_proto(m.group(1))
                rhs = m.group(2).strip()
            else:
                p, rhs = s.split("/", 1)
                proto = _normalize_proto(p)
        elif "," in s:
            # Format: "80,tcp" or "443,80,tcp"
            parts = [p.strip() for p in s.split(",")]
            if len(parts) >= 2:
                # Check if last part is a protocol
                last_part = parts[-1].upper()
                if last_part in ("TCP", "UDP", "ANY"):
                    proto = _normalize_proto(last_part)
                    # Use all parts except the last as port numbers
                    rhs = ",".join(parts[:-1])
                else:
                    # No protocol specified, treat as port numbers
                    rhs = s
            else:
                rhs = s
        else:
            # No separator, treat as port number
            rhs = s
            
        rhs = rhs.strip().lower()
        if rhs == "any": 
            lo, hi = 1, 65535
        elif m := _PORT_NUM_PATTERN.fullmatch(rhs): 
            lo = hi = int(m.group(0))
        elif m := _PORT_RANGE_PATTERN.fullmatch(rhs):
            lo, hi = int(m.group(1)), int(m.group(2))
            if lo > hi: lo, hi = hi, lo
            lo, hi = max(1, lo), min(65535, hi)
        elif "," in rhs or ";" in rhs:
            # Handle multiple ports like "443,80" or "443;80"
            # Split by both comma and semicolon
            port_parts = []
            for separator in [",", ";"]:
                if separator in rhs:
                    port_parts.extend([p.strip() for p in rhs.split(separator)])
                    break
            
            # Filter for valid port numbers
            valid_ports = [p for p in port_parts if p.strip().isdigit()]
            if valid_ports:
                # For multiple ports, create separate intervals
                for port_str in valid_ports:
                    port_num = int(port_str)
                    if 1 <= port_num <= 65535:
                        pset = {"TCP","UDP"} if proto in ("ANY","") else ({proto} if proto in {"TCP","UDP"} else set())
                        if pset:
                            out.append((pset, (port_num, port_num)))
                continue
        else:
            continue  # textual like "https" – ignore for insecure overlap
            
        pset = {"TCP","UDP"} if proto in ("ANY","") else ({proto} if proto in {"TCP","UDP"} else set())
        if not pset:
            continue
        out.append((pset, (lo, hi)))
    return out

def _insecure_match(tokens: List[str]) -> bool:
    # Only check for actual insecure ports, not "any"
    pairs = _proto_and_port_intervals(tokens)
    if not pairs: return False
    for pset, rng in pairs:
        for iv in INSECURE_ANY:
            if _intervals_overlap(rng, iv): return True
        if "TCP" in pset or "UDP" in pset:
            for iv in INSECURE_TCP_UDP:
                if _intervals_overlap(rng, iv): return True
        if "TCP" in pset:
            for iv in INSECURE_TCP_ONLY:
                if _intervals_overlap(rng, iv): return True
    return False

# ----------------------------
# Centralized Scoring Configuration
# ----------------------------
class ScoringConfig:
    """
    Centralized scoring configuration object.
    Change point values here to update throughout the entire codebase.
    All scoring points are defined as class attributes for easy modification.
    """
    
    # Scope & Exposure Points
    SRC_IS_ANY = 25
    SRC_CIDR_LE_16 = 25
    SRC_CIDR_17_22 = 15
    DST_IS_ANY = 25
    DST_CIDR_LE_16 = 25
    DST_CIDR_17_22 = 15
    SRC_ZONE_IS_ANY = 5
    DST_ZONE_IS_ANY = 5
    
    # Service/Application Breadth Points
    SERVICE_ANY_OR_RANGE_GT_1000 = 25
    APP_ANY_OR_RANGE_GT_1000 = 25
    
    # Insecure Ports Points
    SERVICE_INSECURE_MATCH = 20
    
    # Risky Traffic Points
    RISKY_INBOUND = 20
    RISKY_OUTBOUND = 10
    
    # Migration Points
    MIGRATE_INSECURE = 15
    MIGRATE_OTHER_PORTS = 5
    
    # Rule Usage & Configuration Points
    RULE_USAGE_UNUSED = 5
    RULE_USAGE_PARTIALLY_USED = 2
    RULE_USAGE_USED = 0
    RULE_USAGE_DESCRIPTION_NO_TICKET = 5
    RULE_USAGE_DESCRIPTION_HAS_TICKET = 0
    
    SOURCE_USER_PENALTY = -10  # Negative because it's a penalty
    SOURCE_USER_SAFE = 0
    
    PROFILE_NONE_OR_BLANK = 5
    PROFILE_OTHER = 0
    
    OPTIONS_NONE_OR_BLANK = 5
    OPTIONS_OTHER = 0
    
    @classmethod
    def get_weights_dict(cls) -> Dict[str, int]:
        """
        Returns the scoring weights as a dictionary compatible with existing code.
        This maintains backward compatibility with SCORING_WEIGHTS.
        """
        return {
            "Src_IsAny": cls.SRC_IS_ANY,
            "Src_CIDR_Le_16": cls.SRC_CIDR_LE_16,
            "Src_CIDR_17_22": cls.SRC_CIDR_17_22,
            "Dst_IsAny": cls.DST_IS_ANY,
            "Dst_CIDR_Le_16": cls.DST_CIDR_LE_16,
            "Dst_CIDR_17_22": cls.DST_CIDR_17_22,
            "SrcZone_IsAny": cls.SRC_ZONE_IS_ANY,
            "DstZone_IsAny": cls.DST_ZONE_IS_ANY,
            "Service_Any_OR_RangeGt1000": cls.SERVICE_ANY_OR_RANGE_GT_1000,
            "App_Any_OR_RangeGt1000": cls.APP_ANY_OR_RANGE_GT_1000,
            "Service_Insecure_Match": cls.SERVICE_INSECURE_MATCH,
            "Risky_Inbound": cls.RISKY_INBOUND,
            "Risky_Outbound": cls.RISKY_OUTBOUND,
            "Migrate_Insecure": cls.MIGRATE_INSECURE,
            "Migrate_Other_Ports": cls.MIGRATE_OTHER_PORTS,
            "Rule_Usage_Scoring": cls.RULE_USAGE_UNUSED,  # Max value for this category
            "Rule_Usage_Description_Scoring": cls.RULE_USAGE_DESCRIPTION_NO_TICKET,
            "Source_User_Scoring": cls.SOURCE_USER_PENALTY,
            "Profile_Scoring": cls.PROFILE_NONE_OR_BLANK,
            "Options_Scoring": cls.OPTIONS_NONE_OR_BLANK,
        }
    
    @classmethod
    def get_config_rows(cls) -> List[Dict[str, any]]:
        """
        Returns the default configuration rows for Scoring_Config sheet.
        All point values come from this class.
        """
        return [
            {"Scoring_Category": "Src_IsAny", "Description": "Source is 'any'", "Points": cls.SRC_IS_ANY, "Enabled": "Yes"},
            {"Scoring_Category": "Src_CIDR_Le_16", "Description": "Source CIDR ≤ /16", "Points": cls.SRC_CIDR_LE_16, "Enabled": "Yes"},
            {"Scoring_Category": "Src_CIDR_17_22", "Description": "Source CIDR /17-/22", "Points": cls.SRC_CIDR_17_22, "Enabled": "Yes"},
            {"Scoring_Category": "Dst_IsAny", "Description": "Destination is 'any'", "Points": cls.DST_IS_ANY, "Enabled": "Yes"},
            {"Scoring_Category": "Dst_CIDR_Le_16", "Description": "Destination CIDR ≤ /16", "Points": cls.DST_CIDR_LE_16, "Enabled": "Yes"},
            {"Scoring_Category": "Dst_CIDR_17_22", "Description": "Destination CIDR /17-/22", "Points": cls.DST_CIDR_17_22, "Enabled": "Yes"},
            {"Scoring_Category": "SrcZone_IsAny", "Description": "Source Zone is 'any'", "Points": cls.SRC_ZONE_IS_ANY, "Enabled": "Yes"},
            {"Scoring_Category": "DstZone_IsAny", "Description": "Destination Zone is 'any'", "Points": cls.DST_ZONE_IS_ANY, "Enabled": "Yes"},
            {"Scoring_Category": "Service_Any_OR_RangeGt1000", "Description": "Service is 'any' or >1000 ports", "Points": cls.SERVICE_ANY_OR_RANGE_GT_1000, "Enabled": "Yes"},
            {"Scoring_Category": "App_Any_OR_RangeGt1000", "Description": "Application is 'any' or >1000 ports", "Points": cls.APP_ANY_OR_RANGE_GT_1000, "Enabled": "Yes"},
            {"Scoring_Category": "Service_Insecure_Match", "Description": "Broad service AND insecure overlap", "Points": cls.SERVICE_INSECURE_MATCH, "Enabled": "Yes"},
            {"Scoring_Category": "Risky_Inbound", "Description": "Insecure + public src IP + risky src zone", "Points": cls.RISKY_INBOUND, "Enabled": "Yes"},
            {"Scoring_Category": "Risky_Outbound", "Description": "Insecure + public dst IP + risky dst zone", "Points": cls.RISKY_OUTBOUND, "Enabled": "Yes"},
            {"Scoring_Category": "Rule_Usage_Scoring", "Description": f"Rule usage scoring (Unused={cls.RULE_USAGE_UNUSED}, Partially Used={cls.RULE_USAGE_PARTIALLY_USED}, Used={cls.RULE_USAGE_USED})", "Points": cls.RULE_USAGE_UNUSED, "Enabled": "Yes"},
            {"Scoring_Category": "Rule_Usage_Description_Scoring", "Description": f"Rule usage description scoring ({cls.RULE_USAGE_DESCRIPTION_NO_TICKET} points if no INC/CHG/RITM/TASK, {cls.RULE_USAGE_DESCRIPTION_HAS_TICKET} points if contains ticket)", "Points": cls.RULE_USAGE_DESCRIPTION_NO_TICKET, "Enabled": "Yes"},
            {"Scoring_Category": "Source_User_Scoring", "Description": f"Source User scoring ({cls.SOURCE_USER_PENALTY} points if not [Disabled]/any, {cls.SOURCE_USER_SAFE} points otherwise)", "Points": cls.SOURCE_USER_PENALTY, "Enabled": "Yes"},
            {"Scoring_Category": "Profile_Scoring", "Description": f"Profile scoring (none/blank={cls.PROFILE_NONE_OR_BLANK}, other={cls.PROFILE_OTHER})", "Points": cls.PROFILE_NONE_OR_BLANK, "Enabled": "Yes"},
            {"Scoring_Category": "Migrate_Insecure", "Description": "Any insecure service port maps to App-ID (Applicatin ID sheet)", "Points": cls.MIGRATE_INSECURE, "Enabled": "Yes"},
            {"Scoring_Category": "Migrate_Other_Ports", "Description": "Non-insecure service ports found in Application ID catalog that map to App in rule", "Points": cls.MIGRATE_OTHER_PORTS, "Enabled": "Yes"},
            {"Scoring_Category": "Options_Scoring", "Description": f"Options scoring (none/blank={cls.OPTIONS_NONE_OR_BLANK}, other={cls.OPTIONS_OTHER})", "Points": cls.OPTIONS_NONE_OR_BLANK, "Enabled": "Yes"},
        ]


# ----------------------------
# Scoring config (points inline) - Backward compatibility
# ----------------------------
SCORING_WEIGHTS: Dict[str, int] = ScoringConfig.get_weights_dict()

def create_scoring_config_sheet(input_path: str) -> bool:
    """Create a Scoring_Config sheet if it doesn't exist. Returns True if successful."""
    try:
        # Check if config sheet already exists
        pd.read_excel(input_path, sheet_name="Scoring_Config")
        print(f"Scoring_Config sheet already exists in {input_path}")
        return True
    except:
        pass  # Config sheet doesn't exist, create it
    
    try:
        print(f"Creating Scoring_Config sheet in {input_path}...")
        
        # Read all existing sheets
        excel_file = pd.ExcelFile(input_path)
        all_sheets = {}
        
        # Read each existing sheet
        for sheet_name in excel_file.sheet_names:
            print(f"Reading existing sheet: {sheet_name}")
            all_sheets[sheet_name] = pd.read_excel(input_path, sheet_name=sheet_name, dtype=str).fillna("")
        
        # Create scoring configuration data using centralized ScoringConfig
        config_data = ScoringConfig.get_config_rows()
        
        config_df = pd.DataFrame(config_data)
        all_sheets["Scoring_Config"] = config_df
        print("Added Scoring_Config sheet with default configuration")
        
        # Write all sheets back to the file
        with pd.ExcelWriter(input_path, engine="xlsxwriter") as writer:
            for sheet_name, df in all_sheets.items():
                print(f"Writing sheet: {sheet_name}")
                df.to_excel(writer, sheet_name=sheet_name, index=False)
        
        print(f"✅ Successfully created Scoring_Config sheet in {input_path}")
        print("📋 You can now edit the 'Enabled' column to control which categories award points")
        return True
                
    except Exception as e:
        print(f"❌ Error creating Scoring_Config sheet: {e}")
        return False

def _create_scoring_config_sheet(input_path: str) -> None:
    """Internal function to create Scoring_Config sheet (used by main scoring function)."""
    create_scoring_config_sheet(input_path)

def _read_scoring_config(input_path: str) -> Dict[str, dict]:
    """Read scoring configuration from a separate Scoring_Config sheet if it exists."""
    try:
        config_df = pd.read_excel(input_path, sheet_name="Scoring_Config", dtype=str).fillna("")
        if config_df.empty:
            return {}
        
        # Create a mapping of scoring category to config (enabled status and points)
        config = {}
        for _, row in config_df.iterrows():
            category = str(row.get("Scoring_Category", "")).strip()
            enabled = str(row.get("Enabled", "")).strip().lower()
            points = str(row.get("Points", "")).strip()
            
            if category:
                # Parse points (default to 0 if invalid)
                try:
                    points_value = int(points) if points else 0
                except ValueError:
                    points_value = 0
                
                # Store both enabled status and points
                config[category] = {
                    "enabled": enabled in ["yes", "y", "true", "1"],
                    "points": points_value
                }
                
        return config
    except Exception:
        # If no config found, return empty dict (use default weights)
        return {}

def _get_scoring_weights(input_path: str, output_path: str = None) -> Dict[str, int]:
    """Get scoring weights, potentially modified by config sheet."""
    weights = SCORING_WEIGHTS.copy()
    
    # Special categories that use calculated points directly (not weights)
    # These columns have variable point amounts (e.g., Rule_Usage_Scoring can be 5, 2, or 0)
    # So they use their calculated points and are NOT replaced by Excel formulas
    special_categories = ["Rule_Usage_Scoring", "Profile_Scoring", "Options_Scoring"]
    
    # First try to read config from input file
    config = _read_scoring_config(input_path)
    
    # If no config in input file, try output file (for re-scoring with custom config)
    if not config and output_path:
        config = _read_scoring_config(output_path)
    
    # If config exists, use config values for enabled categories
    if config:
        filtered_weights = {}
        for category, default_points in weights.items():
            # Skip special categories - they use calculated points directly
            if category in special_categories:
                continue
                
            if category in config:
                category_config = config[category]
                if category_config["enabled"]:
                    # Use points from config if specified, otherwise use default
                    config_points = category_config["points"]
                    final_points = config_points if config_points > 0 else default_points
                    filtered_weights[category] = final_points
            else:
                # Category not in config, use default
                filtered_weights[category] = default_points
        return filtered_weights
    
    return weights

def _cell(flag: bool, pts_if_true: int) -> str:
    return f"{'True' if flag else 'False'},{pts_if_true if flag else 0}"

def _evaluate_row(r: dict, sep: str, weights: Dict[str, int] = None) -> dict:
    # tokens
    src_raw = r.get("Source Address", "")
    src = _split_tokens(src_raw, sep)
    dst = _split_tokens(r.get("Destination Address", ""), sep)
    app = _split_tokens(r.get("Application", ""), sep)
    svc = _split_tokens(r.get("Service", ""), sep)
    act = str(r.get("Action", "")).strip().lower()
    src_zone = _split_tokens(r.get("Source Zone", ""), sep) if "Source Zone" in r else []
    dst_zone = _split_tokens(r.get("Destination Zone", ""), sep) if "Destination Zone" in r else []

    # ---- scope/exposure
    src_is_any = _any_is_any(src)
    dst_is_any = _any_is_any(dst)
    srcz_is_any = _any_is_any(src_zone)
    dstz_is_any = _any_is_any(dst_zone)
    src_buckets = [_cidr_bucket_v4(t) for t in src]
    dst_buckets = [_cidr_bucket_v4(t) for t in dst]
    src_le16 = any(b == "le16" for b in src_buckets)
    src_17_22 = (not src_le16) and any(b == "17_22" for b in src_buckets)
    dst_le16 = any(b == "le16" for b in dst_buckets)
    dst_17_22 = (not dst_le16) and any(b == "17_22" for b in dst_buckets)

    # ---- service/app breadth (OR) + helpers
    svc_total, svc_any, svc_gt1k = _port_metrics(svc)
    app_total, app_any, app_gt1k = _port_metrics(app)
    svc_or = bool(svc_any or svc_gt1k)
    app_or = bool(app_any or app_gt1k)

    # ---- insecure scoring
    insecure_hit = _insecure_match(svc)
    # Insecure gets points if: insecure ports detected AND NOT "any" service
    # This includes both single insecure ports and broad services with insecure ports
    # Note: insecure_points is not used directly, but kept for reference
    insecure_points = ScoringConfig.SERVICE_INSECURE_MATCH if insecure_hit and not svc_any else 0

    # ---- risky traffic scoring
    # Risky Inbound: (Insecure + Public Source IP + Risky Source Zone)
    src_public = _is_public_ip(src)
    src_risky_zone = _is_risky_zone(src_zone)
    risky_inbound = (insecure_hit and src_public and src_risky_zone)
    
    # Risky Outbound: (Insecure + Public Destination IP + Risky Destination Zone)  
    dst_public = _is_public_ip(dst)
    dst_risky_zone = _is_risky_zone(dst_zone)
    risky_outbound = (insecure_hit and dst_public and dst_risky_zone)

    # ---- rule usage and configuration scoring
    # Rule Usage Rule Usage scoring
    rule_usage = str(r.get("Rule Usage Rule Usage", "")).strip()
    if not rule_usage or rule_usage.lower() == "unused":
        rule_usage_points = ScoringConfig.RULE_USAGE_UNUSED
    elif rule_usage.lower() == "partially used":
        rule_usage_points = ScoringConfig.RULE_USAGE_PARTIALLY_USED
    elif rule_usage.lower() == "used":
        rule_usage_points = ScoringConfig.RULE_USAGE_USED
    else:
        rule_usage_points = ScoringConfig.RULE_USAGE_UNUSED  # Default to unused if unknown value
    
    # Profile scoring
    profile = str(r.get("Profile", "")).strip().lower()
    profile_points = ScoringConfig.PROFILE_NONE_OR_BLANK if profile in ["none", ""] else ScoringConfig.PROFILE_OTHER
    
    # Options scoring
    options = str(r.get("Options", "")).strip().lower()
    # Award points for "none", empty string, or NaN-like values
    # Also handle case variations and common null representations
    options_points = ScoringConfig.OPTIONS_NONE_OR_BLANK if options in ["none", "", "nan", "null", "n/a", "na"] else ScoringConfig.OPTIONS_OTHER
    
    # Rule Usage Description scoring
    rule_usage_desc = str(r.get("Rule Usage Description", "")).strip().upper()
    # Check for ticket keywords (INC, CHG, RITM, TASK)
    ticket_keywords = ["INC", "CHG", "RITM", "TASK"]
    rule_usage_desc_points = ScoringConfig.RULE_USAGE_DESCRIPTION_HAS_TICKET if any(keyword in rule_usage_desc for keyword in ticket_keywords) else ScoringConfig.RULE_USAGE_DESCRIPTION_NO_TICKET
    
    # Source User scoring - normalize column name to handle both "Source User" and "Source_User"
    source_user_key = _resolve(pd.DataFrame([r]), "Source User")
    if source_user_key is None:
        source_user_key = "Source User"  # fallback
    source_user_raw = r.get(source_user_key, "")
    source_user = str(source_user_raw).strip()
    
    # Check if Source User contains "[Disabled]" (case-sensitive) or "any" or empty
    # If found, award 0 points; otherwise award -10 points (deducts from total)
    source_user_lower = source_user.strip().lower()
    
    # Check for "[Disabled]" (case-sensitive) - anywhere in the string
    has_disabled = "[Disabled]" in source_user
    
    # Check for "any" (case-insensitive) - can be standalone word or after semicolon
    # Allow: "any", "any;", "; any", "[Disabled]  any", etc.
    has_any = False
    if source_user_lower == "any":
        has_any = True
    elif source_user_lower:
        # Check if "any" appears as a standalone word (not part of "company" or similar)
        # Use pre-compiled regex pattern for performance
        if _ANY_WORD_PATTERN.search(source_user_lower):
            has_any = True
    
    # Check if empty
    is_empty = source_user == ""
    
    # If contains [Disabled] or "any" or blank → safe (FALSE,bridge 0 points)
    # Otherwise → risky (TRUE, get penalty points from config)
    is_unsafe_source_user = not (has_disabled or has_any or is_empty)

    # ---- override
    is_deny = act in ("deny", "drop")

    # ---- inline cells
    out: Dict[str, object] = {}
    # scoring columns (embed points) - use dynamic weights
    scoring_weights = weights or SCORING_WEIGHTS
    # Get penalty points from config (default from ScoringConfig, but can be changed)
    penalty_points = scoring_weights.get("Source_User_Scoring", ScoringConfig.SOURCE_USER_PENALTY) if is_unsafe_source_user else ScoringConfig.SOURCE_USER_SAFE
    
    out["Src_IsAny"]                  = _cell(src_is_any, scoring_weights.get("Src_IsAny", ScoringConfig.SRC_IS_ANY))
    out["Src_CIDR_Le_16"]             = _cell(src_le16,   scoring_weights.get("Src_CIDR_Le_16", ScoringConfig.SRC_CIDR_LE_16))
    out["Src_CIDR_17_22"]             = _cell(src_17_22,   scoring_weights.get("Src_CIDR_17_22", ScoringConfig.SRC_CIDR_17_22))
    out["Dst_IsAny"]                  = _cell(dst_is_any, scoring_weights.get("Dst_IsAny", ScoringConfig.DST_IS_ANY))
    out["Dst_CIDR_Le_16"]             = _cell(dst_le16,   scoring_weights.get("Dst_CIDR_Le_16", ScoringConfig.DST_CIDR_LE_16))
    out["Dst_CIDR_17_22"]             = _cell(dst_17_22,   scoring_weights.get("Dst_CIDR_17_22", ScoringConfig.DST_CIDR_17_22))
    out["SrcZone_IsAny"]              = _cell(srcz_is_any, scoring_weights.get("SrcZone_IsAny", ScoringConfig.SRC_ZONE_IS_ANY))
    out["DstZone_IsAny"]              = _cell(dstz_is_any, scoring_weights.get("DstZone_IsAny", ScoringConfig.DST_ZONE_IS_ANY))
    out["Service_Any_OR_RangeGt1000"] = _cell(svc_or,     scoring_weights.get("Service_Any_OR_RangeGt1000", ScoringConfig.SERVICE_ANY_OR_RANGE_GT_1000))
    out["App_Any_OR_RangeGt1000"]     = _cell(app_or,     scoring_weights.get("App_Any_OR_RangeGt1000", ScoringConfig.APP_ANY_OR_RANGE_GT_1000))

    # Insecure scoring: points based on broad service + insecure detection
    out["Service_Insecure_Match"]     = _cell(insecure_hit, scoring_weights.get("Service_Insecure_Match", ScoringConfig.SERVICE_INSECURE_MATCH))
    
    # Risky traffic scoring
    out["Risky_Inbound"]              = _cell(risky_inbound, scoring_weights.get("Risky_Inbound", ScoringConfig.RISKY_INBOUND) if risky_inbound else 0)
    out["Risky_Outbound"]             = _cell(risky_outbound, scoring_weights.get("Risky_Outbound", ScoringConfig.RISKY_OUTBOUND) if risky_outbound else 0)
    
    # Rule usage and configuration scoring - use calculated points directly
    out["Rule_Usage_Scoring"]              = _cell(rule_usage_points > 0, rule_usage_points)
    out["Rule_Usage_Description_Scoring"]  = _cell(rule_usage_desc_points > 0, rule_usage_desc_points)
    out["Source_User_Scoring"]             = _cell(is_unsafe_source_user, penalty_points)
    out["Profile_Scoring"]                 = _cell(profile_points > 0, profile_points)
    out["Options_Scoring"]                 = _cell(options_points > 0, options_points)

    # diagnostics (0-point helpers)
    out["Service_IsAny"]              = _cell(svc_any, 0)
    out["Service_UniquePorts_Total"]  = int(svc_total)
    out["Service_RangeGt1000"]        = _cell(svc_gt1k, 0)
    out["App_IsAny"]                  = _cell(app_any, 0)
    out["App_UniquePorts_Total"]      = int(app_total)
    out["App_RangeGt1000"]            = _cell(app_gt1k, 0)
    out["Action_IsDenyOrDrop"]        = _cell(is_deny, 0)

    # ---- score
    if is_deny:
        out["Score_Total"] = 0
    else:
        # Use provided weights or default weights
        scoring_weights = weights or SCORING_WEIGHTS
        total = 0
        
        # Calculate total from all scoring categories (only columns that contribute to score)
        # Exclude diagnostic columns that are not in SCORING_WEIGHTS
        for key in scoring_weights.keys():
            # Map scoring weight keys to actual column names
            col_name = key
            if key == "Migrate_Other_Ports":
                col_name = "Migrate_Other_ports_Score"  # This column name is created later
            elif key == "Migrate_Insecure":
                col_name = "Migrate_Insecure"
            
            # Only process if column exists in output
            if col_name in out:
                val = str(out.get(col_name, "False,0"))
                try:
                    # Handle "True,points" or "False,0" format
                    if "," in val:
                        pts = int(val.split(",")[1])
                    else:
                        # If it's already an integer (shouldn't happen for scoring columns, but handle gracefully)
                        pts = int(val) if val.isdigit() else 0
                except (ValueError, IndexError):
                    pts = 0
                total += pts
        
        out["Score_Total"] = int(total)

    return out
def _augment_migrate_insecure(scored_df: pd.DataFrame, all_sheets: Dict[str, pd.DataFrame], sep: str, input_path: str = "", output_path: str = "", progress_callback: Optional[callable] = None) -> pd.DataFrame:
    """
    - Find 'Applicatin ID' (or similar) sheet inside the SAME workbook
    - Parse 'Standard Ports' (semicolon-aware)
    - For each rule in scored_df:
        * 'Migrate Insecure_AppID': semicolon-joined app names for any matched insecure port
        * 'Migrate_Insecure': scoring cell "True,10" or "False,0" (+10 once per rule if any match)
    """
    logging.info(f"🚀 Starting Migrate Insecure_AppID augmentation")
    logging.info(f"   scored_df shape: {scored_df.shape}")
    logging.info(f"   all_sheets keys: {list(all_sheets.keys())}")
    print(f"🚀 _augment_migrate_insecure called!")
    print(f"   scored_df shape: {scored_df.shape}")
    print(f"   all_sheets keys: {list(all_sheets.keys())}")
    
    if progress_callback:
        progress_callback("🔍 Tool: Searching for Application ID sheet", 65)
    
    # 1) Locate catalog sheet (tolerate typos)
    print(f"🔍 Searching for Application ID sheet in available sheets: {list(all_sheets.keys())}")
    catalog_sheet = None
    for s in all_sheets.keys():
        ns = _norm_col(s)
        if ns in {_norm_col("Applicatin ID"), _norm_col("Application ID"), _norm_col("Applicaiton ID")}:
            catalog_sheet = s
            print(f"✅ Found Application ID sheet: '{s}' (normalized: '{ns}')")
            break
    if catalog_sheet is None:
        for s in all_sheets.keys():
            ns = _norm_col(s)
            if "app" in ns and "id" in ns:
                catalog_sheet = s
                print(f"✅ Found Application ID sheet (fuzzy match): '{s}' (normalized: '{ns}')")
                break

    # If no catalog sheet, add empty columns and return
    if catalog_sheet is None:
        logging.warning(f"⚠️  No Application ID sheet found. Available sheets: {list(all_sheets.keys())}")
        print(f"⚠️  No Application ID sheet found. Available sheets: {list(all_sheets.keys())}")
        print(f"   Adding empty Migrate Insecure_AppID columns.")
        if progress_callback:
            progress_callback("⚠️  Tool: No Application ID sheet found, skipping migration analysis", 67)
        scored_df["Migrate Insecure_AppID"] = ""
        scored_df["Migrate_Insecure"] = "False,0"
        return scored_df

    catalog_df = all_sheets[catalog_sheet].copy()

    # 2) Resolve required columns
    name_col  = _resolve(catalog_df, "Application") or _resolve(catalog_df, "Application Name") \
                or _resolve(catalog_df, "Name") or _resolve(catalog_df, "Technology")
    ports_col = _resolve(catalog_df, "Standard Ports") or _resolve(catalog_df, "Ports") \
                or _resolve(catalog_df, "Default Ports")

    if not name_col or not ports_col:
        scored_df["Migrate Insecure_AppID"] = ""
        scored_df["Migrate_Insecure"] = "False,0"
        return scored_df

    catalog_df = catalog_df.rename(columns={name_col: "Application", ports_col: "Standard Ports"})[
        ["Application", "Standard Ports"]
    ]

    # 3) Build index and constants
    if progress_callback:
        progress_callback(f"📋 Tool: Building port-to-apps index from {len(catalog_df)} catalog entries", 66)
    logging.info(f"📋 Building port-to-apps index from {len(catalog_df)} catalog entries...")
    print(f"📋 Building port-to-apps index from {len(catalog_df)} catalog entries...")
    port_to_apps = _build_port_to_apps_from_catalog(catalog_df)
    insecure = _insecure_port_set()
    logging.info(f"✅ Built index with {len(port_to_apps)} ports mapped to applications")
    
    # Build a lookup of app names to their total port count
    app_port_count = {}
    for _, row in catalog_df.iterrows():
        app = str(row["Application"]).strip()
        std_ports_str = str(row["Standard Ports"])
        app_all_ports = _parse_ports_blob(std_ports_str)
        app_port_count[app] = len(app_all_ports)
    
    # Debug: Show what ports map to apps
    insecure_in_catalog = {p: apps for p, apps in port_to_apps.items() if p in insecure}
    if insecure_in_catalog:
        print(f"🔐 Found {len(insecure_in_catalog)} insecure ports with apps in catalog:")
        for p in sorted(insecure_in_catalog.keys())[:15]:  # Show first 10
            print(f"   Port {p}: {', '.join(list(insecure_in_catalog[p])[:3])}{'...' if len(insecure_in_catalog[p]) > 3 else ''}")
    else:
        print(f"⚠️  No insecure ports found in catalog!")

    svc_col = _resolve(scored_df, "Service") or "Service"
    # Resolve Application column - try Application_original FIRST, then Application
    app_col = _resolve(scored_df, "Application_original") or _resolve(scored_df, "Application") or "Application"
    if progress_callback:
        progress_callback(f"🔍 Tool: Processing {len(scored_df)} rules for Migrate Insecure_AppID", 67)
    logging.info(f"🔍 Processing {len(scored_df)} rules for Migrate Insecure_AppID scoring...")
    print(f"🔍 Processing {len(scored_df)} rules for Migrate Insecure_AppID scoring...")
    print(f"   Using Service column: '{svc_col}', Application column: '{app_col}'")

    # 4) Compute per-row values
    migrate_text: List[str] = []
    migrate_score: List[str] = []

    pts = ScoringConfig.MIGRATE_INSECURE

    total_migrate_rows = len(scored_df)
    for idx, (_, row) in enumerate(scored_df.iterrows()):
        if progress_callback and idx % 500 == 0 and idx > 0:
            progress = 67 + int((idx / total_migrate_rows) * 3)
            progress_callback(f"🔍 Tool: Analyzing Migrate Insecure {idx}/{total_migrate_rows}", progress)
        # Split service into tokens using your existing splitter
        svc_tokens = _split_tokens(row.get(svc_col, ""), sep)
        
        # Get Application column values - check Application_original FIRST, then Application
        app_values = []
        if "Application_original" in row and row.get("Application_original"):
            app_values.extend(_split_tokens(str(row.get("Application_original", "")), sep))
        elif "Application" in row and row.get("Application"):
            app_values.extend(_split_tokens(str(row.get("Application", "")), sep))
        
        # Normalize app names for comparison (case-insensitive)
        app_values_normalized = {_norm_col(a.strip()) for a in app_values if a and a.strip()}
        
        # Pull discrete ports from tokens and keep only insecure ports
        ports: Set[int] = set()
        for tok in svc_tokens:
            for p in _parse_ports_blob(tok):
                if p in insecure:
                    ports.add(p)

        # Gather matching apps, but filter to only show apps where:
        # 1. The insecure port is PRIMARY (app has exactly 1 port)
        # 2. The app is already present in the rule's Application column (Application_original or Application)
        apps: Set[str] = set()
        for p in ports:
            for app in port_to_apps.get(p, set()):
                # Check if this app has exactly 1 total port (insecure port is the only port)
                if app_port_count.get(app, 999) == 1:
                    # Verify the app is in the rule's Application column (Application_original checked first)
                    app_normalized = _norm_col(app.strip())
                    if app_normalized in app_values_normalized:
                        apps.add(app)
        
        # Text column: If multiple apps match, show only ONE (alphabetically first for consistency)
        apps_list = sorted(apps)
        if apps_list:
            # Show only the first app to avoid showing redundant/duplicate apps
            apps_list = [apps_list[0]]
        
        migrate_text.append("; ".join(apps_list) if apps_list else "")
        migrate_score.append(f"{'True' if apps_list else 'False'},{pts if apps_list else 0}")

    scored_df["Migrate Insecure_AppID"] = migrate_text
    scored_df["Migrate_Insecure"] = migrate_score
    
    # Count successful matches
    matches = sum(1 for t in migrate_text if t)
    logging.info(f"✅ Migrate Insecure_AppID complete: {matches}/{len(scored_df)} rules have matching apps")
    print(f"✅ Migrate Insecure_AppID complete: {matches}/{len(scored_df)} rules have matching apps")
    
    if progress_callback:
        progress_callback(f"🔍 Tool: Processing {len(scored_df)} rules for Migrate_Other_ports", 70)
    
    # NEW: Process non-insecure ports from Service column that are in Application ID catalog
    migrate_other_ports_text: List[str] = []
    migrate_other_ports_score: List[str] = []
    pts_other = ScoringConfig.MIGRATE_OTHER_PORTS
    
    logging.info(f"🔍 Processing {len(scored_df)} rules for Migrate_Other_ports (non-insecure ports in APP ID)...")
    print(f"🔍 Processing {len(scored_df)} rules for Migrate_Other_ports (non-insecure ports in APP ID)...")
    print(f"   ⚡ Optimizing: Building reverse lookup indexes...")
    
    # OPTIMIZATION: Pre-build indexes for faster lookups (done once, not per row)
    non_insecure_catalog_ports = {p for p in port_to_apps.keys() if p not in insecure}
    port_to_normalized_apps = {}
    for port, apps in port_to_apps.items():
        if port in non_insecure_catalog_ports:
            port_to_normalized_apps[port] = {_norm_col(app.strip()) for app in apps}
    
    print(f"   📊 Found {len(non_insecure_catalog_ports)} non-insecure ports in catalog")
    
    # OPTIMIZATION: Use itertuples() instead of iterrows() - 10-100x faster
    app_col_original = _resolve(scored_df, "Application_original") or "Application_original"
    app_col = _resolve(scored_df, "Application") or "Application"
    total_rows = len(scored_df)
    
    # Helper function to convert column name to itertuples format (spaces -> underscores)
    def _itertuples_name(col_name: str) -> str:
        """Convert DataFrame column name to itertuples() attribute name format."""
        return col_name.replace(" ", "_")
    
    for row_idx, row in enumerate(scored_df.itertuples(index=False)):
        if row_idx % 500 == 0 and row_idx > 0:
            print(f"   ⏳ Processed {row_idx}/{total_rows} rules ({int(row_idx/total_rows*100)}%)...")
        
        # Fast column access - convert column names to itertuples format
        svc_val = getattr(row, _itertuples_name(svc_col), "") if hasattr(row, _itertuples_name(svc_col)) else ""
        app_val_original = getattr(row, _itertuples_name(app_col_original), "") if hasattr(row, _itertuples_name(app_col_original)) else ""
        app_val = getattr(row, _itertuples_name(app_col), "") if hasattr(row, _itertuples_name(app_col)) else ""
        
        # Split service into tokens to extract ports
        svc_tokens = _split_tokens(svc_val, sep)
        
        # Get Application column values - check Application_original FIRST, then Application
        app_values = []
        if app_val_original:
            app_values.extend(_split_tokens(str(app_val_original), sep))
        elif app_val:
            app_values.extend(_split_tokens(str(app_val), sep))
        
        # Normalize app names for comparison (case-insensitive)
        app_values_normalized = {_norm_col(a.strip()) for a in app_values if a and a.strip()}
        
        if not app_values_normalized:
            migrate_other_ports_text.append("")
            migrate_other_ports_score.append("False,0")
            continue
        
        # Pull ALL ports from Service column tokens
        all_ports_from_service: Set[int] = set()
        for tok in svc_tokens:
            for p in _parse_ports_blob(tok):
                if 1 <= p <= 65535:  # Valid port range
                    all_ports_from_service.add(p)
        
        # OPTIMIZATION: Quick filter using set intersection (very fast!)
        candidate_ports = all_ports_from_service & non_insecure_catalog_ports
        
        if not candidate_ports:
            migrate_other_ports_text.append("")
            migrate_other_ports_score.append("False,0")
            continue
        
        # OPTIMIZATION: Use set intersection for fast matching (O(n) instead of O(n*m))
        matching_ports: List[int] = []
        for p in sorted(candidate_ports):
            port_normalized_apps = port_to_normalized_apps.get(p, set())
            if port_normalized_apps & app_values_normalized:  # Set intersection - very fast!
                matching_ports.append(p)
        
        # List the matching ports
        if matching_ports:
            ports_str = "; ".join(str(p) for p in sorted(matching_ports))
            migrate_other_ports_text.append(ports_str)
            migrate_other_ports_score.append(f"True,{pts_other}")
        else:
            migrate_other_ports_text.append("")
            migrate_other_ports_score.append("False,0")
    
    scored_df["Migrate_Other_ports"] = migrate_other_ports_text
    scored_df["Migrate_Other_ports_Score"] = migrate_other_ports_score
    
    # Count successful matches
    other_matches = sum(1 for t in migrate_other_ports_text if t)
    logging.info(f"✅ Migrate_Other_ports complete: {other_matches}/{len(scored_df)} rules have matching ports (non-insecure)")
    print(f"✅ Migrate_Other_ports complete: {other_matches}/{len(scored_df)} rules have matching ports (non-insecure)")
    
    if progress_callback:
        progress_callback("🔢 Tool: Recalculating Score_Total with migration scores", 73)
    logging.info("🔢 Recalculating Score_Total to include Migrate_Insecure and Migrate_Other_ports_Score...")
    
    # Recalculate Score_Total to include Migrate_Insecure and Migrate_Other_ports_Score
    # Get scoring weights to check which columns contribute to total
    scoring_weights = _get_scoring_weights(input_path, output_path) if input_path else SCORING_WEIGHTS
    
    # Recalculate Score_Total for each row
    for idx in scored_df.index:
        # Skip if Action is deny/drop (Score_Total should be 0)
        action_col = _resolve(scored_df, "Action") or "Action"
        action_val = str(scored_df.loc[idx, action_col]).strip().lower()
        if action_val in ("deny", "drop"):
            scored_df.loc[idx, "Score_Total"] = 0
            continue
        
        # Calculate total from all scoring columns (only columns in SCORING_WEIGHTS)
        total = 0
        for key in scoring_weights.keys():
            # Map scoring weight keys to actual column names
            col_name = None
            if key == "Migrate_Other_Ports":
                col_name = "Migrate_Other_ports_Score"
            elif key == "Migrate_Insecure":
                col_name = "Migrate_Insecure"
            else:
                col_name = key
            
            # Check if column exists and get value
            if col_name in scored_df.columns:
                val = str(scored_df.loc[idx, col_name])
                try:
                    # Extract points from "True,points" or "False,0" format
                    if "," in val:
                        pts = int(val.split(",")[1])
                    else:
                        # If it's already an integer (shouldn't happen for scoring columns, but handle gracefully)
                        pts = int(val) if val.isdigit() else 0
                except (ValueError, IndexError):
                    pts = 0
                total += pts
            elif key in scored_df.columns:
                # Fallback to direct key name
                val = str(scored_df.loc[idx, key])
                try:
                    if "," in val:
                        pts = int(val.split(",")[1])
                    else:
                        # If it's already an integer (shouldn't happen for scoring columns, but handle gracefully)
                        pts = int(val) if val.isdigit() else 0
                except (ValueError, IndexError):
                    pts = 0
                total += pts
        
        scored_df.loc[idx, "Score_Total"] = int(total)
    
    logging.info(f"✅ Recalculated Score_Total for {len(scored_df)} rules")
    print(f"✅ Recalculated Score_Total to include Migrate_Insecure and Migrate_Other_ports_Score")
    
    return scored_df

# ----------------------------
# IO and pipeline
# ----------------------------
def _read_excel(cfg: dict) -> pd.DataFrame:
    path = Path(cfg["input_path"])
    sheet = cfg.get("sheet")
    if sheet is not None:
        try:
            return pd.read_excel(path, sheet_name=sheet, dtype=str).fillna("")
        except Exception:
            pass
    for guess in SHEET_GUESS:
        try:
            return pd.read_excel(path, sheet_name=guess, dtype=str).fillna("")
        except Exception:
            continue
    raise ValueError(f"Could not read sheet from: {path}")

def _read_all_sheets(cfg: dict) -> dict:
    """Read all sheets from the input Excel file"""
    path = Path(cfg["input_path"])
    all_sheets = {}
    
    try:
        # Read all sheet names
        xl_file = pd.ExcelFile(path)
        sheet_names = xl_file.sheet_names
        
        # Read each sheet
        for sheet_name in sheet_names:
            try:
                df = pd.read_excel(path, sheet_name=sheet_name, dtype=str).fillna("")
                all_sheets[sheet_name] = df
            except Exception as e:
                print(f"Warning: Could not read sheet '{sheet_name}': {e}")
                continue
                
        return all_sheets
    except Exception as e:
        raise ValueError(f"Could not read Excel file: {path}, error: {e}")

def _score_df(payload: dict) -> pd.DataFrame:
    df: pd.DataFrame = payload["df"]
    sep: str = payload["sep"]
    input_path: str = payload.get("input_path", "")
    output_path: str = payload.get("output_path", "")
    progress_callback = payload.get("progress_callback")

    def pick(col): return _resolve(df, col) or col
    need = ["Source Address","Destination Address","Application","Service","Action"]
    miss = [c for c in need if _resolve(df, c) is None]
    if miss:
        raise ValueError(f"Missing required columns: {', '.join(miss)}")

    if progress_callback:
        progress_callback("⚙️  Tool: Loading scoring configuration from Scoring_Config sheet", 5)
    logging.info("⚙️  Loading scoring configuration...")

    # Get dynamic scoring weights (check both input and output files)
    weights = _get_scoring_weights(input_path, output_path)
    logging.info(f"✅ Loaded {len(weights)} scoring categories from configuration")

    if progress_callback:
        progress_callback("📊 Tool: Preparing rule data and resolving columns", 10)
    logging.info("📊 Preparing rule data and resolving columns...")

    # OPTIMIZATION 1: Pre-resolve all columns ONCE instead of per row
    col_map = {
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
    
    # OPTIMIZATION 2: Use itertuples() instead of iterrows() - 10-100x faster
    total_rows = len(df)
    
    # Build column index map (column name -> position in DataFrame)
    # This is more reliable than trying to guess itertuples attribute names
    col_index_map = {col: idx for idx, col in enumerate(df.columns)}
    
    # Helper function to get value from row using column index
    def _get_col_value(row, col_name: str) -> str:
        """Get column value from itertuples row using column index (most reliable method)."""
        if col_name in col_index_map:
            col_idx = col_index_map[col_name]
            # Access by index (itertuples rows support indexing)
            try:
                return str(row[col_idx]) if row[col_idx] is not None else ""
            except (IndexError, TypeError):
                return ""
        return ""
    
    # OPTIMIZATION 3: Prepare row data efficiently
    rows = []
    for row_idx, row in enumerate(df.itertuples(index=False)):
        # Use column index-based access (most reliable)
        source_addr_val = _get_col_value(row, col_map["Source Address"])
        
        rows.append({
            "Source Address": source_addr_val,
            "Destination Address": _get_col_value(row, col_map["Destination Address"]),
            "Application": _get_col_value(row, col_map["Application"]),
            "Service": _get_col_value(row, col_map["Service"]),
            "Action": _get_col_value(row, col_map["Action"]),
            "Source Zone": _get_col_value(row, col_map["Source Zone"]) if "Source Zone" in col_map else "",
            "Source User": _get_col_value(row, col_map["Source User"]) if "Source User" in col_map else "",
            "Destination Zone": _get_col_value(row, col_map["Destination Zone"]) if "Destination Zone" in col_map else "",
            "Rule Usage Rule Usage": _get_col_value(row, col_map["Rule Usage Rule Usage"]) if "Rule Usage Rule Usage" in col_map else "",
            "Rule Usage Description": _get_col_value(row, col_map["Rule Usage Description"]) if "Rule Usage Description" in col_map else "",
            "Profile": _get_col_value(row, col_map["Profile"]) if "Profile" in col_map else "",
            "Options": _get_col_value(row, col_map["Options"]) if "Options" in col_map else "",
        })

    if progress_callback:
        progress_callback(f"🔢 Tool: Calculating scores for {total_rows} rules", 20)
    logging.info(f"🔢 Starting score calculation for {total_rows} rules...")

    # OPTIMIZATION 4: Parallel processing for large datasets
    use_parallel = payload.get("use_parallel", False)  # Default False for compatibility
    max_workers = payload.get("max_workers", None)
    
    if use_parallel and total_rows > 500:
        # Use multiprocessing for large datasets
        num_workers = max_workers or min(mp.cpu_count(), 8)
        logging.info(f"🚀 Using parallel processing with {num_workers} workers for {total_rows} rows")
        print(f"🚀 Using parallel processing with {num_workers} workers for {total_rows} rows")
        
        def process_batch(batch):
            return [_evaluate_row(r, sep, weights) for r in batch]
        
        chunk_size = max(100, total_rows // (num_workers * 4))
        chunks = [rows[i:i+chunk_size] for i in range(0, total_rows, chunk_size)]
        logging.info(f"📦 Split into {len(chunks)} chunks of ~{chunk_size} rules each")
        
        evals = []
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(process_batch, chunk) for chunk in chunks]
            completed = 0
            for future in futures:
                batch_results = future.result()
                evals.extend(batch_results)
                completed += len(batch_results)
                if progress_callback:
                    progress = 20 + int((completed / total_rows) * 70)
                    progress_callback(f"🔢 Tool: Processing rules {completed}/{total_rows} (parallel)", progress)
                if completed % 500 == 0 or completed == total_rows:
                    logging.info(f"📊 Progress: {completed}/{total_rows} rules scored ({int(completed/total_rows*100)}%)")
    else:
        # Sequential processing with progress updates
        logging.info(f"🔄 Using sequential processing for {total_rows} rules")
        evals = []
        for i, r in enumerate(rows):
            if progress_callback and i % 100 == 0:
                progress = 20 + int((i / total_rows) * 70)
                progress_callback(f"🔢 Tool: Processing rule {i+1}/{total_rows} (sequential)", progress)
            if i % 500 == 0 and i > 0:
                logging.info(f"📊 Progress: {i}/{total_rows} rules scored ({int(i/total_rows*100)}%)")
            evals.append(_evaluate_row(r, sep, weights))
    facts = pd.DataFrame(evals)
    logging.info(f"✅ Score calculation complete: {len(facts)} scoring columns generated")

    if progress_callback:
        progress_callback("🔗 Tool: Merging scored data with original rules", 60)
    logging.info("🔗 Merging scored data with original rules...")

    out = pd.concat([df.reset_index(drop=True), facts], axis=1)
    cols = [c for c in out.columns if c != "Score_Total"] + ["Score_Total"]
    logging.info(f"✅ Data merge complete: {len(out.columns)} total columns")
    return out.reindex(columns=cols)


def _apply_cell_formatting_after_formulas(ws, wb, df, headers, n_rows):
    """Apply cell formatting after formulas are written. Uses DataFrame values to determine formatting."""
    try:
        # Define scoring column patterns
        scoring_patterns = [
            "Src_", "Dst_", "SrcZone_", "DstZone_", "Service_", "App_", "Action_",
            "Risky_", "Rule_Usage_", "Profile_", "Options_", "Score_", "Risk_",
            "Service_UniquePorts_", "App_UniquePorts_", "Service_Range_", "App_Range_",
            "Migrate_"
        ]
        
        known_scoring_columns = [
            "Src_IsAny", "Src_CIDR_Le_16", "Src_CIDR_17_22", "Dst_IsAny", "Dst_CIDR_Le_16", "Dst_CIDR_17_22",
            "SrcZone_IsAny", "DstZone_IsAny", "Service_Any_OR_RangeGt1000", "App_Any_OR_RangeGt1000",
            "Service_Insecure_Match","Migrate_Insecure", "Migrate Insecure_AppID", "Migrate_Other_ports_Score", "Risky_Inbound", "Risky_Outbound", 
            "Rule_Usage_Scoring", "Rule_Usage_Description_Scoring", "Source_User_Scoring",
            "Profile_Scoring", "Options_Scoring", "Score_Total", "Risk_Level",
            "Service_RangeGt1000", "App_IsAny", "App_RangeGt1000", "Action_IsDenyOrDrop"
        ]
        
        def is_scoring_column(column_name):
            if column_name == "Service_IsAny":
                return False
            if column_name in known_scoring_columns:
                return True
            for pattern in scoring_patterns:
                if column_name.startswith(pattern):
                    return True
            return False
        
        # Create format objects for data cells
        true_cell_format = wb.add_format({
            'bg_color': '#4472C4',  # Medium blue
            'align': 'center',
            'valign': 'vcenter'
        })
        
        scoring_cell_format = wb.add_format({
            'align': 'center',
            'valign': 'vcenter'
        })
        
        original_cell_format = wb.add_format({
            'valign': 'vcenter'
        })
        
        # Apply formatting to data cells based on DataFrame values
        for row_idx in range(1, n_rows + 1):
            for col_idx, header in enumerate(headers):
                if col_idx >= len(df.columns):
                    continue
                    
                cell_value = str(df.iloc[row_idx - 1, col_idx])
                
                if is_scoring_column(header):
                    # For scoring columns, check if cell contains "True" and apply medium blue
                    if cell_value.strip().lower().startswith("true"):
                        # Use conditional formatting approach - set format on the cell
                        # Note: We can't directly format formula cells, but we can use conditional formatting
                        # For now, we'll format based on the original DataFrame value
                        try:
                            # Try to get the cell and apply format (this may not work for formulas)
                            # Instead, we'll use conditional formatting or format when writing
                            pass  # Formatting will be handled when writing formulas
                        except:
                            pass
                # Note: Actual formatting will be applied when writing formulas with format parameter
    except Exception as e:
        logging.warning(f"Could not apply cell formatting after formulas: {e}")

def _format_raw_data_columns(xw, df):
    """Apply formatting to distinguish original columns from scoring columns and format data cells"""
    try:
        # Get the Raw Data worksheet
        ws = xw.sheets["Raw Data"]
        wb = xw.book
        
        # Define scoring column patterns (created by scoring process) - these should be dark blue with white bold text
        scoring_patterns = [
            "Src_", "Dst_", "SrcZone_", "DstZone_", "Service_", "App_", "Action_",
            "Risky_", "Rule_Usage_", "Profile_", "Options_", "Score_", "Risk_",
            "Service_UniquePorts_", "App_UniquePorts_", "Service_Range_", "App_Range_",
            "Migrate_"  # For Migrate_Insecure and Migrate Insecure_AppID
        ]
        
        # Define known scoring columns (excluding Service_IsAny which should be hidden)
        known_scoring_columns = [
            "Src_IsAny", "Src_CIDR_Le_16", "Src_CIDR_17_22", "Dst_IsAny", "Dst_CIDR_Le_16", "Dst_CIDR_17_22",
            "SrcZone_IsAny", "DstZone_IsAny", "Service_Any_OR_RangeGt1000", "App_Any_OR_RangeGt1000",
            "Service_Insecure_Match","Migrate_Insecure", "Migrate Insecure_AppID", "Migrate_Other_ports_Score", "Risky_Inbound", "Risky_Outbound", 
            "Rule_Usage_Scoring", "Rule_Usage_Description_Scoring", "Source_User_Scoring",
            "Profile_Scoring", "Options_Scoring", "Score_Total", "Risk_Level",
            "Service_RangeGt1000", "App_IsAny", "App_RangeGt1000", "Action_IsDenyOrDrop",
            "Service_UniquePorts_Count", "App_UniquePorts_Count", "Service_Range_Count", "App_Range_Count"
        ]
        
        # Function to check if a column is a scoring column
        def is_scoring_column(column_name):
            # Service_IsAny should not be treated as a scoring column (it's hidden)
            if column_name == "Service_IsAny":
                return False
            # Check if it's a known scoring column
            if column_name in known_scoring_columns:
                return True
            # Check if it matches scoring patterns
            for pattern in scoring_patterns:
                if column_name.startswith(pattern):
                    return True
            return False
        
        # Create format objects for headers
        # Grey background for original columns
        original_header_format = wb.add_format({
            'bg_color': '#D3D3D3',  # Light grey
            'bold': True,
            'font_color': '#000000',  # Black text
            'text_wrap': True,  # Wrap text in headers
            'valign': 'vcenter',
            'align': 'center'
        })
        
        # Dark blue background with white bold text for scoring columns
        scoring_header_format = wb.add_format({
            'bg_color': '#1F4E79',  # Dark blue
            'bold': True,
            'font_color': '#FFFFFF',  # White text
            'text_wrap': True,  # Wrap text in headers
            'valign': 'vcenter',
            'align': 'center'
        })
        
        # Create format objects for data cells
        # Medium blue background for cells containing "True"
        true_cell_format = wb.add_format({
            'bg_color': '#4472C4',  # Medium blue
            'align': 'center',
            'valign': 'vcenter'
        })
        
        # Center-aligned format for scoring columns (for point values)
        scoring_cell_format = wb.add_format({
            'align': 'center',
            'valign': 'vcenter'
        })
        
        # Standard format for original columns
        original_cell_format = wb.add_format({
            'valign': 'vcenter'
        })
        
        # Get all column headers
        headers = list(df.columns)
        
        # Apply formatting to header row (row 0)
        scoring_cols = []
        original_cols = []
        
        for col_idx, header in enumerate(headers):
            if is_scoring_column(header):
                # Apply dark blue formatting to scoring columns
                ws.write(0, col_idx, header, scoring_header_format)
                scoring_cols.append(header)
            else:
                # Apply grey formatting to original columns (everything else)
                ws.write(0, col_idx, header, original_header_format)
                original_cols.append(header)
        
        # Apply formatting to data cells
        n_rows = len(df)
        for row_idx in range(1, n_rows + 1):  # Data rows start at 1 (row 0 is header)
            for col_idx, header in enumerate(headers):
                cell_value = str(df.iloc[row_idx - 1, col_idx])
                
                if is_scoring_column(header):
                    # For scoring columns, check if cell contains "True" and apply medium blue
                    if cell_value.strip().lower().startswith("true"):
                        ws.write(row_idx, col_idx, cell_value, true_cell_format)
                    else:
                        # Center-align other scoring column values
                        ws.write(row_idx, col_idx, cell_value, scoring_cell_format)
                else:
                    # Original columns use standard format
                    ws.write(row_idx, col_idx, cell_value, original_cell_format)
        
        # Debug logging
        print(f"📊 Column formatting applied:")
        print(f"   🔵 Scoring columns ({len(scoring_cols)}): {scoring_cols}")
        print(f"   ⚪ Original columns ({len(original_cols)}): {original_cols}")
        
        # Set column widths with text wrapping
        for col_idx, header in enumerate(headers):
            if is_scoring_column(header):
                # Wider columns for scoring data
                ws.set_column(col_idx, col_idx, 20)
            else:
                # Standard width for original columns
                ws.set_column(col_idx, col_idx, 15)
        
        print("✅ Applied column formatting to distinguish original vs scoring columns")
        print("✅ Applied cell formatting: Medium blue for True values, centered point values, wrapped headers")
        
    except Exception as e:
        print(f"⚠️  Column formatting error: {e}")
        logging.error(f"Column formatting error: {e}")

def _format_preserved_sheet(xw, sheet_name, sheet_df):
    """Apply formatting to preserved sheets to indicate they're from the original file"""
    try:
        # Get the worksheet
        ws = xw.sheets[sheet_name]
        wb = xw.book
        
        # Create format for preserved sheet headers (grey background)
        preserved_format = wb.add_format({
            'bg_color': '#D3D3D3',  # Light grey
            'bold': True,
            'font_color': '#000000'  # Black text
        })
        
        # Apply formatting to header row (row 0)
        headers = list(sheet_df.columns)
        for col_idx, header in enumerate(headers):
            ws.write(0, col_idx, header, preserved_format)
        
        # Set column widths
        for col_idx, header in enumerate(headers):
            ws.set_column(col_idx, col_idx, 15)
        
        print(f"✅ Applied preserved sheet formatting to: {sheet_name}")
        
    except Exception as e:
        print(f"⚠️  Preserved sheet formatting error for {sheet_name}: {e}")

def _write_excel(payload: dict) -> dict:
    df: pd.DataFrame = payload["df"]
    all_sheets = payload.get("all_sheets", {})
    out_path = Path(payload["output_path"])
    progress_callback = payload.get("progress_callback")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    
    logging.info(f"💾 Starting Excel write process: {len(df)} rows, {len(df.columns)} columns")
    if progress_callback:
        progress_callback(f"💾 Tool: Preparing Excel output ({len(df)} rows)", 75)

    # Explicitly delete existing file to ensure clean overwrite
    if out_path.exists():
        try:
            out_path.unlink()
            print(f"🗑️  Deleted existing file: {out_path}")
        except Exception as e:
            print(f"⚠️  Could not delete existing file: {e}")

    with pd.ExcelWriter(out_path, engine="xlsxwriter") as xw:
        # Get workbook reference early (needed for formatting)
        wb = xw.book
        
        # Debug: Show DataFrame columns before writing to Excel
        print(f"📝 Writing to Excel. DataFrame columns: {list(df.columns)}")
        print(f"📊 'Migrate Insecure_AppID' in df: {'Migrate Insecure_AppID' in df.columns}")
        print(f"📊 'Migrate_Insecure' in df: {'Migrate_Insecure' in df.columns}")
        
        # Remove diagnostic columns that don't contribute to Score_Total
        diagnostic_columns_to_hide = [
            "Service_UniquePorts_Total",
            "Service_RangeGt1000",
            "Service_IsAny",
            "App_IsAny",
            "App_UniquePorts_Total",
            "App_RangeGt1000"
        ]
        
        if progress_callback:
            progress_callback("🔧 Tool: Removing diagnostic columns from output", 76)
        
        # Create a copy and remove diagnostic columns
        df_output = df.copy()
        columns_to_remove = [col for col in diagnostic_columns_to_hide if col in df_output.columns]
        if columns_to_remove:
            df_output = df_output.drop(columns=columns_to_remove)
            logging.info(f"🔇 Hidden {len(columns_to_remove)} diagnostic columns from output: {columns_to_remove}")
            print(f"🔇 Hidden diagnostic columns from output: {columns_to_remove}")
        
        # Keep original scored data for reference
        # Ensure Score_Total is the last column
        if "Score_Total" in df_output.columns:
            cols = [c for c in df_output.columns if c != "Score_Total"] + ["Score_Total"]
            df_output = df_output[cols]
        
        if progress_callback:
            progress_callback("📝 Tool: Writing Raw Data sheet to Excel", 77)
        logging.info("📝 Writing Raw Data sheet to Excel...")
        df_output.to_excel(xw, sheet_name="Raw Data", index=False)
        
        if progress_callback:
            progress_callback("🎨 Tool: Applying column formatting", 78)
        logging.info("🎨 Applying column formatting...")
        # Apply column formatting to distinguish original vs scoring columns
        _format_raw_data_columns(xw, df_output)

        # 2) Inputs sheet (unchanged)
        meta = pd.DataFrame([{
            "input_path": payload["input_path"],
            "sheet": payload.get("sheet") or "",
            "separator": payload["sep"]
        }])
        meta.to_excel(xw, sheet_name="Inputs", index=False)

        # 3) Ensure Scoring_Config exists (layout: A=Scoring_Category, B=Description, C=Points, D=Enabled)
        # Store config_rows for validation later - use centralized ScoringConfig
        if progress_callback:
            progress_callback("⚙️  Tool: Setting up Scoring_Config sheet", 79)
        logging.info("⚙️  Setting up Scoring_Config sheet...")
        
        config_rows = ScoringConfig.get_config_rows()
        
        if "Scoring_Config" not in xw.sheets:
            # Create default config if none present
            pd.DataFrame(config_rows).to_excel(xw, sheet_name="Scoring_Config", index=False)
            logging.info("✅ Created Scoring_Config sheet with default configuration")
            print("✅ Created Scoring_Config sheet with default configuration.")

        # 4) Make listed columns dynamic and make Score_Total a formula
        if progress_callback:
            progress_callback("🔢 Tool: Writing dynamic formulas to scoring columns", 80)
        logging.info("🔢 Writing dynamic formulas to scoring columns...")
        
        ws       = xw.sheets["Raw Data"]
        headers  = list(df_output.columns)
        n_rows   = df_output.shape[0]

        # Columns the user asked to be dynamic (booleans, not the _UniquePorts_ numeric columns)
        # NOTE: Service_IsAny is excluded as it's a diagnostic column that should be hidden
        dynamic_bool_cols = [
            "Src_IsAny","Src_CIDR_Le_16","Src_CIDR_17_22",
            "Dst_IsAny","Dst_CIDR_Le_16","Dst_CIDR_17_22",
            "SrcZone_IsAny","DstZone_IsAny",
            "Service_Any_OR_RangeGt1000","App_Any_OR_RangeGt1000",
            "Service_Insecure_Match","Risky_Inbound","Risky_Outbound",
            "Rule_Usage_Scoring","Rule_Usage_Description_Scoring","Source_User_Scoring","Profile_Scoring","Options_Scoring",  # All scoring categories
            "Migrate_Insecure","Migrate_Other_ports_Score",
            "Service_RangeGt1000",  # Service_IsAny removed - it's hidden
            "App_IsAny","App_RangeGt1000",
            "Action_IsDenyOrDrop"  # remains 0-pt but we keep "True,0"/"False,0" format
        ]
        # Keys that actually contribute to Score_Total (must also exist in SCORING_WEIGHTS)
        # Map SCORING_WEIGHTS keys to actual column names
        scoring_keys = []
        for k in SCORING_WEIGHTS.keys():
            # Map scoring weight keys to actual column names
            if k == "Migrate_Other_Ports":
                # Check if Migrate_Other_ports_Score column exists
                if "Migrate_Other_ports_Score" in headers:
                    scoring_keys.append("Migrate_Other_ports_Score")
            elif k == "Migrate_Insecure":
                # Check if Migrate_Insecure column exists
                if "Migrate_Insecure" in headers:
                    scoring_keys.append("Migrate_Insecure")
            elif k in headers:
                scoring_keys.append(k)

        # Map header -> column index for quick lookup
        col_index = {h:i for i,h in enumerate(headers)}

        # VALIDATION: Verify Scoring_Config exists and has required structure before writing formulas
        use_formulas = True
        config_validation_errors = []
        
        # Validate that Scoring_Config sheet exists and has the structure we need
        if "Scoring_Config" not in xw.sheets:
            use_formulas = False
            config_validation_errors.append("Scoring_Config sheet not found")
            print("⚠️  WARNING: Scoring_Config sheet not found. Writing static values instead of formulas.")
        else:
            # Build set of categories from config_rows for validation
            config_categories = {row["Scoring_Category"] for row in config_rows}
            
            # Diagnostic columns that don't need to be in Scoring_Config (they're 0-point helpers)
            diagnostic_columns = {"Action_IsDenyOrDrop", "Service_IsAny", "Service_RangeGt1000", "App_IsAny", "App_RangeGt1000"}
            
            # Collect all categories we'll need for lookup (EXCLUDE diagnostic columns)
            needed_categories = set()
            for key in dynamic_bool_cols:
                if key not in col_index:
                    continue
                # Skip diagnostic columns - they don't need to be in Scoring_Config (always 0 points)
                if key in diagnostic_columns:
                    continue
                config_key = key
                if key == "Migrate_Other_ports_Score":
                    config_key = "Migrate_Other_Ports"
                elif key == "Migrate_Insecure":
                    config_key = "Migrate_Insecure"
                needed_categories.add(config_key)
            
            # Check if all needed categories exist in config
            missing_categories = needed_categories - config_categories
            if missing_categories:
                print(f"⚠️  WARNING: Scoring_Config missing {len(missing_categories)} categories: {sorted(missing_categories)[:5]}{'...' if len(missing_categories) > 5 else ''}")
                print(f"   Missing categories will use default points in formulas (XLOOKUP will fallback).")
            else:
                print(f"✅ Scoring_Config validation passed. All {len(needed_categories)} required categories found.")
                print(f"   Will write formulas that reference Scoring_Config sheet.")

        # For each dynamic boolean column, replace its value with a formula that reads Points/Enabled from Scoring_Config
        # BUT: Skip columns with variable calculated points - they're already correct
        # Rule_Usage_Scoring, Profile_Scoring, Options_Scoring: variable points (5/2/0, 5/0, 8/0)
        special_columns = ["Rule_Usage_Scoring", "Profile_Scoring", "Options_Scoring"]
        
        for key in dynamic_bool_cols:
            if key not in col_index:
                continue
            
            # Skip special columns with calculated points - they already have correct values
            if key in special_columns:
                continue
            
            # Skip Source_User_Scoring - it has calculated points that may be negative
            # It will use the actual calculated points in Score_Total via special handling
            if key == "Source_User_Scoring":
                continue
            
            c = col_index[key]
            # Map column name to config key for lookup
            config_key = key
            if key == "Migrate_Other_ports_Score":
                config_key = "Migrate_Other_Ports"
            elif key == "Migrate_Insecure":
                config_key = "Migrate_Insecure"
            
            default_pts = int(SCORING_WEIGHTS.get(config_key, 0))  # 0 for diagnostic/non-scoring keys is fine
            
            # Create format objects for this column
            true_format = wb.add_format({
                'bg_color': '#4472C4',  # Medium blue
                'align': 'center',
                'valign': 'vcenter'
            })
            
            false_format = wb.add_format({
                'align': 'center',
                'valign': 'vcenter'
            })
            
            if use_formulas:
                # Write formulas that reference Scoring_Config
                for r in range(1, n_rows+1):  # data rows start at 1 (row 0 is header)
                    # Get this row's original boolean result so we can hard-code it in the formula
                    # The cell currently holds strings like "True,10" or "False,0"
                    raw = str(df_output.iloc[r-1, c])
                    is_true = str(raw).strip().lower().startswith("true")
                    excel_bool = "TRUE" if is_true else "FALSE"

                    # If TRUE -> "True," & (Enabled? Points : 0)
                    # If FALSE -> "False,0"
                    # Enabled from D:D, Points from C:C of Scoring_Config; fallback to default_pts if Points blank
                    formula = (
                        f'=IF({excel_bool},'
                            f'"True," & IF(XLOOKUP("{config_key}",\'Scoring_Config\'!$A:$A,\'Scoring_Config\'!$D:$D,"Yes")="Yes",'
                            f'XLOOKUP("{config_key}",\'Scoring_Config\'!$A:$A,\'Scoring_Config\'!$C:$C,{default_pts}),0),'
                        f'"False,0")'
                    )
                    # Apply formatting: medium blue for True, center-aligned for False
                    cell_format = true_format if is_true else false_format
                    ws.write_formula(r, c, formula, cell_format)
            else:
                # Write static values using default points (fallback when Scoring_Config is invalid)
                print(f"   📝 Writing static values for column '{key}' (Scoring_Config not available)")
                # Create format objects for static values
                true_format = wb.add_format({
                    'bg_color': '#4472C4',  # Medium blue
                    'align': 'center',
                    'valign': 'vcenter'
                })
                
                false_format = wb.add_format({
                    'align': 'center',
                    'valign': 'vcenter'
                })
                
                for r in range(1, n_rows+1):
                    raw = str(df_output.iloc[r-1, c])
                    is_true = str(raw).strip().lower().startswith("true")
                    # Write static value using default points
                    static_value = f"{'True' if is_true else 'False'},{default_pts if is_true else 0}"
                    cell_format = true_format if is_true else false_format
                    ws.write(r, c, static_value, cell_format)

        # Build the dynamic Score_Total formula per row (deny/drop override still applies)
        try:
            deny_col = col_index["Action_IsDenyOrDrop"]
        except KeyError:
            raise ValueError("Action_IsDenyOrDrop column is required to apply deny/drop override.")

        # Score_Total column index (must exist)
        try:
            score_col = col_index["Score_Total"]
        except KeyError:
            # If missing (rare), create it at the end
            score_col = len(headers)
            ws.write(0, score_col, "Score_Total")

        if progress_callback:
            progress_callback("📊 Tool: Building Score_Total formulas", 85)
        logging.info(f"📊 Building Score_Total formulas for {n_rows} rows...")

        for r in range(1, n_rows+1):
            if progress_callback and r % 1000 == 0:
                progress = 85 + int((r / n_rows) * 5)
                progress_callback(f"📊 Tool: Writing Score_Total formulas {r}/{n_rows}", progress)
            
            deny_cell = xl_rowcol_to_cell(r, deny_col)
            parts = []
            for key in scoring_keys:
                if key in col_index:  # Only include keys that exist in the data
                    kc = col_index[key]
                    key_cell = xl_rowcol_to_cell(r, kc)
                    
                    # Map column name back to SCORING_WEIGHTS key for config lookup
                    config_key = key
                    if key == "Migrate_Other_ports_Score":
                        config_key = "Migrate_Other_Ports"
                    elif key == "Migrate_Insecure":
                        config_key = "Migrate_Insecure"
                    
                    default_pts = int(SCORING_WEIGHTS.get(config_key, 0))
                    
                    # Special handling for columns with calculated points
                    # Source_User_Scoring also needs special handling (can have negative points)
                    if key in special_columns or key == "Source_User_Scoring":
                        # For special columns, extract the actual points from the cell value
                        # The cell contains "True,5" or "True,-10" or "False,0" - we need to extract the number after the comma
                        part = f'IF(XLOOKUP("{config_key}",\'Scoring_Config\'!$A:$A,\'Scoring_Config\'!$D:$D,"Yes")="Yes",'
                        part += f'VALUE(MID({key_cell},FIND(",",{key_cell})+1,100)),0)'
                    else:
                        # For regular columns, use the standard formula
                        part = (
                            f'IF(LEFT({key_cell},4)="True",'
                            f'IF(XLOOKUP("{config_key}",\'Scoring_Config\'!$A:$A,\'Scoring_Config\'!$D:$D,"Yes")="Yes",'
                            f'XLOOKUP("{config_key}",\'Scoring_Config\'!$A:$A,\'Scoring_Config\'!$C:$C,{default_pts}),0),'
                            f'0)'
                        )
                    parts.append(part)
            total_formula = f'=IF(LEFT({deny_cell},4)="True",0,({"+".join(parts) if parts else "0"}))'
            # Center-align Score_Total values
            score_format = wb.add_format({
                'align': 'center',
                'valign': 'vcenter'
            })
            ws.write_formula(r, score_col, total_formula, score_format)

        # Format special columns (Rule_Usage_Scoring, Profile_Scoring, Options_Scoring, Source_User_Scoring)
        # These columns have calculated points and weren't written as formulas
        special_columns_to_format = ["Rule_Usage_Scoring", "Profile_Scoring", "Options_Scoring", "Source_User_Scoring"]
        true_format_special = wb.add_format({
            'bg_color': '#4472C4',  # Medium blue
            'align': 'center',
            'valign': 'vcenter'
        })
        
        false_format_special = wb.add_format({
            'align': 'center',
            'valign': 'vcenter'
        })
        
        for special_col in special_columns_to_format:
            if special_col in col_index:
                special_col_idx = col_index[special_col]
                for r in range(1, n_rows+1):
                    cell_value = str(df_output.iloc[r-1, special_col_idx])
                    is_true = cell_value.strip().lower().startswith("true")
                    cell_format = true_format_special if is_true else false_format_special
                    # Re-write the cell with formatting (preserving the value)
                    ws.write(r, special_col_idx, cell_value, cell_format)
        
        # Format remaining data cells that weren't written as formulas
        if progress_callback:
            progress_callback("🎨 Tool: Applying final cell formatting", 90)
        logging.info("🎨 Applying final cell formatting to remaining cells...")
        
        # Get list of columns that were written as formulas (so we don't re-format them)
        columns_with_formulas = set(dynamic_bool_cols) & set(headers)
        columns_with_formulas.add("Score_Total")  # Score_Total also has formulas
        columns_with_formulas.update(special_columns_to_format)  # Special columns already formatted
        
        # Define known scoring columns for checking
        known_scoring_cols_set = {
            "Src_IsAny", "Src_CIDR_Le_16", "Src_CIDR_17_22", "Dst_IsAny", "Dst_CIDR_Le_16", "Dst_CIDR_17_22",
            "SrcZone_IsAny", "DstZone_IsAny", "Service_Any_OR_RangeGt1000", "App_Any_OR_RangeGt1000",
            "Service_Insecure_Match","Migrate_Insecure", "Migrate Insecure_AppID", "Migrate_Other_ports_Score", 
            "Risky_Inbound", "Risky_Outbound", "Rule_Usage_Scoring", "Rule_Usage_Description_Scoring", 
            "Source_User_Scoring", "Profile_Scoring", "Options_Scoring", "Score_Total", "Risk_Level",
            "Service_RangeGt1000", "App_IsAny", "App_RangeGt1000", "Action_IsDenyOrDrop"
        }
        
        # Format all other scoring columns that don't have formulas
        true_format_other = wb.add_format({
            'bg_color': '#4472C4',  # Medium blue
            'align': 'center',
            'valign': 'vcenter'
        })
        
        false_format_other = wb.add_format({
            'align': 'center',
            'valign': 'vcenter'
        })
        
        for col_idx, header in enumerate(headers):
            # Skip columns that already have formulas or are original columns
            if header in columns_with_formulas:
                continue
            
            # Check if it's a scoring column
            scoring_patterns_check = ["Src_", "Dst_", "SrcZone_", "DstZone_", "Service_", "App_", "Action_",
                                     "Risky_", "Rule_Usage_", "Profile_", "Options_", "Score_", "Risk_", "Migrate_"]
            is_scoring = any(header.startswith(p) for p in scoring_patterns_check) or header in known_scoring_cols_set
            
            if is_scoring and header != "Service_IsAny":  # Skip Service_IsAny
                for r in range(1, n_rows+1):
                    cell_value = str(df_output.iloc[r-1, col_idx])
                    is_true = cell_value.strip().lower().startswith("true")
                    cell_format = true_format_other if is_true else false_format_other
                    ws.write(r, col_idx, cell_value, cell_format)

        # === [ADDED] Scoring_Config formatting & validation ===
        # This block enhances the Scoring_Config sheet with:
        # - Column sizing
        # - Header styling
        # - Data validation (Enabled Yes/No dropdown, Points integer 0..100)
        # - A small inline tip note
        if "Scoring_Config" in xw.sheets:
            sc = xw.sheets["Scoring_Config"]
            # Note: wb is already defined at the top of the with block

            # Auto-fit / helpful widths
            sc.set_column('A:A', 26)   # Scoring_Category
            sc.set_column('B:B', 54)   # Description
            sc.set_column('C:C', 10)   # Points
            sc.set_column('D:D', 12)   # Enabled

            # Header re-write with style (safe even if already present)
            hdr = wb.add_format({'bold': True, 'bg_color': '#E5E7EB', 'border': 1})
            for c, name in enumerate(["Scoring_Category", "Description", "Points", "Enabled"]):
                sc.write(0, c, name, hdr)

            # Data validation range: rows 2..500 (adjust if you expect more)
            sc.data_validation('D2:D500', {
                'validate': 'list',
                'source': ['Yes', 'No']
            })
            sc.data_validation('C2:C500', {
                'validate': 'integer',
                'criteria': 'between',
                'minimum': -100,
                'maximum': 100
            })

            # Helpful hint to the right
            sc.write('F2', "Tip: Toggle Enabled or change Points to update Score_Total dynamically.")

        # 5) Preserve all original sheets from input file (except the rules sheet which is already processed)
        if progress_callback:
            progress_callback("📚 Tool: Preserving original sheets", 92)
        logging.info("📚 Preserving original sheets from input file...")
        
        rules_sheet_names = ["rules_curated", "rules_expanded", "Raw Data"]
        preserved_count = 0
        for sheet_name, sheet_df in all_sheets.items():
            # Skip sheets that are already processed or are scoring-related
            if sheet_name in rules_sheet_names or sheet_name in ["Inputs", "Scoring_Config"]:
                continue
            
            # Preserve the original sheet
            try:
                sheet_df.to_excel(xw, sheet_name=sheet_name, index=False)
                
                # Apply formatting to preserved sheets (grey headers to indicate they're from original file)
                _format_preserved_sheet(xw, sheet_name, sheet_df)
                
                preserved_count += 1
                logging.info(f"✅ Preserved sheet: {sheet_name}")
                print(f"✅ Preserved sheet: {sheet_name}")
            except Exception as e:
                logging.warning(f"⚠️  Could not preserve sheet '{sheet_name}': {e}")
                print(f"⚠️  Could not preserve sheet '{sheet_name}': {e}")

        logging.info(f"✅ Preserved {preserved_count} original sheets")

    # Generate static file path (same directory, different filename)
    dynamic_path = str(out_path.resolve())
    static_path_obj = out_path.parent / "Final_output_scored_static.xlsx"
    
    # Write static version (no formulas, no Scoring_Config)
    if progress_callback:
        progress_callback("💾 Tool: Writing static Excel file (no formulas)", 95)
    logging.info("💾 Writing static Excel file (no formulas)...")
    
    try:
        static_payload = payload.copy()
        static_payload["output_path"] = str(static_path_obj)
        static_payload["dynamic_output_path"] = dynamic_path  # Pass dynamic file path for Scoring_Config reading
        static_path = _write_excel_static(static_payload)
        logging.info(f"✅ Static file written: {static_path}")
    except Exception as e:
        logging.error(f"⚠️  Could not write static file: {e}")
        print(f"⚠️  Could not write static file: {e}")
        static_path = None

    result = {"saved_file": dynamic_path, "rows": int(df_output.shape[0])}
    if static_path:
        result["static_file"] = static_path
    
    logging.info(f"✅ Excel write complete: {result['rows']} rows written")
    return result


def _write_excel_static(payload: dict) -> str:
    """
    Write Excel file with static values (no formulas, no Scoring_Config sheet).
    Same structure as dynamic file but all values are static.
    """
    df: pd.DataFrame = payload["df"]
    all_sheets = payload.get("all_sheets", {})
    out_path = Path(payload["output_path"])
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Explicitly delete existing file to ensure clean overwrite
    if out_path.exists():
        try:
            out_path.unlink()
            print(f"🗑️  Deleted existing static file: {out_path}")
        except Exception as e:
            print(f"⚠️  Could not delete existing static file: {e}")

    with pd.ExcelWriter(out_path, engine="xlsxwriter") as xw:
        
        # Remove diagnostic columns that don't contribute to Score_Total
        diagnostic_columns_to_hide = [
            "Service_UniquePorts_Total",
            "Service_RangeGt1000",
            "Service_IsAny",
            "App_IsAny",
            "App_UniquePorts_Total",
            "App_RangeGt1000"
        ]
        
        # Prepare DataFrame - ensure Score_Total is the last column
        df_copy = df.copy()
        
        # Remove diagnostic columns
        columns_to_remove = [col for col in diagnostic_columns_to_hide if col in df_copy.columns]
        if columns_to_remove:
            df_copy = df_copy.drop(columns=columns_to_remove)
            print(f"🔇 Hidden diagnostic columns from static output: {columns_to_remove}")
        
        # IMPORTANT: Recalculate scoring column values and Score_Total based on Scoring_Config
        # The DataFrame might have values like "True,10" but Scoring_Config has 25 points
        # We need to update all scoring columns to use Scoring_Config values, then recalculate Score_Total
        
        # Get scoring weights from Scoring_Config (same logic as dynamic file)
        input_path = payload.get("input_path", "")
        dynamic_output_path = payload.get("dynamic_output_path", "")  # Dynamic file path passed from caller
        static_output_path = payload.get("output_path", "")  # This is the static file path
        
        scoring_weights = _get_scoring_weights(input_path, dynamic_output_path) if input_path else SCORING_WEIGHTS
        
        # Read Scoring_Config to get actual point values
        # Try dynamic file first (where Scoring_Config was just written), then input_path
        scoring_config = {}
        try:
            if dynamic_output_path and Path(dynamic_output_path).exists():
                scoring_config = _read_scoring_config(dynamic_output_path)
                print(f"📋 Read Scoring_Config from dynamic file: {len(scoring_config)} categories")
            elif input_path and Path(input_path).exists():
                scoring_config = _read_scoring_config(input_path)
                print(f"📋 Read Scoring_Config from input file: {len(scoring_config)} categories")
            else:
                print(f"⚠️  No Scoring_Config found, using default SCORING_WEIGHTS")
        except Exception as e:
            print(f"⚠️  Could not read Scoring_Config: {e}, using default weights")
        
        # Debug: Show point values that will be used
        if scoring_config:
            print(f"📊 Scoring_Config point values (first 5):")
            for i, (key, config) in enumerate(list(scoring_config.items())[:5]):
                enabled = config.get("enabled", True)
                points = config.get("points", SCORING_WEIGHTS.get(key, 0))
                default = SCORING_WEIGHTS.get(key, 0)
                print(f"   {key}: enabled={enabled}, points={points} (default={default})")
        
        # Update all dynamic scoring columns with correct point values from Scoring_Config
        dynamic_bool_cols = [
            "Src_IsAny", "Src_CIDR_Le_16", "Src_CIDR_17_22",
            "Dst_IsAny", "Dst_CIDR_Le_16", "Dst_CIDR_17_22",
            "SrcZone_IsAny", "DstZone_IsAny",
            "Service_Any_OR_RangeGt1000", "App_Any_OR_RangeGt1000",
            "Service_Insecure_Match", "Risky_Inbound", "Risky_Outbound",
            "Rule_Usage_Scoring", "Rule_Usage_Description_Scoring", "Source_User_Scoring", 
            "Profile_Scoring", "Options_Scoring",
            "Migrate_Insecure", "Migrate_Other_ports_Score"
        ]
        
        # Special columns that use calculated points (but still need to respect enabled/disabled status)
        # Note: Rule_Usage_Description_Scoring is NOT in this list - dynamic file treats it as regular column
        # (reads points from Scoring_Config, not from calculated cell value)
        special_columns = ["Rule_Usage_Scoring", "Profile_Scoring", "Options_Scoring", "Source_User_Scoring"]
        
        for col in dynamic_bool_cols:
            if col not in df_copy.columns:
                continue
            
            # Map column name to config key
            config_key = col
            if col == "Migrate_Other_ports_Score":
                config_key = "Migrate_Other_Ports"
            elif col == "Migrate_Insecure":
                config_key = "Migrate_Insecure"
            
            # Check if this category is enabled in Scoring_Config
            is_enabled = True
            if config_key in scoring_config:
                is_enabled = scoring_config[config_key].get("enabled", True)
            
            # For special columns, we keep the calculated points but set to 0 if disabled
            if col in special_columns:
                # Update all rows for this special column
                for idx in df_copy.index:
                    cell_val = str(df_copy.loc[idx, col])
                    if "," in cell_val:
                        # Extract boolean and points
                        is_true = cell_val.strip().lower().startswith("true")
                        try:
                            original_points = int(cell_val.split(",")[1])
                        except (ValueError, IndexError):
                            original_points = 0
                        
                        # If disabled, set points to 0; otherwise keep original calculated points
                        if not is_enabled:
                            new_val = f"{'True' if is_true else 'False'},0"
                        else:
                            # Keep the original calculated points
                            new_val = f"{'True' if is_true else 'False'},{original_points}"
                        
                        df_copy.loc[idx, col] = new_val
                continue
            
            # For regular columns, update points from Scoring_Config
            # Match dynamic file logic: use points from Scoring_Config if available and enabled,
            # otherwise use default from SCORING_WEIGHTS (not scoring_weights which may be filtered)
            default_pts = int(SCORING_WEIGHTS.get(config_key, 0))
            
            # Get points from Scoring_Config (matches dynamic file XLOOKUP logic)
            if config_key in scoring_config:
                config_points = scoring_config[config_key].get("points", default_pts)
                # If points is 0 or empty in config, use default_pts (matches XLOOKUP fallback)
                # BUT: if config explicitly sets points to 0, that's valid (category awards 0 points)
                # So we only use default if points is missing/empty string, not if it's 0
                if config_points == "" or config_points is None:
                    points = default_pts
                else:
                    points = int(config_points)
            else:
                # Not in config, use default (matches XLOOKUP fallback)
                points = default_pts
            
            # Update all rows for this column
            for idx in df_copy.index:
                cell_val = str(df_copy.loc[idx, col])
                if "," in cell_val:
                    # Extract boolean and update points
                    is_true = cell_val.strip().lower().startswith("true")
                    
                    # Match dynamic file formula: if enabled and True, use points; else 0
                    if not is_enabled:
                        new_val = f"{'True' if is_true else 'False'},0"
                    else:
                        # If True, use points from config; if False, use 0
                        new_points = points if is_true else 0
                        new_val = f"{'True' if is_true else 'False'},{new_points}"
                    
                    df_copy.loc[idx, col] = new_val
        
        # Now recalculate Score_Total from updated cell values
        # IMPORTANT: This must match the dynamic file's formula logic exactly
        
        # Identify columns that contribute to Score_Total
        # Match dynamic file: use scoring_keys logic (only columns that exist in DataFrame)
        scoring_cols = []
        missing_cols = []
        for key in SCORING_WEIGHTS.keys():
            # Map scoring weight keys to actual column names (matches dynamic file scoring_keys logic)
            if key == "Migrate_Other_Ports":
                if "Migrate_Other_ports_Score" in df_copy.columns:
                    scoring_cols.append("Migrate_Other_ports_Score")
                else:
                    missing_cols.append(f"{key} (mapped to Migrate_Other_ports_Score)")
            elif key == "Migrate_Insecure":
                if "Migrate_Insecure" in df_copy.columns:
                    scoring_cols.append("Migrate_Insecure")
                else:
                    missing_cols.append(key)
            elif key in df_copy.columns:
                scoring_cols.append(key)
            else:
                missing_cols.append(key)
        
        if missing_cols:
            print(f"⚠️  Warning: {len(missing_cols)} scoring columns not found in DataFrame: {missing_cols[:5]}{'...' if len(missing_cols) > 5 else ''}")
        print(f"📊 Using {len(scoring_cols)} scoring columns for Score_Total calculation")
        
        # Check for Action_IsDenyOrDrop column first (matches dynamic file logic)
        # If not found, fall back to Action column
        deny_col = None
        if "Action_IsDenyOrDrop" in df_copy.columns:
            deny_col = "Action_IsDenyOrDrop"
        else:
            # Fallback to Action column
            for col in ["Action", "action", "ACTION"]:
                if col in df_copy.columns:
                    deny_col = col
                    break
        
        # Recalculate Score_Total for each row
        recalculated_scores = []
        for idx in df_copy.index:
            # Check if Action is deny/drop (should result in 0 points)
            # Match dynamic file: IF(LEFT({deny_cell},4)="True",0,...)
            is_deny = False
            if deny_col:
                if deny_col == "Action_IsDenyOrDrop":
                    # Check if cell starts with "True" (matches dynamic file formula)
                    deny_val = str(df_copy.loc[idx, deny_col])
                    is_deny = deny_val.strip().lower().startswith("true")
                else:
                    # Fallback: check Action column value
                    action_val = str(df_copy.loc[idx, deny_col]).strip().lower()
                    is_deny = action_val in ("deny", "drop")
            
            if is_deny:
                recalculated_scores.append(0)
            else:
                # Sum points from ALL scoring columns that have "True" values
                # This must match the dynamic file formula logic exactly
                # Dynamic file formula: IF(LEFT({key_cell},4)="True", IF(XLOOKUP(enabled)="Yes", points, 0), 0)
                # Since cells are already updated with correct points based on enabled/disabled, we just read them
                total = 0
                contributing_cols = []  # For debug
                
                # Map column names back to config keys for enabled/disabled check
                col_to_config_key = {}
                for key in SCORING_WEIGHTS.keys():
                    if key == "Migrate_Other_Ports":
                        col_to_config_key["Migrate_Other_ports_Score"] = key
                    elif key == "Migrate_Insecure":
                        col_to_config_key["Migrate_Insecure"] = key
                    else:
                        col_to_config_key[key] = key
                
                for col in scoring_cols:
                    if col not in df_copy.columns:
                        continue
                    
                    try:
                        cell_val = str(df_copy.loc[idx, col]).strip()
                        
                        # Check if cell starts with "True" (case-insensitive)
                        # This matches dynamic file: IF(LEFT({key_cell},4)="True",...)
                        if cell_val.lower().startswith("true"):
                            # Extract points from "True,points" or "True, points" format
                            if "," in cell_val:
                                try:
                                    # Split by comma and get the second part (points)
                                    parts = cell_val.split(",", 1)
                                    if len(parts) == 2:
                                        points = int(parts[1].strip())
                                        # Add points (can be negative, e.g., Source_User_Scoring = -10)
                                        # Disabled categories will have "True,0" which adds 0 (no change)
                                        # This matches dynamic file: IF(enabled="Yes", points, 0)
                                        total += points
                                        if points != 0:  # Only log non-zero contributions for debugging
                                            contributing_cols.append(f"{col}:{points}")
                                except (ValueError, IndexError):
                                    # Invalid format, skip
                                    pass
                            else:
                                # Cell is "True" but no comma - might be just boolean, skip
                                pass
                        # If cell starts with "False" or doesn't start with "True", add 0 (implicit)
                    except Exception as e:
                        # Error reading cell, skip
                        pass
                
                recalculated_scores.append(int(total))
                
                # Debug: Log first row's calculation details
                if idx == df_copy.index[0] and len(contributing_cols) > 0:
                    print(f"   📊 Row 1 Score_Total calculation: {len(contributing_cols)} columns contributed")
                    print(f"      Total = {total} (from: {', '.join(contributing_cols[:10])}{'...' if len(contributing_cols) > 10 else ''})")
        
        # Update Score_Total column with recalculated values
        df_copy["Score_Total"] = recalculated_scores
        
        # Debug: Compare first few rows with original Score_Total if it exists
        if "Score_Total" in df.columns and len(df) > 0:
            print(f"\n🔍 Debug: Comparing Score_Total values (first 5 rows):")
            print(f"   Note: 'Original' is from initial calculation (default weights)")
            print(f"   Note: 'Recalculated' is after applying Scoring_Config points")
            for i in range(min(5, len(df))):
                original = df.iloc[i]["Score_Total"] if "Score_Total" in df.columns else "N/A"
                recalculated = recalculated_scores[i] if i < len(recalculated_scores) else "N/A"
                if str(original) != str(recalculated):
                    print(f"   Row {i+1}: Original={original}, Recalculated={recalculated} ❌ MISMATCH (diff: {recalculated - int(original) if isinstance(original, (int, float)) and isinstance(recalculated, int) else 'N/A'})")
                    # Show ALL contributing columns for this row
                    if i < len(df_copy.index):
                        idx = df_copy.index[i]
                        print(f"      All contributing columns for row {i+1}:")
                        row_total = 0
                        for col in scoring_cols:
                            if col in df_copy.columns:
                                cell_val = str(df_copy.loc[idx, col])
                                if cell_val.strip().lower().startswith("true") and "," in cell_val:
                                    try:
                                        points = int(cell_val.split(",")[1])
                                        row_total += points
                                        print(f"        {col}: {cell_val} → {points} points")
                                    except (ValueError, IndexError):
                                        pass
                        print(f"      Sum of all contributing columns: {row_total}")
                else:
                    print(f"   Row {i+1}: {original} ✓")
        
        print(f"✅ Recalculated Score_Total for {len(recalculated_scores)} rows")
        
        # Final verification: Show summary statistics
        if len(recalculated_scores) > 0:
            total_sum = sum(recalculated_scores)
            non_zero_count = sum(1 for s in recalculated_scores if s > 0)
            zero_count = sum(1 for s in recalculated_scores if s == 0)
            print(f"📈 Score_Total Summary: Total sum={total_sum:,}, Non-zero={non_zero_count}, Zero={zero_count}")
            print(f"   ✓ Verified: Summing points from {len(scoring_cols)} scoring columns where cell='True'")
        
        # Ensure Score_Total is the last column
        if "Score_Total" in df_copy.columns:
            cols = [c for c in df_copy.columns if c != "Score_Total"] + ["Score_Total"]
            df_copy = df_copy[cols]
        
        # 1) Write Raw Data sheet with static values (no formulas)
        df_copy.to_excel(xw, sheet_name="Raw Data", index=False)
        
        # Apply column formatting to distinguish original vs scoring columns
        _format_raw_data_columns(xw, df_copy)
        
        # Apply cell formatting for static file (medium blue for True, center alignment)
        ws = xw.sheets["Raw Data"]
        wb = xw.book
        headers = list(df_copy.columns)
        n_rows = len(df_copy)
        
        # Define scoring column patterns
        scoring_patterns = [
            "Src_", "Dst_", "SrcZone_", "DstZone_", "Service_", "App_", "Action_",
            "Risky_", "Rule_Usage_", "Profile_", "Options_", "Score_", "Risk_",
            "Service_UniquePorts_", "App_UniquePorts_", "Service_Range_", "App_Range_",
            "Migrate_"
        ]
        
        known_scoring_cols = {
            "Src_IsAny", "Src_CIDR_Le_16", "Src_CIDR_17_22", "Dst_IsAny", "Dst_CIDR_Le_16", "Dst_CIDR_17_22",
            "SrcZone_IsAny", "DstZone_IsAny", "Service_Any_OR_RangeGt1000", "App_Any_OR_RangeGt1000",
            "Service_Insecure_Match","Migrate_Insecure", "Migrate Insecure_AppID", "Migrate_Other_ports_Score", 
            "Risky_Inbound", "Risky_Outbound", "Rule_Usage_Scoring", "Rule_Usage_Description_Scoring", 
            "Source_User_Scoring", "Profile_Scoring", "Options_Scoring", "Score_Total", "Risk_Level",
            "Service_RangeGt1000", "App_IsAny", "App_RangeGt1000", "Action_IsDenyOrDrop"
        }
        
        def is_scoring_col(header):
            if header == "Service_IsAny":
                return False
            if header in known_scoring_cols:
                return True
            return any(header.startswith(p) for p in scoring_patterns)
        
        # Create format objects
        true_format = wb.add_format({
            'bg_color': '#4472C4',  # Medium blue
            'align': 'center',
            'valign': 'vcenter'
        })
        
        scoring_format = wb.add_format({
            'align': 'center',
            'valign': 'vcenter'
        })
        
        # Apply formatting to all data cells
        for col_idx, header in enumerate(headers):
            if is_scoring_col(header):
                for r in range(1, n_rows + 1):
                    cell_value = str(df_copy.iloc[r - 1, col_idx])
                    is_true = cell_value.strip().lower().startswith("true")
                    cell_format = true_format if is_true else scoring_format
                    ws.write(r, col_idx, cell_value, cell_format)

        # 2) Inputs sheet (unchanged)
        meta = pd.DataFrame([{
            "input_path": payload["input_path"],
            "sheet": payload.get("sheet") or "",
            "separator": payload["sep"]
        }])
        meta.to_excel(xw, sheet_name="Inputs", index=False)

        # 3) Skip Scoring_Config sheet entirely for static file

        # 4) Preserve all original sheets from input file (except the rules sheet which is already processed)
        rules_sheet_names = ["rules_curated", "rules_expanded", "Raw Data"]
        for sheet_name, sheet_df in all_sheets.items():
            # Skip sheets that are already processed or are scoring-related
            if sheet_name in rules_sheet_names or sheet_name in ["Inputs", "Scoring_Config"]:
                continue
            
            # Preserve the original sheet
            try:
                sheet_df.to_excel(xw, sheet_name=sheet_name, index=False)
                
                # Apply formatting to preserved sheets (grey headers to indicate they're from original file)
                _format_preserved_sheet(xw, sheet_name, sheet_df)
                
                print(f"✅ Preserved sheet in static file: {sheet_name}")
            except Exception as e:
                print(f"⚠️  Could not preserve sheet '{sheet_name}' in static file: {e}")

    print(f"✅ Static Excel file written: {out_path}")
    return str(out_path.resolve())


# Wrapper function to augment with Migrate Insecure_AppID before writing
def _augment_and_write(payload: dict) -> dict:
    """Augment DataFrame with Migrate Insecure_AppID columns then write to Excel"""
    progress_callback = payload.get("progress_callback")
    
    # Read all sheets for augmentation
    all_sheets = _read_all_sheets({"input_path": payload["input_path"]})
    
    # Augment with Migrate Insecure_AppID
    payload["df"] = _augment_migrate_insecure(
        payload["df"], 
        all_sheets, 
        payload["sep"],
        payload.get("input_path", ""),
        payload.get("output_path", ""),
        progress_callback
    )
    payload["all_sheets"] = all_sheets
    
    # Write to Excel
    return _write_excel(payload)

# LCEL chain: read -> score -> augment -> write
read_chain  = RunnableLambda(_read_excel)
score_chain = {
    "df": read_chain, 
    "sep": RunnablePassthrough() | (lambda c: c["sep"]),
    "input_path": RunnablePassthrough() | (lambda c: c["input_path"]),
    "output_path": RunnablePassthrough() | (lambda c: c["output_path"])
} | RunnableLambda(_score_df)
write_chain = {
    "df": score_chain,
    "input_path": RunnablePassthrough() | (lambda c: c["input_path"]),
    "output_path": RunnablePassthrough() | (lambda c: c["output_path"]),
    "sep": RunnablePassthrough() | (lambda c: c["sep"]),
    "sheet": RunnablePassthrough() | (lambda c: c.get("sheet")),
} | RunnableLambda(_augment_and_write)

# ----------------------------
# MCP tool
# ----------------------------
@mcp.tool()
def score_over_permissive_points_inline_from_excel(
    input_path: str,
    sheet_name: Optional[str] = None,
    output_path: str = os.path.join(OUT_DIR, OUT_BASENAME),
    separator: str = SEP_DEFAULT,
    progress_callback: Optional[callable] = None
) -> dict:
    """
    Adds 'True,points' in each scoring column (comma) and a final integer Score_Total.
    All scoring points are defined in the ScoringConfig class for easy modification.
    - Service/Application breadth use OR gating.
    - Insecure ports: points live in Service_Insecure_Match.
    - Risky Inbound: Insecure + Public Source IP + Risky Source Zone (Internet/Untrust/External/Any).
    - Risky Outbound: Insecure + Public Destination IP + Risky Destination Zone (Internet/Untrust/External/Any).
    - Deny/Drop -> Score_Total = 0.
    """
    logging.info("🚀 Starting scoring process")
    if progress_callback:
        progress_callback("🔧 Tool: Initializing scoring process", 0)
    
    cfg = {"input_path": input_path, "sheet": sheet_name, "output_path": output_path, "sep": separator}
    logging.info(f"📁 Input file: {input_path}, Output: {output_path}")
    
    if progress_callback:
        progress_callback("📖 Tool: Reading all sheets from Excel file", 5)
    logging.info("📖 Reading all sheets from input file...")
    
    # Read all sheets from the input file
    all_sheets = _read_all_sheets(cfg)
    logging.info(f"✅ Read {len(all_sheets)} sheets: {list(all_sheets.keys())}")
    
    if progress_callback:
        progress_callback("📋 Tool: Reading rules sheet for scoring", 10)
    logging.info("📋 Reading rules sheet for scoring...")
    
    # Get the rules sheet for scoring
    df = _read_excel(cfg)
    logging.info(f"✅ Loaded {len(df)} rules from sheet")
    
    if progress_callback:
        progress_callback(f"⚙️  Tool: Processing {len(df)} rules for scoring", 15)
    
    # Score the data
    scored_df = _score_df({
        "df": df,
        "sep": separator,
        "input_path": input_path,
        "output_path": output_path,
        "progress_callback": progress_callback
    })
    logging.info(f"✅ Scoring complete: {len(scored_df)} rules processed")
    
    if progress_callback:
        progress_callback("🔍 Tool: Augmenting with Migrate Insecure_AppID analysis", 65)
    logging.info("🔍 Starting Migrate Insecure_AppID augmentation...")
    
    # NEW: enrich with Migrate Insecure_AppID (reads catalog from all_sheets)
    scored_df = _augment_migrate_insecure(scored_df, all_sheets, separator, input_path, output_path, progress_callback)
    logging.info("✅ Migrate Insecure_AppID augmentation complete")
    
    if progress_callback:
        progress_callback("💾 Tool: Writing scored data to Excel file", 75)
    logging.info("💾 Writing scored data to Excel file...")
    
    # Write to Excel
    result = _write_excel({
        "df": scored_df,
        "all_sheets": all_sheets,
        "input_path": input_path,
        "output_path": output_path,
        "sep": separator,
        "sheet": sheet_name,
        "progress_callback": progress_callback
    })
    logging.info(f"✅ Excel file written: {result.get('saved_file', 'N/A')}")
    
    if progress_callback:
        progress_callback("✅ Tool: Scoring process completed successfully", 100)
    logging.info("🎉 Scoring process completed successfully")
    
    return result

@mcp.resource("scored://{basename}.xlsx", mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
def fetch_scored_excel(basename: str) -> bytes:
    p = Path(OUT_DIR) / f"{basename}.xlsx"
    return p.read_bytes()

# ----------------------------
# CLI / STDIO entry
# ----------------------------
def main():
    ap = argparse.ArgumentParser(description="Over-permissive scorer with inline points (insecure points inside Service_Insecure_Match)")
    ap.add_argument("--mcp", action="store_true", help="Run as MCP stdio server")
    ap.add_argument("--input", dest="input_path", help="Path to .xlsx")
    ap.add_argument("--sheet", dest="sheet_name", default=None, help="Sheet (tries rules_curated, rules_expanded, then first)")
    ap.add_argument("--out", dest="output_path", default=os.path.join(OUT_DIR, OUT_BASENAME), help="Output .xlsx")
    ap.add_argument("--sep", dest="separator", default=SEP_DEFAULT, help="Token separator (default '; ')")
    ap.add_argument("--create-config", action="store_true", help="Create Scoring_Config sheet and exit")
    args = ap.parse_args()

    if args.mcp:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO)
        try:
            from mcp.server.fastmcp import stdio_server
            asyncio.run(mcp.run(stdio_server()))
        except Exception:
            mcp.run(transport="stdio")
        return

    if not args.input_path:
        ap.error("--input is required (unless --mcp)")

    # Handle create-config option (standalone)
    if args.create_config:
        success = create_scoring_config_sheet(args.input_path)
        if success:
            print("✅ Scoring_Config sheet created successfully!")
            print("📋 You can now edit the 'Enabled' column to control which categories award points")
            print("🔄 Run the scoring script again without --create-config to perform the scoring")
        else:
            print("❌ Failed to create Scoring_Config sheet")
        return

    # For normal scoring: automatically create config sheet if it doesn't exist
    print("🔍 Checking for Scoring_Config sheet...")
    success = create_scoring_config_sheet(args.input_path)
    if success:
        print("✅ Scoring_Config sheet is ready!")
        print("📋 Edit the 'Enabled' column in the Scoring_Config sheet to control which categories award points")
        print("🚀 Proceeding with scoring...")
    else:
        print("⚠️  Warning: Could not create/verify Scoring_Config sheet, using default scoring weights")
    
    # Also try to create config sheet in output file after scoring
    print("🔧 Will add Scoring_Config sheet to output file...")

    cfg = {"input_path": args.input_path, "sheet": args.sheet_name, "output_path": args.output_path, "sep": args.separator}
    res = write_chain.invoke(cfg)
    print(json.dumps(res, indent=2))

if __name__ == "__main__":
    main()
