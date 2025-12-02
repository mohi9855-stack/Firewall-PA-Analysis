
# pa_mcp_server_service_groups_folder.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
import io, os, re, time, uuid, sys, logging, asyncio
import os
import pandas as pd
from mcp.server.fastmcp import FastMCP

# ---- Multi-file helpers (services) ----
from pathlib import Path as _Path

def _iter_service_files(folder: str, recursive: bool = False):
    p = _Path(folder)
    if not p.is_dir():
        return
    walker = p.rglob("*") if recursive else p.iterdir()
    for f in walker:
        try:
            if f.is_file() and f.suffix.lower() in (".csv", ".xlsx", ".xls"):
                yield f
        except Exception:
            continue

def _read_and_concat_services(folder: str, kind: str, recursive: bool = False) -> pd.DataFrame:
    files = list(_iter_service_files(folder, recursive=recursive)) or []
    if not files:
        raise ValueError(f"No readable {kind} files found in: {folder}")
    dfs = []
    for f in files:
        try:
            if f.suffix.lower() == ".csv":
                df = pd.read_csv(f, dtype=str, keep_default_na=False)
            else:
                df = pd.read_excel(f, dtype=str).fillna("")
            df.columns = [str(c).strip() for c in df.columns]
            # Track source filename for each row
            df["Source File"] = os.path.basename(str(f))
            dfs.append(df)
        except Exception as e:
            print(f"[LOAD-ERR] {kind}: {f} -> {e}")
    if not dfs:
        raise ValueError(f"No usable {kind} dataframes after read in: {folder}")
    out = pd.concat(dfs, ignore_index=True).fillna("")
    out.columns = [str(c).strip() for c in out.columns]
    return out

def _dedupe_by_name_ci(_df: pd.DataFrame, name_col: str = "Name") -> pd.DataFrame:
    """De-duplicate by Name (case-insensitive). Prefer non-empty Location; else last wins."""
    if name_col not in _df.columns:
        return _df
    tmp = _df.copy()
    tmp["_key"] = tmp[name_col].astype(str).str.strip().str.casefold()
    if "Location" in tmp.columns:
        tmp["_loc_nonempty"] = tmp["Location"].astype(str).str.strip().ne("")
        tmp = tmp.sort_values(by=["_key", "_loc_nonempty"], ascending=[True, False])
        tmp = tmp.drop_duplicates("_key", keep="first").drop(columns=["_loc_nonempty"])
    else:
        tmp = tmp.drop_duplicates("_key", keep="last")
    return tmp.drop(columns=["_key"])


mcp = FastMCP("PA-Service-Groups-Folder")

# Joiner for consolidated leaves
CONSOLIDATE_DELIM = "; "

# File detection
SEARCH_RECURSIVELY = True
SERVICES_FILE_CANDIDATES = [
    "services.csv",
    "services.xlsx",
]
GROUPS_FILE_CANDIDATES = [
    "service groups.csv",
    "service_groups.csv",
    "services groups.csv",
    "services_groups.csv",
    "service-groups.csv",
    "servicegroups.csv",
    "service groups.xlsx",
    "service_groups.xlsx",
]

@dataclass
class ServiceObj:
    name: str
    protocol: str           # TCP | UDP | ICMP | SCTP | ANY | UNKNOWN
    ports: List[str]        # normalized tokens like '443', '80-90', 'any'
    tags: Set[str] = field(default_factory=set)
    location: str = ""

@dataclass
class ServiceGroup:
    name: str
    type: str               # static | dynamic
    static_members: List[str] = field(default_factory=list)
    dynamic_filter: Optional[str] = None
    location: str = ""

class Store:
    def __init__(self) -> None:
        self.services: Dict[str, ServiceObj] = {}
        self.groups: Dict[str, ServiceGroup] = {}
        self.df_groups: Optional[pd.DataFrame] = None
        self._xlsx_blobs: Dict[str, bytes] = {}
        # last found paths for transparency
        self.services_path: Optional[str] = None
        self.groups_path: Optional[str] = None
        # case-insensitive name indexes
        self._svc_index: Dict[str, str] = {}
        self._grp_index: Dict[str, str] = {}

    def put_xlsx(self, data: bytes) -> str:
        job_id = f"{int(time.time())}-{uuid.uuid4().hex[:8]}"
        self._xlsx_blobs[job_id] = data
        return job_id

    def get_xlsx(self, job_id: str) -> bytes:
        return self._xlsx_blobs[job_id]

STORE = Store()

def clear_store():
    """Clear the global store to prevent data contamination between clients."""
    STORE.services.clear()
    STORE.groups.clear()
    STORE.df_groups = None
    STORE._xlsx_blobs.clear()
    STORE.services_path = None
    STORE.groups_path = None
    STORE._svc_index.clear()
    STORE._grp_index.clear()

# ---------------------
# Helpers / Normalizers
# ---------------------
def _norm(s: str) -> str:
    return re.sub(r'[^a-z0-9]+','', str(s).strip().lower())

def _casekey(s: str) -> str:
    # normalize: casefold + unify separators and prefixes
    ks = str(s).strip().casefold()
    # underscore/slash to dash
    ks = ks.replace('_', '-').replace('/', '-')
    # unify "proto + range" variants to a single proto-<rest> form
    # e.g., tcp-range-6095-6100, tcp_range_6095_6100, tcp/range/6095/6100  -> tcp-6095-6100
    ks = re.sub(r'^(tcp|udp|icmp)-?range-?', r'\1-', ks)
    # collapse any double (or more) dashes left by the previous steps
    ks = re.sub(r'-{2,}', '-', ks)
    return ks


def _split_list(s: str) -> List[str]:
    if s is None:
        return []
    s = str(s)
    if not s.strip():
        return []
    parts = re.split(r'[;,\n]+', s)
    return [p.strip() for p in parts if p.strip()]

def _split_ports(s: str) -> List[str]:
    # Accept comma/semicolon separated ranges or single ports, keep ranges intact
    tokens: List[str] = []
    for chunk in re.split(r'[;,\n]+', str(s).strip()):
        c = chunk.strip()
        if not c: 
            continue
        # break further by whitespace or commas inside
        for sub in re.split(r'[,\s]+', c):
            if not sub.strip():
                continue
            tokens.append(sub.strip())
    return tokens

def _normalize_protocol(raw: str) -> str:
    r = str(raw).strip().upper()
    if r in ("TCP", "UDP", "ICMP", "SCTP", "ANY"):
        return r
    # common variants
    if r in ("TCPV4","TCPV6","TCP/IP"):
        return "TCP"
    if r in ("UDPV4","UDPV6"):
        return "UDP"
    return "UNKNOWN"

def _normalize_port_token(tok: str) -> str:
    t = str(tok).strip()
    if not t:
        return ""
    # keep digits or range "start-end" as-is; map "*", "any" to "any"
    if t == "*" or t.lower() == "any":
        return "any"
    if re.fullmatch(r'\d+', t):
        return str(int(t))  # remove leading zeros
    if re.fullmatch(r'\d+\-\d+', t):
        lo, hi = t.split("-")
        return f"{int(lo)}-{int(hi)}"
    # allow common service words (e.g., "https") but keep literal
    return t.lower()

def _format_service_leaf(svc: ServiceObj) -> List[str]:
    # normalize protocol/ports -> "PROTO/PORTTOKEN"
    proto = _normalize_protocol(svc.protocol)
    out: List[str] = []
    if not svc.ports:
        # some services may not have explicit ports (e.g., ANY)
        out.append(f"{proto}/any" if proto != "UNKNOWN" else "unknown")
        return out
    for p in svc.ports:
        ptok = _normalize_port_token(p)
        if not ptok:
            continue
        out.append(f"{proto}/{ptok}")
    if not out:
        return [svc.name]
    return out

# Tag filter for dynamic groups (same mini-language as address variant)
_TAG_TOKEN = re.compile(r'"([^"]+)"|\'([^\']+)\'|([^\s]+)')
def _tag_filter_service(service: ServiceObj, expr: str) -> bool:
    if not expr:
        return False
    tokens = re.split(r'\s+(AND|OR|NOT)\s+', expr, flags=re.IGNORECASE)
    def _extract_token(s: str) -> str:
        m = _TAG_TOKEN.findall(s)
        if not m:
            return s.strip()
        for g1, g2, g3 in m:
            if g1: return g1
            if g2: return g2
            if g3: return g3
        return s.strip()

    def eval_clause(clause: str) -> bool:
        m_contains = re.match(r'^\s*tag\s+contains\s+(.+)$', clause, flags=re.IGNORECASE)
        m_has = re.match(r'^\s*tag\s+has\s+(.+)$', clause, flags=re.IGNORECASE)
        if m_contains:
            q = _extract_token(m_contains.group(1)).lower()
            return any(q in t.lower() for t in service.tags)
        if m_has:
            q = _extract_token(m_has.group(1)).lower()
            return any(q == t.lower() for t in service.tags)
        return False

    result: Optional[bool] = None
    pending_not = False
    op: Optional[str] = None
    i = 0
    while i < len(tokens):
        part = tokens[i]
        if part.upper() in ("AND", "OR", "NOT"):
            if part.upper() == "NOT":
                pending_not = not pending_not
            else:
                op = part.upper()
            i += 1
            continue
        val = eval_clause(part)
        if pending_not:
            val = not val
            pending_not = False
        if result is None:
            result = val
        else:
            if op == "AND":
                result = bool(result and val)
            elif op == "OR":
                result = bool(result or val)
            else:
                result = bool(result and val)
        i += 1
    return bool(result)

def _find_file(folder: str, candidates: List[str]) -> Optional[str]:
    """Find a file by trying exact candidate names (case-insensitive). Searches recursively if configured."""
    base = os.path.abspath(folder)
    if not os.path.isdir(base):
        return None
    want = [c.lower() for c in candidates]
    want_set = set(want)

    if SEARCH_RECURSIVELY:
        walker = ((root, files) for root, _, files in os.walk(base))
    else:
        walker = [(base, os.listdir(base))]

    # Prefer exact candidate matches; then fallback to fuzzy
    for root, files in walker:
        for f in files:
            if f.lower() in want_set:
                return os.path.join(root, f)

    # reset walker for fuzzy search
    if SEARCH_RECURSIVELY:
        walker = ((root, files) for root, _, files in os.walk(base))
    else:
        walker = [(base, os.listdir(base))]

    for root, files in walker:
        for f in files:
            lower = f.lower()
            if "service" in lower and any(lower.endswith(ext) for ext in [".csv", ".xlsx"]):
                return os.path.join(root, f)
    return None

def _read_table(path: str) -> pd.DataFrame:
    if path.lower().endswith((".xlsx", ".xls")):
        return pd.read_excel(path, dtype=str).fillna("")
    return pd.read_csv(path, dtype=str).fillna("")

# ---------------------
# Expansion
# ---------------------
def expand_service_group(name: str) -> Tuple[List[str], List[str]]:
    warnings: List[str] = []
    leaves: List[str] = []
    visited: Set[str] = set()

    def resolve_service(n: str) -> Optional[str]:
        key = _casekey(n)
    # try exact, lowercase, and normalized
        if n in STORE.services:
            return n
        if n.lower() in STORE.services:
            return n.lower()
        if key in STORE._svc_index:
            return STORE._svc_index[key]
    # also handle proto prefix variants like tcp_, tcp/, udp_, udp/
        proto_variants = [
            key.replace("tcp_", "tcp-").replace("udp_", "udp-"),
            key.replace("tcp/", "tcp-").replace("udp/", "udp-"),
        ]
        for k in proto_variants:
            if k in STORE._svc_index:
                return STORE._svc_index[k]
        return None


    def resolve_group(n: str) -> Optional[str]:
        if n in STORE.groups:
            return n
        return STORE._grp_index.get(_casekey(n))

    def dfs(obj_name: str):
        if obj_name in visited:
            warnings.append(f"Cycle detected at '{obj_name}'")
            return

        svc_key = resolve_service(obj_name)
        if svc_key:
            visited.add(obj_name)
            svc = STORE.services[svc_key]
            leaves.extend(_format_service_leaf(svc))
            return

        grp_key = resolve_group(obj_name)
        if grp_key:
            visited.add(obj_name)
            grp = STORE.groups[grp_key]
            if grp.type.lower() == "static":
                for m in grp.static_members:
                    dfs(m)
            else:
                expr = grp.dynamic_filter or ""
                for svc in STORE.services.values():
                    if _tag_filter_service(svc, expr):
                        leaves.extend(_format_service_leaf(svc))
            return

        warnings.append(f"Unknown object '{obj_name}'")
        leaves.append(obj_name)

    dfs(name)

    # de-duplicate but keep original order
    uniq = []
    seen = set()
    for v in leaves:
        v = str(v).strip()
        if v and v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq, warnings

# ---------------------
# Tools
# ---------------------
@mcp.tool()
def load_service_data_from_folder(folder: str, services_filename: Optional[str] = None, groups_filename: Optional[str] = None) -> dict:
    """
    Auto-detect and load Services + Service Groups from a folder.
    Accepts CSV or XLSX. Case-insensitive filename matching.
    You can override exact filenames via services_filename/groups_filename.
    """
    folder = os.path.abspath(folder)
    if not os.path.isdir(folder):
        raise ValueError(f"Not a directory: {folder}")

    svc_path = os.path.join(folder, services_filename) if services_filename else _find_file(folder, SERVICES_FILE_CANDIDATES)
    grp_path = os.path.join(folder, groups_filename) if groups_filename else _find_file(folder, GROUPS_FILE_CANDIDATES)

    if not svc_path:
        raise FileNotFoundError(f"Could not find Services file in: {folder}")
    if not grp_path:
        raise FileNotFoundError(f"Could not find Service Groups file in: {folder}")

    df_s = _read_table(svc_path)
    df_g = _read_table(grp_path)
    STORE.df_services = df_s.copy()

    s_map = { _norm(c): c for c in df_s.columns }
    g_map = { _norm(c): c for c in df_g.columns }

    # Services required columns
    k_name = s_map.get("name")
    k_proto = s_map.get("protocol")
    k_dport = s_map.get("destinationport") or s_map.get("destinationport/range") or s_map.get("destport") or s_map.get("serviceport") or s_map.get("ports")
    k_tags = s_map.get("tags")
    k_loc  = s_map.get("location")
    if not (k_name and k_proto and k_dport):
        raise ValueError("Services file must contain Name, Protocol, Destination Port columns.")

    STORE.services.clear()
    STORE.groups.clear()
    STORE.df_groups = None
    STORE._svc_index.clear()
    STORE._grp_index.clear()

    # Build services
    for _, r in df_s.iterrows():
        nm = str(r[k_name]).strip()
        if not nm: 
            continue
        proto = _normalize_protocol(r[k_proto])
        ports = _split_ports(r[k_dport])
        ports = [_normalize_port_token(p) for p in ports if _normalize_port_token(p)]
        tags  = set(_split_list(r[k_tags])) if k_tags else set()
        loc   = str(r[k_loc]).strip() if k_loc else ""
        STORE.services[nm] = ServiceObj(name=nm, protocol=proto, ports=ports, tags=tags, location=loc)
        STORE._svc_index[_casekey(nm)] = nm

    # Service Groups required columns
    g_name = g_map.get("name")
    g_services = g_map.get("services") or g_map.get("members")
    g_loc = g_map.get("location")
    g_dyn = g_map.get("dynamicfilter") or g_map.get("filters")
    if not g_name:
        raise ValueError("Service Groups file must contain 'Name'.")
    if not (g_services or g_dyn):
        raise ValueError("Service Groups file must have 'Services' (members) or a 'Dynamic Filter'.")

    for _, r in df_g.iterrows():
        nm = str(r[g_name]).strip()
        if not nm:
            continue
        members = _split_list(r[g_services]) if g_services else []
        dyn = str(r[g_dyn]).strip() if g_dyn else ""
        loc = str(r[g_loc]).strip() if g_loc else ""
        gtype = "dynamic" if dyn else "static"
        STORE.groups[nm] = ServiceGroup(name=nm, type=gtype, static_members=members, dynamic_filter=(dyn or None), location=loc)
        STORE._grp_index[_casekey(nm)] = nm

    # Preserve original groups DataFrame as-is
    STORE.df_groups = df_g.copy()
    STORE.services_path = svc_path
    STORE.groups_path = grp_path
    return {"services_loaded": len(STORE.services), "groups_loaded": len(STORE.groups), "services_path": svc_path, "groups_path": grp_path}



@mcp.tool()
def load_service_data_from_parent_folder(
    parent_folder: str,
    services_subdir: str = "Services",
    groups_subdir: str = "Service Groups",
    recursive: bool = True
) -> dict:
    """
    Pass the Parent folder which contains "Services" and "Service Groups" Folder.
    Case-insensitive filename matching. You can override exact filenames via app_filename/groups_filename
    """
    base = os.path.abspath(parent_folder)
    svc_dir = os.path.join(base, services_subdir)
    grp_dir = os.path.join(base, groups_subdir)
    # NEW: collect the exact files that will be read (absolute paths)
    services_files = [str(p) for p in _iter_service_files(svc_dir, recursive=recursive)]
    groups_files   = [str(p) for p in _iter_service_files(grp_dir, recursive=recursive)]
    if not services_files:
        raise ValueError(f"No Services files found in: {svc_dir}")
    if not groups_files:
        raise ValueError(f"No Service Groups files found in: {grp_dir}")


    df_s = _read_and_concat_services(svc_dir, "Services", recursive=recursive)
    df_g = _read_and_concat_services(grp_dir, "Service Groups", recursive=recursive)

    df_s = _dedupe_by_name_ci(df_s, "Name")
    df_g = _dedupe_by_name_ci(df_g, "Name")
    
    # --- Re-parse using single-file loader on combined CSVs to hydrate STORE.services/STORE.groups ---
    try:
        tmp_dir = os.path.join(base, "_tmp_combined_services_mcp")
        os.makedirs(tmp_dir, exist_ok=True)
        svc_tmp = os.path.join(tmp_dir, "services.csv")
        grp_tmp = os.path.join(tmp_dir, "service_groups.csv")
        df_s.to_csv(svc_tmp, index=False)
        df_g.to_csv(grp_tmp, index=False)
        # reuse existing single-file loader with explicit filenames
        load_service_data_from_folder(folder=tmp_dir,
            services_filename=os.path.basename(svc_tmp),
            groups_filename=os.path.basename(grp_tmp))
    except Exception as e:
        print(f"[WARN] Multi-file hydration via single-file loader failed: {e}")
# --- Hydrate STORE so expand_service_groups_consolidated() can see the data ---
    try:
        STORE.df_services = df_s.copy()
        STORE.df_groups   = df_g.copy()
        STORE.services_loaded = len(df_s)
        STORE.groups_loaded   = len(df_g)
    except Exception as e:
        print(f"[WARN] Could not set STORE attributes: {e}")

    try:
        meta = _load_from_dataframes(df_s, df_g)
    except NameError:
        meta = {"services_loaded": int(df_s.shape[0]), "groups_loaded": int(df_g.shape[0])}

    try:
        STORE.services_path = svc_dir
        STORE.groups_path = grp_dir
        meta.update({"services_path": svc_dir, "groups_path": grp_dir,"services_files": services_files,"groups_files": groups_files})
    except Exception:
        pass

    return meta



@mcp.tool()
def expand_service_groups_consolidated(save_filename: Optional[str] = None, purge_old: bool = True) -> dict:
    """
    Expand every service-group and merge normalized leaves back into the original Service Groups file:
    - Output has the SAME rows and columns as the input Service Groups file.
    - The 'Services' column is replaced with 'PROTO/PORT' entries (e.g., TCP/443; UDP/500-510).
    - Groups with no leaves remain with empty 'Services' cell.
    - Saves to a fixed filename (default: 'service_groups_merged.xlsx') and optionally purges old timestamped files.
    """
    if STORE.df_groups is None:
        raise RuntimeError("No Service Groups file loaded. Run load_service_data_from_folder first.")

    df_out = STORE.df_groups.copy()
    col_map = { _norm(c): c for c in df_out.columns }

    name_col = col_map.get("name")
    if name_col is None:
        raise RuntimeError("Could not find 'Name' column in Service Groups file.")

    svc_col = col_map.get("services")  # target column to replace; create if absent
    if svc_col is None:
        df_out["Services"] = ""
        svc_col = "Services"

    expanded_vals: List[str] = []
    warnings_all: List[str] = []

# Iterate in exact original order
    for _, row in df_out.iterrows():
        gname = str(row[name_col]).strip()

    # always capture the original members text so it's in scope
        original_members = str(row.get(svc_col, "")).strip()

    # If the group name is missing or not loaded, copy the original cell verbatim
        if not gname or gname not in STORE.groups:
            expanded_vals.append(original_members)
            if gname and gname not in STORE.groups:
                warnings_all.append(f"Group '{gname}' not found in parsed groups store")
            continue  # <-- this MUST be inside the if-block

    # Normal expansion path
        leaves, warns = expand_service_group(gname)
        warnings_all.extend([f"{gname}: {w}" for w in warns])
        consolidated = CONSOLIDATE_DELIM.join(leaves) if leaves else ""
        expanded_vals.append(consolidated)


    df_out[svc_col] = expanded_vals

    # Ensure 'Source File' column is visible near the front
    if "Source File" not in df_out.columns:
        df_out["Source File"] = ""
    preferred_cols = ["Name", "Location", "Source File", "Services", "Tags"]
    existing_cols = [c for c in preferred_cols if c in df_out.columns]
    remaining_cols = [c for c in df_out.columns if c not in existing_cols]
    df_out = df_out.reindex(columns=existing_cols + remaining_cols)

    # Write Excel to memory
    bio = io.BytesIO()
    with pd.ExcelWriter(bio, engine="openpyxl") as xw:
        df_out.to_excel(xw, sheet_name="Service Groups (Merged)", index=False)
        # ---------- BEGIN: Footer appending ALL Services into existing Name / Services / Location columns ----------
        try:
            df_services = getattr(STORE, "df_services", None)
            if df_services is not None and not df_services.empty:
                # 1) Normalize headers in Services table
                df_services = df_services.copy()
                df_services.columns = [str(c).strip() for c in df_services.columns]
                lower_map = {c.lower().replace(" ", "").replace("/", ""): c for c in df_services.columns}

                # 2) Identify Services table columns
                name_col_services = next((c for c in df_services.columns if c.strip().lower() == "name"), None)
                dport_col = (
                    lower_map.get("destinationport")
                    or lower_map.get("destinationportrange")
                    or lower_map.get("destport")
                    or lower_map.get("serviceport")
                    or lower_map.get("ports")
                )
                proto_col = lower_map.get("protocol")
                location_col_services = next((c for c in df_services.columns if c.strip().lower() == "location"), None)

                # 3) Identify EXISTING output columns (we only fill Name, Services, Location)
                name_col_out = name_col   # defined earlier
                svc_col_out  = svc_col    # defined earlier
                loc_col_out  = next((c for c in df_out.columns if c.strip().lower() == "location"), None)

                if name_col_services and dport_col and name_col_out and svc_col_out:
                    # 4) Build footer rows for ALL services (no filtering)
                    def _row_proto_port(r):
                        proto = _normalize_protocol(r[proto_col]) if proto_col else "ANY"
                        ports = _split_ports(r[dport_col]) if dport_col else []
                        parts = [f"{proto}/{_normalize_port_token(p)}" for p in ports if _normalize_port_token(p)]
                        if not parts:
                            parts = [f"{proto}/any"]
                        return CONSOLIDATE_DELIM.join(parts)

                    svc_series = df_services.apply(_row_proto_port, axis=1)

                    footer = pd.DataFrame({
                        name_col_out: df_services[name_col_services].astype(str).fillna("").str.strip(),
                        svc_col_out:  svc_series.astype(str).fillna("").str.strip()
                })


                    # Include Location if both sides have it
                    if loc_col_out and location_col_services:
                        footer[loc_col_out] = df_services[location_col_services].astype(str).fillna("").str.strip()

                    # 5) Make footer have exactly the same columns/order as df_out (others blank)
                    for col in df_out.columns:
                        if col not in footer.columns:
                            footer[col] = ""
                    footer = footer[df_out.columns]

                    # 6) Append into SAME sheet, directly below the analysis table, without headers
                    sheet_name = "Service Groups (Merged)"
                    startrow = df_out.shape[0] + 3  # adjust to +1 or +0 if you prefer fewer blank lines
                    footer.to_excel(
                        xw,
                        sheet_name=sheet_name,
                        startrow=startrow,
                        header=False,
                        index=False
                    )
        except Exception as _footer_err:
            # Footer is best-effort; do not block the main export
            pass
        # ---------- END: Footer block ----------


        inputs = [ {"services_path": STORE.services_path or "", "groups_path": STORE.groups_path or ""} ]
        pd.DataFrame(inputs).to_excel(xw, sheet_name="Inputs", index=False)
        if warnings_all:
            pd.DataFrame({"warnings": warnings_all}).to_excel(xw, sheet_name="Warnings", index=False)

    # Save to disk with fixed name (and purge older timestamped files if requested)
    out_dir = "./expansions"
    os.makedirs(out_dir, exist_ok=True)

    if purge_old:
        for old in os.listdir(out_dir):
            if re.match(r"^service_groups_merged.*\.xlsx$", old, flags=re.IGNORECASE):
                try:
                    os.remove(os.path.join(out_dir, old))
                except OSError:
                    pass

    fname = save_filename.strip() if (save_filename and save_filename.strip()) else "service_groups_merged.xlsx"
    if not fname.lower().endswith(".xlsx"):
        fname += ".xlsx"
    fpath = os.path.abspath(os.path.join(out_dir, fname))

    tmp_path = fpath + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(bio.getvalue())
    os.replace(tmp_path, fpath)  # atomic-ish replace

    # Expose resource
    job_id = STORE.put_xlsx(bio.getvalue())
    uri = f"expansion://{job_id}.xlsx"
    return {"excel_resource_uri": uri, "saved_file": fpath, "rows": int(df_out.shape[0]), "services_path": STORE.services_path, "groups_path": STORE.groups_path}

def _server_main_address():
    
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    try:
        from mcp.server.fastmcp import stdio_server
        asyncio.run(mcp.run(stdio_server()))
    except Exception:
        # fallback for older SDKs
        mcp.run(transport="stdio")  # type: ignore[attr-defined]

def _batch_main_address():
    import argparse, sys, os, shutil, traceback

    parser = argparse.ArgumentParser(description="Batch Address expansion")
    parser.add_argument("--parent-folder", required=True, help="Folder that contains subfolders for Addresses and Address Groups")
    parser.add_argument("--services-subdir", default="Services")
    parser.add_argument("--groups-subdir",   default="Service Groups")  # match your real folder name
    parser.add_argument("--recursive",       action="store_true")
    parser.add_argument("--out",             default="./expansions/service_groups_merged.xlsx")
    args = parser.parse_args()

    try:
        # 1) load multi-file
        _ = load_service_data_from_parent_folder(
            parent_folder=args.parent_folder,
            services_subdir=args.services_subdir,
            groups_subdir=args.groups_subdir,
            recursive=args.recursive
            
        )
        # 2) expand + write
        exp = expand_service_groups_consolidated(save_filename=os.path.basename(args.out),purge_old=True)

        out_abs = os.path.abspath(args.out)
        os.makedirs(os.path.dirname(out_abs), exist_ok=True)
        saved = exp.get("saved_file")
        if saved and os.path.abspath(saved) != out_abs:
            shutil.copyfile(saved, out_abs)
        elif not saved:
            raise RuntimeError("expand_groups_and_append_all_addresses did not return 'saved_file'")

        print(out_abs, flush=True)
        sys.exit(0)

    except Exception:
        traceback.print_exc()
        sys.exit(1)


@mcp.resource("expansion://{job_id}.xlsx", mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
def get_expansion_excel(job_id: str) -> bytes:
    return STORE.get_xlsx(job_id)

# --- STDIO entrypoint (SDK-version compatible)
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--mcp", action="store_true")
    # Only parse --mcp here; batch args are parsed inside _batch_main_address
    known, _ = p.parse_known_args()

    if known.mcp:
        _server_main_address()
    else:
        _batch_main_address()