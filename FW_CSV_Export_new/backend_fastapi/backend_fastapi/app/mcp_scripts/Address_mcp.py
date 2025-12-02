
# Address_mcp_folder_merge_addresses_v3.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
import io, os, re, time, uuid, sys, logging, asyncio
import pandas as pd

# === Multi-file merge helpers (non-breaking additions) ===
from pathlib import Path as _Path

def _read_and_concat(_folder: str, _kind: str) -> pd.DataFrame:
    """
    Read and concatenate all *.csv and *.xlsx files under '_folder' (non-recursive).
    Returns a single DataFrame with trimmed headers. Skips unreadable files.
    """
    p = _Path(_folder)
    all_files = []
    if p.is_dir():
        all_files.extend(list(p.glob("*.csv")))
        all_files.extend(list(p.glob("*.xlsx")))
    else:
        raise FileNotFoundError(f"{_kind} folder not found: {_folder}")

    dfs = []
    for f in all_files:
        try:
            if f.suffix.lower() == ".csv":
                dfs.append(pd.read_csv(f, dtype=str, keep_default_na=False))
            else:
                dfs.append(pd.read_excel(f, dtype=str).fillna(""))
        except Exception as _e:
            # Non-fatal: skip unreadable files
            print(f"[WARN] Skipped {_kind} file {f}: {_e}")
    if not dfs:
        raise ValueError(f"No readable {_kind} files found in: {_folder}")
    df = pd.concat(dfs, ignore_index=True).fillna("")
    df.columns = [str(c).strip() for c in df.columns]
    return df

def _dedupe_by_name_ci(_df: pd.DataFrame, name_col: str = "Name") -> pd.DataFrame:
    """De-duplicate by Name (case-insensitive). Prefer non-empty Location; else last wins."""
    if name_col not in _df.columns:
        raise KeyError(f"Expected column '{name_col}' not found in merged table.")
    tmp = _df.copy()
    tmp["_key"] = tmp[name_col].astype(str).str.strip().str.casefold()
    if "Location" in tmp.columns:
        tmp["_loc_nonempty"] = tmp["Location"].astype(str).str.strip().ne("")
        tmp = tmp.sort_values(by=["_key", "_loc_nonempty"], ascending=[True, False])
        tmp = tmp.drop_duplicates("_key", keep="first")
        tmp = tmp.drop(columns=["_loc_nonempty"])
    else:
        tmp = tmp.drop_duplicates("_key", keep="last")
    return tmp.drop(columns=["_key"]) 
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("PA-Address-Folder-Merge-Addresses")

# ---------------- Config ----------------
CONSOLIDATE_DELIM = "; "
SEARCH_RECURSIVELY = True  # set False to only scan the top-level folder

# File detection candidates (case-insensitive)
ADDRESSES_FILE_CANDIDATES = [
    "addresses.csv",
    "addresses.xlsx",
]
GROUPS_FILE_CANDIDATES = [
    "address groups.csv",
    "address_groups.csv",
    "addresses groups.csv",
    "addresses_groups.csv",
    "address-groups.csv",
    "addressgroups.csv",
    "address groups.xlsx",
    "address_groups.xlsx",
]

# ---------------- Data classes ----------------
@dataclass
class AddressObj:
    name: str
    type: str   # ip-netmask | ip-range | fqdn | unknown
    value: str
    tags: Set[str] = field(default_factory=set)
    location: str = ""

@dataclass
class AddressGroup:
    name: str
    type: str   # static | dynamic
    static_members: List[str] = field(default_factory=list)
    dynamic_filter: Optional[str] = None
    location: str = ""

class Store:
    def __init__(self) -> None:
        self.addresses: Dict[str, AddressObj] = {}
        self.groups: Dict[str, AddressGroup] = {}
        self.df_groups: Optional[pd.DataFrame] = None
        self._xlsx_blobs: Dict[str, bytes] = {}
        # last located paths
        self.addresses_path: Optional[str] = None
        self.groups_path: Optional[str] = None
        # case-insensitive name index
        self.addr_index_ci: Dict[str, str] = {}  # casefold(name) -> canonical name
        self.group_index_ci: Dict[str, str] = {}

    def put_xlsx(self, data: bytes) -> str:
        job_id = f"{int(time.time())}-{uuid.uuid4().hex[:8]}"
        self._xlsx_blobs[job_id] = data
        return job_id

    def get_xlsx(self, job_id: str) -> bytes:
        return self._xlsx_blobs[job_id]

STORE = Store()

def clear_store():
    """Clear the global store to prevent data contamination between clients."""
    STORE.addresses.clear()
    STORE.groups.clear()
    STORE.df_groups = None
    STORE._xlsx_blobs.clear()
    STORE.addresses_path = None
    STORE.groups_path = None
    STORE.addr_index_ci.clear()
    STORE.group_index_ci.clear()

# ---------------- Helpers ----------------
def _norm(s: str) -> str:
    return re.sub(r'[^a-z0-9]+','', str(s).strip().lower())

def _casekey(s: str) -> str:
    return str(s).strip().casefold()

def _map_addr_type(raw: str) -> str:
    r = str(raw).strip().lower()
    if r in ("ip netmask", "ipnetmask", "ip_subnet", "subnet"):
        return "ip-netmask"
    if r in ("ip range", "iprange", "range"):
        return "ip-range"
    if r in ("fqdn", "dns", "hostname"):
        return "fqdn"
    return "unknown"

def _split_members(val: str) -> List[str]:
    if val is None:
        return []
    s = str(val).strip()
    if not s:
        return []
    # split on semicolon/comma/newline; keep quoted tokens intact
    parts = re.split(r'[;,\n]+', s)
    out = []
    for p in parts:
        t = p.strip().strip('"').strip("'")
        if t:
            out.append(t)
    return out

def _split_tags(val: str) -> Set[str]:
    if val is None:
        return set()
    s = str(val).strip()
    if not s:
        return set()
    parts = re.split(r'[;,\s]+', s)
    return set(p.strip() for p in parts if p.strip())

_TAG_TOKEN = re.compile(r'"([^"]+)"|\'([^\']+)\'|([^\s]+)')
def _tag_filter(address: AddressObj, expr: str) -> bool:
    """Mini-language for dynamic groups: tag contains foo AND NOT tag has "bar baz" """
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
            return any(q in t.lower() for t in address.tags)
        if m_has:
            q = _extract_token(m_has.group(1)).lower()
            return any(q == t.lower() for t in address.tags)
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
    """Find a file by trying candidate names (case-insensitive). Searches recursively if configured."""
    base = os.path.abspath(folder)
    if not os.path.isdir(base):
        return None
    want = {c.lower() for c in candidates}

    # Prefer exact candidate matches; then fallback to fuzzy
    if SEARCH_RECURSIVELY:
        walker = ((root, files) for root, _, files in os.walk(base))
    else:
        walker = [(base, os.listdir(base))]

    for root, files in walker:
        for f in files:
            if f.lower() in want:
                return os.path.join(root, f)

    # reset walker for fuzzy search
    if SEARCH_RECURSIVELY:
        walker = ((root, files) for root, _, files in os.walk(base))
    else:
        walker = [(base, os.listdir(base))]

    for root, files in walker:
        for f in files:
            lower = f.lower()
            if any(tok in lower for tok in ["address"]) and any(lower.endswith(ext) for ext in [".csv", ".xlsx"]):
                return os.path.join(root, f)
    return None

def _read_table(path: str) -> pd.DataFrame:
    if path.lower().endswith((".xlsx", ".xls")):
        return pd.read_excel(path, dtype=str).fillna("")
    return pd.read_csv(path, dtype=str).fillna("")

# ---------------- Expansion ----------------
def expand_group(name: str) -> Tuple[List[str], List[str]]:
    """Return (leaf address VALUES, warnings) for a group name."""
    warnings: List[str] = []
    leaves: List[str] = []
    visited: Set[str] = set()

    def dfs(obj_name: str):
        if obj_name in visited:
            warnings.append(f"Cycle detected at '{obj_name}'")
            return
        visited.add(obj_name)

        # resolve addresses/groups case-insensitively
        ak = STORE.addr_index_ci.get(_casekey(obj_name))
        gk = STORE.group_index_ci.get(_casekey(obj_name))

        if ak:
            leaves.append(STORE.addresses[ak].value)
            return
        if gk:
            grp = STORE.groups[gk]
            if grp.type == "static":
                for m in grp.static_members:
                    dfs(m)
            else:
                expr = grp.dynamic_filter or ""
                for addr in STORE.addresses.values():
                    if _tag_filter(addr, expr):
                        leaves.append(addr.value)
            return
        warnings.append(f"Unknown object '{obj_name}'")

    dfs(name)
    uniq = sorted(set([v for v in leaves if str(v).strip() != ""]))
    return uniq, warnings

# ---------------- Tools ----------------
@mcp.tool()
def load_address_data_from_folder(folder: str, addresses_filename: Optional[str] = None, groups_filename: Optional[str] = None) -> dict:
    """
    Auto-detect and load Addresses + Address Groups from a folder.
    Accepts CSV or XLSX. Case-insensitive filename matching.
    You can override exact filenames via addresses_filename/groups_filename.
    """
    folder = os.path.abspath(folder)
    if not os.path.isdir(folder):
        raise ValueError(f"Not a directory: {folder}")

    addr_path = os.path.join(folder, addresses_filename) if addresses_filename else _find_file(folder, ADDRESSES_FILE_CANDIDATES)
    grp_path  = os.path.join(folder, groups_filename) if groups_filename else _find_file(folder, GROUPS_FILE_CANDIDATES)

    if not addr_path:
        raise FileNotFoundError(f"Could not find Addresses file in: {folder}")
    if not grp_path:
        raise FileNotFoundError(f"Could not find Address Groups file in: {folder}")

    df_a = _read_table(addr_path)
    df_g = _read_table(grp_path)

    a_map = { _norm(c): c for c in df_a.columns }
    g_map = { _norm(c): c for c in df_g.columns }

    # Addresses required columns
    k_name = a_map.get("name")
    k_type = a_map.get("type")  # we will NOT output this later
    k_value = a_map.get("address") or a_map.get("value")
    k_tags = a_map.get("tags")
    k_loc  = a_map.get("location")
    if not (k_name and k_type and k_value):
        raise ValueError("Addresses file must have columns: Name, Type, Address/Value")

    STORE.addresses.clear()
    STORE.groups.clear()
    STORE.df_groups = None
    STORE.addr_index_ci.clear()
    STORE.group_index_ci.clear()

    for _, r in df_a.iterrows():
        nm = str(r[k_name]).strip()
        if not nm: continue
        typ = str(r[k_type]).strip()
        val = str(r[k_value]).strip()
        tags = _split_tags(r[k_tags]) if k_tags else set()
        loc  = str(r[k_loc]).strip() if k_loc else ""
        ao = AddressObj(name=nm, type=typ, value=val, tags=tags, location=loc)
        STORE.addresses[nm] = ao
        STORE.addr_index_ci[_casekey(nm)] = nm

    # Groups: accept 'Addresses' / 'Members' / 'StaticMembers' as member list; 'DynamicFilter' or 'Filters' as dynamic
    g_name = g_map.get("name")
    g_members = g_map.get("addresses") or g_map.get("members") or g_map.get("staticmembers")
    g_loc = g_map.get("location")
    g_dyn = g_map.get("dynamicfilter") or g_map.get("filters")
    if not (g_name and g_members):
        raise ValueError("Address Groups file must have columns: Name and Addresses (members)")

    for _, r in df_g.iterrows():
        nm = str(r[g_name]).strip()
        if not nm: continue
        members = _split_members(r[g_members])
        dyn = str(r[g_dyn]).strip() if g_dyn else ""
        loc = str(r[g_loc]).strip() if g_loc else ""
        gtype = "dynamic" if dyn else "static"
        grp = AddressGroup(name=nm, type=gtype, static_members=members, dynamic_filter=(dyn or None), location=loc)
        STORE.groups[nm] = grp
        STORE.group_index_ci[_casekey(nm)] = nm

    STORE.df_groups = df_g.copy()
    STORE.addresses_path = addr_path
    STORE.groups_path = grp_path

    return {
        "addresses_loaded": len(STORE.addresses),
        "groups_loaded": len(STORE.groups),
        "addresses_path": addr_path,
        "groups_path": grp_path
    }


@mcp.tool()
def load_address_data_from_parent_folder(parent_folder: str,
                                         addresses_subdir: str = "Addresses",
                                         groups_subdir: str = "Address Groups") -> dict:
    """
    Load Addresses + Address Groups from two subfolders under a parent folder.
    - parent_folder/addresses/: all CSV/XLSX are concatenated and de-duplicated (by Name)
    - parent_folder/address_groups/: all CSV/XLSX are concatenated and de-duplicated (by Name)
    This is additive and does NOT change the existing single-file loader.
    """
    base = os.path.abspath(parent_folder)
    addr_dir = os.path.join(base, addresses_subdir)
    grp_dir  = os.path.join(base, groups_subdir)

    df_a = _read_and_concat(addr_dir, "Addresses")
    df_g = _read_and_concat(grp_dir, "Address Groups")

    def _colmap(df):
        return { re.sub(r'[^a-z0-9]+','', str(c).strip().lower()): c for c in df.columns }

    a_map = _colmap(df_a)
    g_map = _colmap(df_g)

    k_name = a_map.get("name")
    k_type = a_map.get("type")
    k_value = a_map.get("address") or a_map.get("value")
    k_tags = a_map.get("tags")
    k_loc  = a_map.get("location")
    if not (k_name and k_type and k_value):
        raise ValueError("Addresses merged table must have: Name, Type, Address/Value")

    df_a = _dedupe_by_name_ci(df_a, name_col=k_name)
    df_g = _dedupe_by_name_ci(df_g, name_col=(g_map.get("name") or "Name"))

    STORE.addresses.clear()
    STORE.groups.clear()
    STORE.df_groups = None
    STORE.addr_index_ci.clear()
    STORE.group_index_ci.clear()

    for _, r in df_a.iterrows():
        nm = str(r[k_name]).strip()
        if not nm: 
            continue
        typ = str(r[k_type]).strip()
        val = str(r[k_value]).strip()
        tags = _split_tags(r[k_tags]) if k_tags else set()
        loc  = str(r[k_loc]).strip() if k_loc else ""
        ao = AddressObj(name=nm, type=typ, value=val, tags=tags, location=loc)
        STORE.addresses[nm] = ao
        STORE.addr_index_ci[_casekey(nm)] = nm

    g_name = g_map.get("name")
    g_members = g_map.get("addresses") or g_map.get("members") or g_map.get("staticmembers")
    g_loc = g_map.get("location")
    g_dyn = g_map.get("dynamicfilter") or g_map.get("filters")
    if not (g_name and g_members):
        raise ValueError("Address Groups merged table must have: Name and Addresses/Members")

    for _, r in df_g.iterrows():
        nm = str(r[g_name]).strip()
        if not nm: 
            continue
        members = _split_members(r[g_members])
        dyn = str(r[g_dyn]).strip() if g_dyn else ""
        loc = str(r[g_loc]).strip() if g_loc else ""
        gtype = "dynamic" if dyn else "static"
        grp = AddressGroup(name=nm, type=gtype, static_members=members, dynamic_filter=(dyn or None), location=loc)
        STORE.groups[nm] = grp
        STORE.group_index_ci[_casekey(nm)] = nm

    STORE.df_groups = df_g.copy()
    STORE.addresses_path = addr_dir
    STORE.groups_path = grp_dir

    return {
        "addresses_loaded": len(STORE.addresses),
        "groups_loaded": len(STORE.groups),
        "addresses_path": addr_dir,
        "groups_path": grp_dir
    }

@mcp.tool()
def expand_groups_and_append_all_addresses(output_column: Optional[str] = None, purge_old: bool = True) -> dict:
    """
    Expand groups to leaf values and write them back to the Address Groups table.
    Then APPEND ALL rows from Addresses.csv mapped as:
      Name -> Name, Location -> Location, Address -> <output_column>, Tags -> Tags
    The 'Type' column from addresses is intentionally NOT added.
    output_column: target column name for the consolidated values; if None,
                   prefers existing 'Addresses', else existing 'Address', else creates 'Addresses'.
    """
    if STORE.df_groups is None:
        raise RuntimeError("No groups file loaded. Run load_address_data_from_folder first.")

    df_out = STORE.df_groups.copy()
    col_map = { _norm(c): c for c in df_out.columns }

    name_col = col_map.get("name")
    if name_col is None:
        raise RuntimeError("Could not find 'Name' column in Address Groups file.")

    # choose target column
    if output_column and output_column.strip():
        addr_col = output_column.strip()
        if addr_col not in df_out.columns:
            df_out[addr_col] = ""
    else:
        addr_col = col_map.get("addresses") or col_map.get("address")
        if not addr_col:
            addr_col = "Addresses"
            df_out[addr_col] = ""

    # expand each group
    expanded_vals: List[str] = []
    warnings_all: List[str] = []

    for _, row in df_out.iterrows():
        gname = str(row[name_col]).strip()
        if not gname or _casekey(gname) not in STORE.group_index_ci:
            expanded_vals.append("")
            if gname and _casekey(gname) not in STORE.group_index_ci:
                warnings_all.append(f"Group '{gname}' not found in parsed groups store")
            continue

        leaf_values, warns = _expand_group_for_tool(gname)
        warnings_all.extend([f"{gname}: {w}" for w in warns])
        consolidated = CONSOLIDATE_DELIM.join(leaf_values) if leaf_values else ""
        expanded_vals.append(consolidated)

    df_out[addr_col] = expanded_vals

    # append ALL addresses.csv rows with mapped columns (Type intentionally excluded)
    # ensure standard columns exist in df_out
    if "Location" not in df_out.columns and any(ao.location for ao in STORE.addresses.values()):
        df_out["Location"] = ""
    if "Tags" not in df_out.columns and any(ao.tags for ao in STORE.addresses.values()):
        df_out["Tags"] = ""

    extra_rows = []
    for nm, ao in STORE.addresses.items():
        row = { col: "" for col in df_out.columns }
        # Map: Name -> Name
        if name_col in df_out.columns:
            row[name_col] = nm
        else:
            row["Name"] = nm
        # Map: Location -> Location (if present)
        if "Location" in df_out.columns:
            row["Location"] = ao.location
        # Map: Address -> output column
        row[addr_col] = ao.value
        # Map: Tags -> Tags (if present)
        if "Tags" in df_out.columns:
            row["Tags"] = "; ".join(sorted(ao.tags)) if ao.tags else ""

        extra_rows.append(row)

    if extra_rows:
        df_out = pd.concat([df_out, pd.DataFrame(extra_rows)], ignore_index=True)

    # Ensure 'Location' column exists and is placed prominently before writing
    if "Location" not in df_out.columns:
        df_out["Location"] = ""
    preferred_cols = ["Name", "Location", addr_col, "Tags"]
    existing_cols = [c for c in preferred_cols if c in df_out.columns]
    remaining = [c for c in df_out.columns if c not in existing_cols]
    df_out = df_out.reindex(columns=existing_cols + remaining)

    # Excel output
    bio = io.BytesIO()
    with pd.ExcelWriter(bio, engine="openpyxl") as xw:
        df_out.to_excel(xw, sheet_name="Groups (Merged + All Addresses)", index=False)

        inputs = [ {
            "addresses_path": STORE.addresses_path or "",
            "groups_path": STORE.groups_path or "",
            "output_column": addr_col,
        } ]
        pd.DataFrame(inputs).to_excel(xw, sheet_name="Inputs", index=False)
        if warnings_all:
            pd.DataFrame({"warnings": warnings_all}).to_excel(xw, sheet_name="Warnings", index=False)

    # Save with fixed filename and atomic replace
    out_dir = "./expansions"
    os.makedirs(out_dir, exist_ok=True)
    
    # Purge old files if requested
    if purge_old:
        for old in os.listdir(out_dir):
            if re.match(r"^address_groups_merged.*\.xlsx$", old, flags=re.IGNORECASE):
                try:
                    os.remove(os.path.join(out_dir, old))
                except OSError:
                    pass

    fpath = os.path.abspath(os.path.join(out_dir, "address_groups_merged.xlsx"))
    tmp_path = fpath + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(bio.getvalue())
    os.replace(tmp_path, fpath)

    # Expose as MCP resource
    job_id = STORE.put_xlsx(bio.getvalue())
    uri = f"expansion://{job_id}.xlsx"
    return {
        "excel_resource_uri": uri,
        "saved_file": fpath,
        "rows": int(df_out.shape[0]),
        "addresses_path": STORE.addresses_path,
        "groups_path": STORE.groups_path,
        "output_column": addr_col,
    }

def _expand_group_for_tool(group_name: str) -> Tuple[List[str], List[str]]:
    return expand_group(group_name)
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
    parser.add_argument("--addresses-subdir", default="Addresses")
    parser.add_argument("--groups-subdir",   default="Address Groups")  # match your real folder name
    parser.add_argument("--recursive",       action="store_true")
    parser.add_argument("--out",             default="./expansions/address_groups_merged.xlsx")
    args = parser.parse_args()

    try:
        # 1) load multi-file
        _ = load_address_data_from_parent_folder(
            parent_folder=args.parent_folder,
            addresses_subdir=args.addresses_subdir,
            groups_subdir=args.groups_subdir,
            
        )
        # 2) expand + write
        exp = expand_groups_and_append_all_addresses(output_column=None)

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

# --- STDIO entrypoint (SDK-version compatible) ---
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
