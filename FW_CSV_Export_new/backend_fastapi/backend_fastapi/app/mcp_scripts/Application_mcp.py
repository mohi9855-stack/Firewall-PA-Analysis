
# pa_mcp_server_application_groups_map_attribute_folder.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
import io, os, re, time, uuid, sys, logging, asyncio
import pandas as pd
from mcp.server.fastmcp import FastMCP

# ---- Multi-file helpers (applications) ----
from pathlib import Path as _Path

def _iter_app_files(folder: str, recursive: bool = False):
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

def _read_and_concat_apps(folder: str, kind: str, recursive: bool = False) -> pd.DataFrame:
    files = list(_iter_app_files(folder, recursive=recursive)) or []
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
        raise KeyError(f"Expected column '{name_col}' not found in merged table.")
    tmp = _df.copy()
    tmp["_key"] = tmp[name_col].astype(str).str.strip().str.casefold()
    if "Location" in tmp.columns:
        tmp["_loc_nonempty"] = tmp["Location"].astype(str).str.strip().ne("")
        tmp = tmp.sort_values(by=["_key", "_loc_nonempty"], ascending=[True, False])
        tmp = tmp.drop_duplicates("_key", keep="first").drop(columns=["_loc_nonempty"])
    else:
        tmp = tmp.drop_duplicates("_key", keep="last")
    return tmp.drop(columns=["_key"])


mcp = FastMCP("PA-App-Groups-Map-Attribute-Folder")

# ---------------- Config ----------------
CONSOLIDATE_DELIM = "; "
CASE_INSENSITIVE_LOOKUPS = True
SPLIT_PATTERN = r"[;,\n]+"

# Attribute mapping defaults
DEFAULT_TARGET_APP_FIELD = "Address"     # what to pull from Applications.csv (fallbacks apply)
DEFAULT_OUTPUT_COLUMN = "Applications"   # which column in Groups to write
DEFAULT_REPLACE_MEMBER_COLUMN = True     # overwrite column if True; else create new column
INCLUDE_UNRESOLVED_TOKENS_IN_OUTPUT = True

# File detection
SEARCH_RECURSIVELY = True
APPS_FILE_CANDIDATES = [
    "applications.csv",
    "applications.xlsx",
]
GROUPS_FILE_CANDIDATES = [
    "application groups.csv",
    "application_groups.csv",
    "applications groups.csv",
    "applications_groups.csv",
    "app groups.csv",
    "app_groups.csv",
    "application-groups.csv",
    "applicationgroups.csv",
    "application groups.xlsx",
    "application_groups.xlsx",
]

@dataclass
class ApplicationObj:
    name: str
    attrs: dict

@dataclass
class ApplicationGroup:
    name: str
    members: List[str] = field(default_factory=list)  # can include apps or nested groups
    dynamic_filter: Optional[str] = None
    location: str = ""

class Store:
    def __init__(self) -> None:
        self.apps: Dict[str, ApplicationObj] = {}
        self.groups: Dict[str, ApplicationGroup] = {}
        self.df_groups: Optional[pd.DataFrame] = None
        self._xlsx_blobs: Dict[str, bytes] = {}
        self._app_index: Dict[str, str] = {}
        self._group_index: Dict[str, str] = {}

        # last-located files (for transparency)
        self.apps_path: Optional[str] = None
        self.groups_path: Optional[str] = None

    def put_xlsx(self, data: bytes) -> str:
        job_id = f"{int(time.time())}-{uuid.uuid4().hex[:8]}"
        self._xlsx_blobs[job_id] = data
        return job_id

    def get_xlsx(self, job_id: str) -> bytes:
        return self._xlsx_blobs[job_id]

STORE = Store()

def clear_store():
    """Clear the global store to prevent data contamination between clients."""
    STORE.apps.clear()
    STORE.groups.clear()
    STORE.df_groups = None
    STORE._xlsx_blobs.clear()
    STORE._app_index.clear()
    STORE._group_index.clear()
    STORE.apps_path = None
    STORE.groups_path = None

# -------------- Helpers --------------
def _norm(s: str) -> str:
    return re.sub(r'[^a-z0-9]+','', str(s).strip().lower())

def _casekey(s: str) -> str:
    return str(s).strip().casefold()

def _split_list(s: str) -> List[str]:
    if s is None:
        return []
    s = str(s)
    if not s.strip():
        return []
    parts = re.split(SPLIT_PATTERN, s)
    return [p.strip() for p in parts if p.strip()]

def _resolve_name(name: str, kind: str) -> Optional[str]:
    if not CASE_INSENSITIVE_LOOKUPS:
        if kind == "app":
            return name if name in STORE.apps else None
        return name if name in STORE.groups else None
    key = _casekey(name)
    idx = STORE._app_index if kind == "app" else STORE._group_index
    return idx.get(key)

def _find_file(folder: str, candidates: List[str]) -> Optional[str]:
    """Find a file by trying exact candidate names (case-insensitive). Searches recursively if configured."""
    base = os.path.abspath(folder)
    if not os.path.isdir(base):
        return None
    want = [c.lower() for c in candidates]
    # build candidate set for fast check
    want_set = set(want)

    if SEARCH_RECURSIVELY:
        walker = ((root, files) for root, _, files in os.walk(base))
    else:
        walker = [(base, os.listdir(base))]

    best_match = None
    for root, files in walker:
        for f in files:
            lower = f.lower()
            if lower in want_set:
                best_match = os.path.join(root, f)
                return best_match  # first exact match wins
        # fuzzy: look for files that contain key tokens if exact not found
        for f in files:
            lower = f.lower()
            # simple token rules
            if any(x in lower for x in ["applications"]) and any(lower.endswith(ext) for ext in [".csv", ".xlsx"]):
                if candidates is APPS_FILE_CANDIDATES and "group" not in lower:
                    best_match = os.path.join(root, f)
                    # don't return yet—prefer exact; but keep as fallback
            if any(x in lower for x in ["group"]) and any(lower.endswith(ext) for ext in [".csv", ".xlsx"]):
                if candidates is GROUPS_FILE_CANDIDATES and any(tok in lower for tok in ["application","app"]):
                    best_match = os.path.join(root, f)
    return best_match

def _read_table(path: str) -> pd.DataFrame:
    if path.lower().endswith((".xlsx", ".xls")):
        return pd.read_excel(path, dtype=str).fillna("")
    return pd.read_csv(path, dtype=str).fillna("")

# -------------- Data loading --------------
def _load_from_dataframes(df_a: pd.DataFrame, df_g: pd.DataFrame) -> dict:
    a_map = { _norm(c): c for c in df_a.columns }
    g_map = { _norm(c): c for c in df_g.columns }

    k_name = a_map.get("name")
    if not k_name:
        raise ValueError("Applications.csv must contain a 'Name' column.")

    STORE.apps.clear()
    STORE.groups.clear()
    STORE.df_groups = None
    STORE._app_index.clear()
    STORE._group_index.clear()

    # apps
    for _, r in df_a.iterrows():
        nm = str(r[k_name]).strip()
        if not nm:
            continue
        attrs = { c: r[c] for c in df_a.columns }
        STORE.apps[nm] = ApplicationObj(name=nm, attrs=attrs)
        if CASE_INSENSITIVE_LOOKUPS:
            STORE._app_index[_casekey(nm)] = nm

    # groups: merge Applications + Groups; 'Filters' optional
    g_name = g_map.get("name")
    g_apps = g_map.get("applications") or g_map.get("apps") or g_map.get("applicationlist") or g_map.get("applist")
    g_grps = g_map.get("groups")
    g_dyn  = g_map.get("dynamicfilter") or g_map.get("filters")
    g_loc  = g_map.get("location")

    if not g_name:
        raise ValueError("Application Groups.csv must contain 'Name'.")
    if not (g_apps or g_grps or g_dyn):
        raise ValueError("Application Groups.csv must have at least one of: Applications/Groups/Filters.")

    for _, r in df_g.iterrows():
        nm = str(r[g_name]).strip()
        if not nm:
            continue
        members: List[str] = []
        if g_apps:
            members.extend(_split_list(r[g_apps]))
        if g_grps:
            members.extend(_split_list(r[g_grps]))
        dyn = str(r[g_dyn]).strip() if g_dyn else ""
        loc = str(r[g_loc]).strip() if g_loc else ""
        STORE.groups[nm] = ApplicationGroup(name=nm, members=members, dynamic_filter=(dyn or None), location=loc)
        if CASE_INSENSITIVE_LOOKUPS:
            STORE._group_index[_casekey(nm)] = nm

    STORE.df_groups = df_g.copy()
    return {"applications_loaded": len(STORE.apps), "groups_loaded": len(STORE.groups)}

# -------------- Expansion --------------
def _expand_group_to_apps(group_name: str) -> Tuple[List[str], List[str]]:
    unresolved: List[str] = []
    leaves: List[str] = []
    visited_groups: Set[str] = set()

    resolved_group = _resolve_name(group_name, "group") if CASE_INSENSITIVE_LOOKUPS else (group_name if group_name in STORE.groups else None)
    if not resolved_group:
        unresolved.append(group_name)
        return [], unresolved

    def dfs(name: str):
        r_app = _resolve_name(name, "app") if CASE_INSENSITIVE_LOOKUPS else (name if name in STORE.apps else None)
        if r_app:
            leaves.append(r_app)
            return
        r_grp = _resolve_name(name, "group") if CASE_INSENSITIVE_LOOKUPS else (name if name in STORE.groups else None)
        if r_grp:
            if r_grp in visited_groups:
                return
            visited_groups.add(r_grp)
            for m in STORE.groups[r_grp].members:
                dfs(m)
            return
        unresolved.append(name)

    dfs(resolved_group)

    # dedupe leaves (case-insensitive) and sort
    seen = set(); uniq = []
    for v in leaves:
        ck = _casekey(v)
        if ck in seen:
            continue
        seen.add(ck)
        uniq.append(v.strip())
    uniq.sort(key=lambda x: x.casefold())
    return uniq, unresolved

def _select_attr_column(df_apps: pd.DataFrame, target_field: str) -> Tuple[str, List[str]]:
    errs: List[str] = []
    if target_field in df_apps.columns:
        return target_field, errs
    norm_target = _norm(target_field)
    norm_map = { _norm(c): c for c in df_apps.columns }
    if norm_target in norm_map:
        return norm_map[norm_target], errs
    fallback_keys = ["address", "standardports", "standardport", "port", "ports"]
    for fk in fallback_keys:
        if fk in norm_map:
            errs.append(f"Target column '{target_field}' not found; falling back to '{norm_map[fk]}'")
            return norm_map[fk], errs
    errs.append(f"Target column '{target_field}' not found and no fallback column exists in Applications.csv")
    return df_apps.columns[0], errs

# -------------- Tools --------------
@mcp.tool()
def load_application_data_from_folder(folder: str, apps_filename: Optional[str] = None, groups_filename: Optional[str] = None) -> dict:
    """
    Auto-detect and load Applications + Application Groups from a folder.
    Use only for when you are using Panorama export  of application Object
    - Accepts CSV or XLSX.
    - Case-insensitive filename matching. You can override exact filenames via apps_filename/groups_filename.
    """
    folder = os.path.abspath(folder)
    if not os.path.isdir(folder):
        raise ValueError(f"Not a directory: {folder}")

    # resolve file paths
    apps_path = os.path.join(folder, apps_filename) if apps_filename else _find_file(folder, APPS_FILE_CANDIDATES)
    groups_path = os.path.join(folder, groups_filename) if groups_filename else _find_file(folder, GROUPS_FILE_CANDIDATES)

    if not apps_path:
        raise FileNotFoundError(f"Could not find Applications file in: {folder}")
    if not groups_path:
        raise FileNotFoundError(f"Could not find Application Groups file in: {folder}")

    df_a = _read_table(apps_path)
    df_g = _read_table(groups_path)

    meta = _load_from_dataframes(df_a, df_g)
    STORE.apps_path = apps_path
    STORE.groups_path = groups_path
    meta.update({"apps_path": apps_path, "groups_path": groups_path})
    return meta



@mcp.tool()
def load_application_data_from_parent_folder(
    parent_folder: str,
    apps_subdir: str = "Applications",
    groups_subdir: str = "Application Groups",
    recursive: bool = True
) -> dict:
    """
    Pass the Parent folder which contains "Applicaitons" and "Application Groups" Folder.
    Case-insensitive filename matching. You can override exact filenames via apps_filename/groups_filename
    """
    base = os.path.abspath(parent_folder)
    apps_dir = os.path.join(base, apps_subdir)
    groups_dir = os.path.join(base, groups_subdir)

    # Accept underscore variants if the exact space-named folders don't exist.
    if not os.path.isdir(apps_dir):
        alt = os.path.join(base, apps_subdir.replace(" ", "_"))
        if os.path.isdir(alt):
            apps_dir = alt
    if not os.path.isdir(groups_dir):
        altg = os.path.join(base, groups_subdir.replace(" ", "_"))
        if os.path.isdir(altg):
            groups_dir = altg
    df_a = _read_and_concat_apps(apps_dir, "Applications", recursive=recursive)
    df_g = _read_and_concat_apps(groups_dir, "Application Groups", recursive=recursive)
    df_a = _dedupe_by_name_ci(df_a, name_col="Name") if "Name" in df_a.columns else df_a
    df_g = _dedupe_by_name_ci(df_g, name_col="Name") if "Name" in df_g.columns else df_g
    meta = _load_from_dataframes(df_a, df_g)
    STORE.apps_path = apps_dir
    STORE.groups_path = groups_dir
    meta.update({"apps_path": apps_dir, "groups_path": groups_dir})
    return meta



@mcp.tool()
def expand_application_groups_map_attribute(
    target_field: Optional[str] = "Standard Ports",
    output_column: Optional[str] = "Applications",
    replace_member_column: Optional[bool] = None,
    include_unresolved_tokens_in_output: Optional[bool] = True,
    purge_old: bool = True
) -> dict:
    """
    Expand app groups to leaf app names, map each to a chosen Applications.csv attribute.
    Fallbacks:
      - If an app lacks that attribute value, fallback to the app's canonical name.
      - Optionally include unresolved tokens in output (default True).
    """
    if STORE.df_groups is None:
        raise RuntimeError("No Application Groups have been loaded. Run load_application_data_from_folder first.")

    target_field = target_field or DEFAULT_TARGET_APP_FIELD
    output_column = output_column or DEFAULT_OUTPUT_COLUMN
    replace_flag = DEFAULT_REPLACE_MEMBER_COLUMN if replace_member_column is None else bool(replace_member_column)
    include_unresolved = INCLUDE_UNRESOLVED_TOKENS_IN_OUTPUT if include_unresolved_tokens_in_output is None else bool(include_unresolved_tokens_in_output)

    if not STORE.apps:
        raise RuntimeError("No applications loaded.")
    df_apps = pd.DataFrame([a.attrs for a in STORE.apps.values()])
    actual_attr_col, attr_errors = _select_attr_column(df_apps, target_field)

    # Build app->attr lookup
    app_to_attr: Dict[str, str] = { app.name: str(app.attrs.get(actual_attr_col, "")).strip() for app in STORE.apps.values() }

    df_out = STORE.df_groups.copy()
    col_map = { _norm(c): c for c in df_out.columns }
    name_col = col_map.get("name")
    if name_col is None:
        raise RuntimeError("Application Groups.csv must contain 'Name'.")

    out_col = output_column
    if replace_flag:
        if out_col not in df_out.columns:
            df_out[out_col] = ""
    else:
        if out_col in df_out.columns:
            base = out_col; i = 1
            while f"{base} ({target_field})" in df_out.columns:
                i += 1
            out_col = f"{base} ({target_field})"
        df_out[out_col] = ""

    consolidated_vals: List[str] = []
    diag_rows: List[dict] = []

    def add_val(v: str, vals: List[str], seen_keys: Set[str]):
        s = str(v).strip()
        if not s:
            return
        k = s.casefold() if CASE_INSENSITIVE_LOOKUPS else s
        if k in seen_keys:
            return
        seen_keys.add(k)
        vals.append(s)

    for _, row in df_out.iterrows():
        gname_raw = str(row[name_col])
        gname = gname_raw.strip()
        if not gname:
            consolidated_vals.append("")
            continue

        leaves, unresolved = _expand_group_to_apps(gname)

        vals: List[str] = []
        seen_keys: Set[str] = set()

        # Map each leaf to attribute; fallback to app name if attr missing
        for app_name in leaves:
            canon = _resolve_name(app_name, "app") if CASE_INSENSITIVE_LOOKUPS else app_name
            attr = app_to_attr.get(canon or app_name, "").strip()
            add_val(attr if attr else (canon or app_name), vals, seen_keys)

        if include_unresolved and unresolved:
            for tok in unresolved:
                add_val(tok, vals, seen_keys)

        consolidated_vals.append(CONSOLIDATE_DELIM.join(vals) if vals else "")
        if unresolved:
            diag_rows.append({"Group": gname_raw, "Unresolved": ", ".join(unresolved)})

    df_out[out_col] = consolidated_vals

    # Ensure 'Location' is present and ordered before writing
    if "Location" not in df_out.columns:
        df_out["Location"] = ""
    preferred_cols = ["Name", "Location", out_col, "Tags"]
    exist = [c for c in preferred_cols if c in df_out.columns]
    remain = [c for c in df_out.columns if c not in exist]
    df_out = df_out.reindex(columns=exist + remain)

    # Build Excel
    bio = io.BytesIO()
    with pd.ExcelWriter(bio, engine="openpyxl") as xw:
        df_out.to_excel(xw, sheet_name="Application Groups (Mapped)", index=False)
        # --- Append ALL Applications below the analysis, placing Name/Standard Ports/Location into existing columns ---
        try:
            apps_df = df_apps.copy()
            apps_df.columns = [str(c).strip() for c in apps_df.columns]
            lower_map = {c.lower().replace(" ", "").replace("/", ""): c for c in apps_df.columns}

            name_col_apps = next((c for c in apps_df.columns if c.strip().lower() == "name"), None)
            std_ports_col = (
                lower_map.get("standardports")
                or lower_map.get("standardport")
                or lower_map.get("ports")
                or lower_map.get("port")
            )
            loc_col_apps = next((c for c in apps_df.columns if c.strip().lower() == "location"), None)

            # destination columns in df_out
            name_col_out = name_col
            apps_col_out = out_col
            loc_col_out  = next((c for c in df_out.columns if c.strip().lower() == "location"), None)

            if name_col_apps and std_ports_col and name_col_out and apps_col_out:
                footer = pd.DataFrame({
                    name_col_out: apps_df[name_col_apps].astype(str).fillna("").str.strip(),
                    apps_col_out: apps_df[std_ports_col].astype(str).fillna("").str.strip()
                })
                if loc_col_out and loc_col_apps:
                    footer[loc_col_out] = apps_df[loc_col_apps].astype(str).fillna("").str.strip()

                # align to df_out columns
                for col in df_out.columns:
                    if col not in footer.columns:
                        footer[col] = ""
                footer = footer[df_out.columns]

                # append without headers below the analysis
                sheet_name = "Application Groups (Mapped)"
                startrow = df_out.shape[0] + 3
                footer.to_excel(
                    xw,
                    sheet_name=sheet_name,
                    startrow=startrow,
                    header=False,
                    index=False
                )
        except Exception:
            pass
        info_rows = [ {"apps_path": STORE.apps_path or "", "groups_path": STORE.groups_path or ""} ]
        pd.DataFrame(info_rows).to_excel(xw, sheet_name="Inputs", index=False)
        if diag_rows or attr_errors:
            diag_df = pd.DataFrame(diag_rows) if diag_rows else pd.DataFrame(columns=["Group","Unresolved"])
            diag_df.to_excel(xw, sheet_name="Diagnostics", index=False)
            if attr_errors:
                pd.DataFrame({"attribute_resolution": attr_errors}).to_excel(xw, sheet_name="Notes", index=False)

    out_dir = "./expansions"
    os.makedirs(out_dir, exist_ok=True)

# Purge old files if requested
    if purge_old:
        for old in os.listdir(out_dir):
            if re.match(r"^application_groups_mapped.*\.xlsx$", old, flags=re.IGNORECASE):
                try:
                    os.remove(os.path.join(out_dir, old))
                except OSError:
                    pass

# Always write the same filename
    fpath = os.path.abspath(os.path.join(out_dir, "application_groups_mapped.xlsx"))

# Atomic-ish replace
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
        "apps_path": STORE.apps_path,
        "groups_path": STORE.groups_path,
    }

@mcp.resource("expansion://{job_id}.xlsx", mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
def get_expansion_excel(job_id: str) -> bytes:
    return STORE.get_xlsx(job_id)

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

    parser = argparse.ArgumentParser(description="Batch Application expansion")
    parser.add_argument("--parent-folder", required=True, help="Folder that contains subfolders for Applications and Application Groups")
    parser.add_argument("--apps_subdir", default="Applications")
    parser.add_argument("--groups_subdir", default="Application Groups")
    parser.add_argument("--recursive", action="store_true")
    parser.add_argument("--target-field", default="Standard Ports")  # NEW: allow override
    parser.add_argument("--out", default="./expansions/application_groups_mapped.xlsx")
    args = parser.parse_args()

    try:
        # 1) load multi-file
        _ = load_application_data_from_parent_folder(
            parent_folder=args.parent_folder,
            apps_subdir=args.apps_subdir,
            groups_subdir=args.groups_subdir,
            recursive=args.recursive
        )

        # 2) expand + write (no save_filename/purge_old here)
        exp = expand_application_groups_map_attribute(target_field=args.target_field)

        out_abs = os.path.abspath(args.out)
        os.makedirs(os.path.dirname(out_abs), exist_ok=True)
        saved = exp.get("saved_file")
        if saved and os.path.abspath(saved) != out_abs:
            shutil.copyfile(saved, out_abs)
        elif not saved:
            raise RuntimeError("expand_application_groups_map_attribute did not return 'saved_file'")

        print(out_abs, flush=True)
        sys.exit(0)

    except Exception:
        traceback.print_exc()
        sys.exit(1)


# --- STDIO entrypoint ---
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