#!/usr/bin/env python3
"""
Parent MCP server: Orchestrate Address MCP -> Rule-base combiner -> Address expansion into rule base.

Tools exposed:
  - run_pipeline_address_expand(
        address_cmd: str,
        address_result_path: str,
        rule_cmd: str,
        rule_result_path: str,
        final_output_path: str = "./expansions/Final_output.xlsx",
        source_col: str = "Source Address",
        dest_col: str = "Destination Address",
        sheet_name: str = "rules",
        separator: str = "; ",
        run_commands: bool = False,
        wait_seconds: int = 30
    ) -> dict

  - expand_addresses_only(
        rule_result_path: str,
        address_result_path: str,
        final_output_path: str = "./expansions/Final_output.xlsx",
        source_col: str = "Source Address",
        dest_col: str = "Destination Address",
        sheet_name: str = "rules",
        separator: str = "; "
    ) -> dict

Notes:
- By default, run_commands=False to avoid hanging when using 'npx @modelcontextprotocol/inspector'.
  If you set run_commands=True, the tool will spawn the exact commands you pass and then
  poll for the expected output files until they appear or wait_seconds elapse.
- The address_result_path workbook must contain columns 'Name' and 'Addresses' where 'Addresses'
  already holds the fully expanded leaves joined with '; ' (output of your Address MCP).
- The rule_result_path workbook must contain a sheet with unified headers (output of your combiner MCP).
"""

from __future__ import annotations
import os, sys, time, shlex, subprocess, re, unicodedata
from typing import List, Dict, Tuple
from pathlib import Path
import re

import pandas as pd
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("parent-mcp-address-expand")

# ---------- Utilities ----------
def _norm_key(s: str) -> str:
    s = "" if s is None else str(s)
    # normalize unicode and whitespace, then casefold
    s = s.replace("\ufeff","").replace("\xa0"," ")
    s = unicodedata.normalize("NFKC", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s.casefold()

def _split_tokens(cell: str, sep: str) -> List[str]:
    if cell is None:
        return []
    raw = str(cell).strip()
    if not raw:
        return []
    # use the provided separator (default ";"), and be whitespace-tolerant
    sep = re.escape((sep or ";").strip())
    parts = [p.strip() for p in re.split(rf"\s*{sep}\s*", raw) if p.strip()]
    return parts


def _dedup_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for it in items:
        key = it.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out
def _norm_colname(s: str) -> str:
    # normalize spaces/underscores and case for robust matching
    return re.sub(r"[\s_]+", " ", str(s)).strip().casefold()

def _resolve_header_case(df: pd.DataFrame, name: str) -> str:
    #header matching tolerant of spaces/underscores/case.
    norm = {c.casefold().strip(): c for c in df.columns}
    return norm.get(name.casefold().strip(), name)
from typing import List, Optional
import pandas as pd
from pathlib import Path
import re

def export_curated_to_new_excel(
    final_output_path: str = "./expansions/Final_output.xlsx",
    output_path: str = "./expansions/Final_output_curated.xlsx",
    input_sheet: str = "rules_expanded",
    output_sheet: str = "rules_curated",
    purge_old: bool = True,
) -> dict:
    """
    Read rules_expanded from final_output_path and write a NEW Excel workbook to output_path
    with only the requested columns in the requested order. The original workbook is not modified.
    """
    # Load the input sheet only
    try:
        df = pd.read_excel(final_output_path, sheet_name=input_sheet, dtype=str).fillna("")
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {final_output_path}")
    except ValueError as e:
        # typically happens if sheet doesn't exist
        raise ValueError(f"Could not read sheet '{input_sheet}' from {final_output_path}: {e}")

    # Build a resolver mapping normalized name -> actual column name from the input df
    norm_map = {_norm_colname(c): c for c in df.columns}

    def resolve_one(candidates: List[str]) -> Optional[str]:
        for cand in candidates:
            hit = norm_map.get(_norm_colname(cand))
            if hit:
                return hit
        return None

    # Preserve exact column names from source - no renaming
    # For expanded fields we prefer __expanded first, then fall back to non-expanded if needed.
    spec: List[tuple[str, List[str]]] = [
        ("Source_File", ["Source_File", "Source File"]),
        ("Name", ["Name", "Rule Name"]),
        ("Location", ["Location"]),
        ("Tags", ["Tags"]),
        ("Type", ["Type"]),
        ("Source Zone", ["Source Zone", "From Zone", "Source_Zone"]),
        ("Source Address", [
            "Source Address__expanded", "Source__expanded", "Source Address", "Source"
        ]),
        ("Source User", ["Source User", "Source_User"]),
        ("Destination Zone", ["Destination Zone", "To Zone", "Destination_Zone"]),
        ("Destination Address", [
            "Destination Address__expanded", "Destination__expanded", "Destination Address", "Destination"
        ]),
        ("Application", ["Application__expanded", "Application"]),
        ("Service", ["Service__expanded", "Service"]),
        ("Action", ["Action"]),
        ("Profile", ["Profile", "Security Profile", "Profiles"]),
        ("Options", ["Options"]),
        ("Rule Usage Rule Usage", ["Rule Usage Rule Usage", "Rule Usage Apps Seen"]),
        ("Rule Usage Description", ["Rule Usage Description"]),
        ("Rule Usage Apps Seen", ["Rule Usage Apps Seen", "Rule Usage Apps Seen"]),
        ("Days With No New Apps", ["Days With No New Apps", "Days with no new apps"]),
        ("Modified", ["Modified", "Last Modified"]),
        ("Created", ["Created", "Creation Time"]),
        ("Rule Usage First Hit", ["Rule Usage First Hit", "First Hit"]),
        ("Rule Usage Hit Count", ["Rule Usage Hit Count", "Hit Count"]),
        ("Rule Usage Last Hit", ["Rule Usage Last Hit", "Last Hit"]),
    ]

    # Build the curated DataFrame preserving original column names
    curated = pd.DataFrame()
    missing: List[str] = []
    for out_name, candidates in spec:
        actual = resolve_one(candidates)
        if actual is None:
            curated[out_name] = ""  # create an empty column if not found in input
            missing.append(out_name)
        else:
            # Use the actual source column name as the output column name
            curated[actual] = df[actual]

    # Check which expanded columns exist in the original dataframe (before any renaming)
    expanded_exists_in_source = {
        "Source Address": "Source Address__expanded" in df.columns or "Source__expanded" in df.columns,
        "Destination Address": "Destination Address__expanded" in df.columns or "Destination__expanded" in df.columns,
        "Application": "Application__expanded" in df.columns,
        "Service": "Service__expanded" in df.columns
    }
    
    # Explicitly add original columns to curated if they exist in source, even if expanded was already added
    # This ensures we keep both expanded and original columns
    columns_to_add_if_exist = {
        "Source Address": "Source Address",
        "Source": "Source",
        "Destination Address": "Destination Address",
        "Destination": "Destination",
        "Application": "Application",
        "Service": "Service"
    }
    
    for col_name, actual_col in columns_to_add_if_exist.items():
        if actual_col in df.columns and actual_col not in curated.columns:
            # Original column exists in source but wasn't added to curated (because expanded was used)
            # Add it now so we can rename it to _original
            curated[actual_col] = df[actual_col]
    
    # Handle original columns - rename them to _original
    # This will rename originals to _original, keeping expanded columns with clean names
    original_renames_before = {}
    
    # Handle Source Address / Source - rename original to _original if it exists
    if "Source Address" in curated.columns:
        original_renames_before["Source Address"] = "Source Address_original"
    elif "Source" in curated.columns:
        original_renames_before["Source"] = "Source_original"
    
    # Handle Destination Address / Destination
    if "Destination Address" in curated.columns:
        original_renames_before["Destination Address"] = "Destination Address_original"
    elif "Destination" in curated.columns:
        original_renames_before["Destination"] = "Destination_original"
    
    # Handle Application
    if "Application" in curated.columns:
        original_renames_before["Application"] = "Application_original"
    
    # Handle Service
    if "Service" in curated.columns:
        original_renames_before["Service"] = "Service_original"
    
    # Apply original column renames FIRST
    if original_renames_before:
        curated = curated.rename(columns=original_renames_before)
        print(f"📝 Renamed original columns to _original: {original_renames_before}")
    
    # Now rename expanded columns to remove __expanded suffix
    column_renames = {
        "Source Address__expanded": "Source Address",
        "Source__expanded": "Source Address",  # Also handle Source__expanded
        "Destination Address__expanded": "Destination Address", 
        "Destination__expanded": "Destination Address",  # Also handle Destination__expanded
        "Application__expanded": "Application",
        "Service__expanded": "Service"
    }
    
    # Track which expanded renames were actually applied
    expanded_renames_applied = {}
    
    # Apply the renames if the columns exist
    for old_name, new_name in column_renames.items():
        if old_name in curated.columns:
            curated = curated.rename(columns={old_name: new_name})
            expanded_renames_applied[old_name] = new_name
    
    if expanded_renames_applied:
        print(f"✅ Renamed expanded columns: {expanded_renames_applied}")

    # Reorder columns to match spec order, with _original columns appearing BEFORE their expanded counterparts
    # Define the expected column order based on spec
    expected_order = [
        "Source_File",
        "Name",
        "Location",
        "Tags",
        "Type",
        "Source Zone",
        "Source Address_original",  # Insert _original before expanded
        "Source Address",
        "Source User",
        "Destination Zone",
        "Destination Address_original",  # Insert _original before expanded
        "Destination Address",
        "Application_original",  # Insert _original before expanded
        "Application",
        "Service_original",  # Insert _original before expanded
        "Service",
        "Action",
        "Profile",
        "Options",
        "Rule Usage Rule Usage",
        "Rule Usage Description",
        "Rule Usage Apps Seen",
        "Days With No New Apps",
        "Modified",
        "Created",
        "Rule Usage First Hit",
        "Rule Usage Hit Count",
        "Rule Usage Last Hit"
    ]
    
    # Also handle alternative column names
    alternative_original_names = {
        "Source_original": "Source Address_original",
        "Destination_original": "Destination Address_original"
    }
    
    # Get current columns
    current_columns = list(curated.columns)
    reordered_columns = []
    processed_columns = set()
    
    # Build reordered list following spec order
    for expected_col in expected_order:
        # First check for exact match
        if expected_col in current_columns and expected_col not in processed_columns:
            reordered_columns.append(expected_col)
            processed_columns.add(expected_col)
            continue
        
        # Check for alternative original column names
        if expected_col.endswith("_original"):
            base_name = expected_col.replace("_original", "")
            # Check for alternative names like "Source_original" for "Source Address_original"
            for alt_name, target_name in alternative_original_names.items():
                if expected_col == target_name and alt_name in current_columns and alt_name not in processed_columns:
                    reordered_columns.append(alt_name)
                    processed_columns.add(alt_name)
                    break
            continue
        
        # For non-_original columns, try normalized matching
        norm_expected = _norm_colname(expected_col)
        found = False
        for col in current_columns:
            if col not in processed_columns:
                norm_col = _norm_colname(col)
                if norm_expected == norm_col:
                    reordered_columns.append(col)
                    processed_columns.add(col)
                    found = True
                    break
    
    # Add any remaining columns that weren't in the spec (append at end)
    for col in current_columns:
        if col not in processed_columns:
            reordered_columns.append(col)
    
    # Reorder the dataframe
    curated = curated[reordered_columns]
    print(f"📋 Reordered columns to match spec order with _original before expanded")

    # Write the curated DF to a BRAND NEW workbook
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Purge old file if requested
    if purge_old and out_path.exists():
        try:
            out_path.unlink()
        except OSError:
            pass
    
    with pd.ExcelWriter(out_path, engine="xlsxwriter") as xw:
        curated.to_excel(xw, sheet_name=output_sheet, index=False)
    
    # Log final column names
    print(f"📊 Final curated columns: {list(curated.columns)}")

    return {
        "output_path": str(out_path.resolve()),
        "output_sheet": output_sheet,
        "rows": int(curated.shape[0]),
        "missing_output_columns": missing,  # helpful to see what wasn't found
        "original_columns_renamed": list(original_renames_before.values()) if original_renames_before else [],
        "expanded_columns_renamed": list(expanded_renames_applied.values()) if expanded_renames_applied else [],
    }

def _run_cmd(cmd: str) -> subprocess.Popen:
    # Use shell=False for safety; split with shlex
    args = shlex.split(cmd)
    # Inherit env; user may include DANGEROUSLY_OMIT_AUTH in cmd prefix already
    return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def _wait_for_file(path: str, timeout: int) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if os.path.isfile(path):
            # ensure file settled (size stop changing)
            size1 = os.path.getsize(path)
            time.sleep(0.5)
            size2 = os.path.getsize(path)
            if size1 == size2 and size1 > 0:
                return True
        time.sleep(0.5)
    return False

def _load_address_map(address_xlsx: str) -> Dict[str, List[str]]:
    # Read any sheet; locate 'Name' and 'Addresses' columns
    df = pd.read_excel(address_xlsx, sheet_name=0, dtype=str).fillna("")
    # try exact, then case-insensitive find
    cols = {c.casefold(): c for c in df.columns}
    name_col = cols.get("name")
    addr_col = cols.get("addresses") or cols.get("members") or cols.get("staticmembers")
    if not name_col or not addr_col:
        raise ValueError("Address result workbook must have 'Name' and 'Addresses' columns.")
    m: Dict[str, List[str]] = {}
    for _, r in df.iterrows():
        name = _norm_key(r[name_col])
        addrs = _split_tokens(r[addr_col], ";")
        # keep original formatting (no further normalization)
        if name:
            m[name] = addrs
    return m

def _expand_rule_columns(rule_xlsx: str, final_xlsx: str,
                         addr_map: Dict[str, List[str]],
                         source_col: str, dest_col: str,
                         sheet_name: str, separator: str,
                         address_result_path: str) -> Dict[str, int]:
    df = pd.read_excel(rule_xlsx, sheet_name=sheet_name, dtype=str).fillna("")

    # Resolve headers case/space-insensitively
    norm = {c.casefold().strip(): c for c in df.columns}
    source_col = norm.get(source_col.casefold().strip(), source_col)
    dest_col   = norm.get(dest_col.casefold().strip(), dest_col)

    # Prepare output columns
    src_out = f"{source_col}__expanded"
    dst_out = f"{dest_col}__expanded"
    src_cnt = f"{source_col}__count"
    dst_cnt = f"{dest_col}__count"

    def expand_cell(val: str):
        tokens = _split_tokens(val, separator)
        acc: List[str] = []
        unresolved: List[str] = []
        for t in tokens:
            key = _norm_key(t)
            mapped = addr_map.get(key)
            if mapped:
                acc.extend(mapped)
            else:
                # copy-through for unresolved/empty
                acc.append(t)
                unresolved.append(t)
        acc = _dedup_preserve_order([a.strip() for a in acc if str(a).strip() != ""])
        return separator.join(acc), len(acc), unresolved

    src_vals: List[str] = []
    dst_vals: List[str] = []
    src_counts: List[int] = []
    dst_counts: List[int] = []
    src_unres: List[str] = []
    dst_unres: List[str] = []

    for idx, row in df.iterrows():
        v, c, u = expand_cell(row.get(source_col, ""))
        src_vals.append(v); src_counts.append(c); src_unres.extend(f"{idx}:{source_col}:{x}" for x in u)

        v, c, u = expand_cell(row.get(dest_col, ""))
        dst_vals.append(v); dst_counts.append(c); dst_unres.extend(f"{idx}:{dest_col}:{x}" for x in u)

    df[src_out] = src_vals
    df[dst_out] = dst_vals
    df[src_cnt] = src_counts
    df[dst_cnt] = dst_counts

    # Write final workbook
    out_path = Path(final_xlsx)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(out_path, engine="xlsxwriter") as xw:
        df.to_excel(xw, sheet_name="rules_expanded", index=False)
        # Inputs & metrics
        inputs = pd.DataFrame([{
            "rule_result_path": str(Path(rule_xlsx).resolve()),
            "address_result_path": str(Path(address_result_path).resolve()),
            "source_col": source_col,
            "dest_col": dest_col,
            "separator": separator
        }])
        inputs.to_excel(xw, sheet_name="Inputs", index=False)
        warns = pd.DataFrame({"unresolved_tokens": src_unres + dst_unres})
        warns.to_excel(xw, sheet_name="Warnings", index=False)

    return {
        "rows": int(df.shape[0]),
        "source_total": int(df[src_cnt].sum()),
        "destination_total": int(df[dst_cnt].sum())
    }


# ---------- Defaults for Address & Services & Applications pipeline (edit these as you wish) ----------
DEFAULT_SERVICES_CMD = "DANGEROUSLY_OMIT_AUTH=true npx -y @modelcontextprotocol/inspector /home/labuser/networkAgent/venv/bin/python3 -u ./Services_mcp.py --mcp"
DEFAULT_SERVICES_RESULT_PATH = "/home/labuser/networkAgent/pages/FW_Rule_Analysis_XML/MCP_PA/expansions/service_groups_merged.xlsx"
DEFAULT_APPLICATIONS_CMD = "DANGEROUSLY_OMIT_AUTH=true npx -y @modelcontextprotocol/inspector /home/labuser/networkAgent/venv/bin/python3 -u ./Application_mcp.py --mcp"
DEFAULT_APPLICATIONS_RESULT_PATH = "/home/labuser/networkAgent/pages/FW_Rule_Analysis_XML/MCP_PA/expansions/application_groups_mapped.xlsx"
DEFAULT_ADDRESS_CMD = "DANGEROUSLY_OMIT_AUTH=true npx -y @modelcontextprotocol/inspector /home/labuser/networkAgent/venv/bin/python3 -u ./Address_mcp.py --mcp"
DEFAULT_ADDRESS_RESULT_PATH = "/home/labuser/networkAgent/pages/FW_Rule_Analysis_XML/MCP_PA/expansions/address_groups_merged.xlsx"
DEFAULT_RULE_CMD = "DANGEROUSLY_OMIT_AUTH=true npx -y @modelcontextprotocol/inspector /home/labuser/networkAgent/venv/bin/python3 -u ./Rule_base_combined.py --mcp"
DEFAULT_RULE_RESULT_PATH = "/home/labuser/networkAgent/pages/FW_Rule_Analysis_XML/MCP_PA/expansions/rule_base_combined.xlsx"
DEFAULT_FINAL_OUTPUT_PATH ="/home/labuser/networkAgent/pages/FW_Rule_Analysis_XML/MCP_PA/expansions/Final_output.xlsx"

# ---------- Tools ----------

@mcp.tool()
def expand_addresses_only(
    rule_result_path: str,
    address_result_path: str,
    final_output_path: str = "./expansions/Final_output.xlsx",
    source_col: str = "Source Address",
    dest_col: str = "Destination Address",
    sheet_name: str = "rules",
    separator: str = "; "
) -> dict:
    """
    Expand Source/Destination Address columns using an already-produced Address workbook.
    - Does not run any external commands.
    - Writes the final result to final_output_path (default ./expansions/Final_output.xlsx).
    """
    addr_map = _load_address_map(address_result_path)
    metrics = _expand_rule_columns(rule_result_path, final_output_path, addr_map,
                                   source_col, dest_col, sheet_name, separator,
                                   address_result_path)
    return { "final_output_path": str(Path(final_output_path).resolve()), **metrics }


@mcp.tool()
def run_pipeline_address_expand(
    address_cmd: str = DEFAULT_ADDRESS_CMD,
    address_result_path: str = DEFAULT_ADDRESS_RESULT_PATH,
    rule_cmd: str = DEFAULT_RULE_CMD,
    rule_result_path: str = DEFAULT_RULE_RESULT_PATH,
    final_output_path: str = DEFAULT_FINAL_OUTPUT_PATH,
    source_col: str = "Source Address",
    dest_col: str = "Destination Address",
    sheet_name: str = "rules",
    separator: str = "; ",
    run_commands: bool = False,
    wait_seconds: int = 30
) -> dict:
    """
    End-to-end pipeline:
      1) (optional) run 'address_cmd' to start Address MCP client flow
      2) (optional) run 'rule_cmd' to start rule-base combiner flow
      3) Expand addresses in the rule base and write final_output_path
    Notes:
      - If run_commands=False, we skip spawning the commands and just use the provided paths.
      - If you set run_commands=True, we spawn both commands, then poll for the files to appear
        for up to 'wait_seconds'. This is best-effort because 'npx @modelcontextprotocol/inspector'
        is interactive and may not exit on its own.
    """
    procs = []
    try:
        if run_commands:
            # start address tool
            procs.append(_run_cmd(address_cmd))
            if not _wait_for_file(address_result_path, wait_seconds):
                raise TimeoutError(f"Address result did not appear in {wait_seconds}s: {address_result_path}")
            # start rule combiner
            procs.append(_run_cmd(rule_cmd))
            if not _wait_for_file(rule_result_path, wait_seconds):
                raise TimeoutError(f"Rule-base result did not appear in {wait_seconds}s: {rule_result_path}")

        # perform expansion
        addr_map = _load_address_map(address_result_path)
        metrics = _expand_rule_columns(rule_result_path, final_output_path, addr_map,
                                       source_col, dest_col, sheet_name, separator,
                                       address_result_path)

        return {
            "final_output_path": str(Path(final_output_path).resolve()),
            "address_result_path": str(Path(address_result_path).resolve()),
            "rule_result_path": str(Path(rule_result_path).resolve()),
            **metrics
        }
    finally:
        # best-effort terminate spawned processes (Inspector may keep running otherwise)
        for p in procs:
            if p and p.poll() is None:
                try:
                    p.terminate()
                except Exception:
                    pass

# ---------- New loaders for Services & Applications ----------
def _load_services_map(services_xlsx: str) -> Dict[str, List[str]]:
    """Expect columns: 'Name', 'Services' (already expanded, ';'-separated)."""
    df = pd.read_excel(services_xlsx, sheet_name=0, dtype=str).fillna("")
    cols = {c.casefold(): c for c in df.columns}
    name_col = cols.get("name")
    svc_col = cols.get("services") or cols.get("members") or cols.get("staticmembers")
    if not name_col or not svc_col:
        raise ValueError("Services workbook must have 'Name' and 'Services' (expanded) columns.")
    m: Dict[str, List[str]] = {}
    for _, r in df.iterrows():
        name = _norm_key(r[name_col])
        svcs = _split_tokens(r[svc_col], ";")
        if name:
            m[name] = svcs
    return m

def _load_applications_map(apps_xlsx: str) -> Dict[str, List[str]]:
    """Expect columns: 'Name', 'Applications' (already expanded, ';'-separated)."""
    df = pd.read_excel(apps_xlsx, sheet_name=0, dtype=str).fillna("")
    cols = {c.casefold(): c for c in df.columns}
    name_col = cols.get("name")
    app_col = cols.get("applications") or cols.get("members") or cols.get("staticmembers")
    if not name_col or not app_col:
        raise ValueError("Applications workbook must have 'Name' and 'Applications' (expanded) columns.")
    m: Dict[str, List[str]] = {}
    for _, r in df.iterrows():
        name = _norm_key(r[name_col])
        apps = _split_tokens(r[app_col], ";")
        if name:
            m[name] = apps
    return m

# ---------- Helpers to load base DF / write Excel safely ----------
def _load_base_df(rule_xlsx: str, final_xlsx: str, sheet_name: str) -> pd.DataFrame:
    """
    If final_xlsx exists with sheet 'rules_expanded', use it as the working base,
    otherwise load the original rules sheet from rule_xlsx.
    """
    try:
        if Path(final_xlsx).is_file():
            with pd.ExcelFile(final_xlsx) as xf:
                if "rules_expanded" in xf.sheet_names:
                    return pd.read_excel(xf, sheet_name="rules_expanded", dtype=str).fillna("")
    except Exception:
        pass
    return pd.read_excel(rule_xlsx, sheet_name=sheet_name, dtype=str).fillna("")

def _write_final_with_merge(df: pd.DataFrame, final_xlsx: str, extra_inputs: Dict[str, str], warnings: List[str]) -> None:
    out_path = Path(final_xlsx)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # If existing Inputs sheet exists, try to load and append; otherwise create fresh
    prior_inputs = None
    if out_path.is_file():
        try:
            with pd.ExcelFile(out_path) as xf:
                if "Inputs" in xf.sheet_names:
                    prior_inputs = pd.read_excel(xf, sheet_name="Inputs", dtype=str).fillna("")
        except Exception:
            prior_inputs = None
    with pd.ExcelWriter(out_path, engine="xlsxwriter") as xw:
        df.to_excel(xw, sheet_name="rules_expanded", index=False)
        if prior_inputs is not None:
            merged_inputs = pd.concat([prior_inputs, pd.DataFrame([extra_inputs])], ignore_index=True)
        else:
            merged_inputs = pd.DataFrame([extra_inputs])
        merged_inputs.to_excel(xw, sheet_name="Inputs", index=False)
        warn_df = pd.DataFrame({"unresolved_tokens": warnings})
        warn_df.to_excel(xw, sheet_name="Warnings", index=False)

# ---------- Generic column expander ----------
def _expand_column_using_map(df: pd.DataFrame, column: str, obj_map: Dict[str, List[str]], separator: str):
    out_col = f"{column}__expanded"
    cnt_col = f"{column}__count"
    unresolved_list: List[str] = []

    def expand_cell(idx, val: str):
        tokens = _split_tokens(val, separator)
        acc: List[str] = []
        unresolved: List[str] = []
        for t in tokens:
            key = _norm_key(t)
            mapped = obj_map.get(key)
            if mapped:  # non-empty list expands
                acc.extend(mapped)
            else:
                # missing OR empty → copy-through and mark unresolved
                acc.append(t)
                unresolved.append(t)
        acc = _dedup_preserve_order([a.strip() for a in acc if str(a).strip() != ""])
        if unresolved:
            for u in unresolved:
                unresolved_list.append(f"{idx}:{column}:{u}")
        return separator.join(acc), len(acc)

    expanded_vals, counts = [], []
    for idx, row in df.iterrows():
        v, c = expand_cell(idx, row.get(column, ""))
        expanded_vals.append(v); counts.append(c)
    df[out_col] = expanded_vals
    df[cnt_col] = counts
    return df, unresolved_list


# ---------- New Tools: Services & Applications ----------

@mcp.tool()
def expand_services_only(
    rule_result_path: str,
    services_result_path: str,
    final_output_path: str = "./expansions/Final_output.xlsx",
    service_col: str = "Service",
    sheet_name: str = "rules",
    separator: str = "; "
) -> dict:
    """
    Expand the Service column using an already-produced Services workbook.
    Writes/updates final_output_path (rules_expanded, Inputs, Warnings).
    """
    df_base = _load_base_df(rule_result_path, final_output_path, sheet_name)
    service_col = _resolve_header_case(df_base, service_col)
    svc_map = _load_services_map(services_result_path)
    df_out, warnings = _expand_column_using_map(df_base, service_col, svc_map, separator)
    _write_final_with_merge(
        df_out, final_output_path,
        {
            "rule_result_path": rule_result_path,
            "services_result_path": services_result_path,
            "service_col": service_col,
            "separator": separator
        },
        warnings
    )
    return {
        "final_output_path": str(Path(final_output_path).resolve()),
        "rows": int(df_out.shape[0]),
        "service_total": int(df_out[f"{service_col}__count"].sum())
    }


@mcp.tool()
def expand_applications_only(
    rule_result_path: str,
    applications_result_path: str,
    final_output_path: str = "./expansions/Final_output.xlsx",
    application_col: str = "Application",
    sheet_name: str = "rules",
    separator: str = "; "
) -> dict:
    """
    Expand the Application column using an already-produced Applications workbook.
    Writes/updates final_output_path (rules_expanded, Inputs, Warnings).
    """
    df_base = _load_base_df(rule_result_path, final_output_path, sheet_name)
    application_col = _resolve_header_case(df_base, application_col)

    app_map = _load_applications_map(applications_result_path)
    df_out, warnings = _expand_column_using_map(df_base, application_col, app_map, separator)
    _write_final_with_merge(
        df_out, final_output_path,
        {
            "rule_result_path": rule_result_path,
            "applications_result_path": applications_result_path,
            "application_col": application_col,
            "separator": separator
        },
        warnings
    )
    return {
        "final_output_path": str(Path(final_output_path).resolve()),
        "rows": int(df_out.shape[0]),
        "application_total": int(df_out[f"{application_col}__count"].sum())
    }


@mcp.tool()
def run_pipeline_services_applications(
    services_cmd: str = DEFAULT_SERVICES_CMD,
    services_result_path: str = DEFAULT_SERVICES_RESULT_PATH,
    applications_cmd: str = DEFAULT_APPLICATIONS_CMD,
    applications_result_path: str = DEFAULT_APPLICATIONS_RESULT_PATH,
    rule_result_path: str = DEFAULT_RULE_RESULT_PATH,
    final_output_path: str = DEFAULT_FINAL_OUTPUT_PATH,
    service_col: str = "Service",
    application_col: str = "Application",
    sheet_name: str = "rules",
    separator: str = "; ",
    run_commands: bool = False,
    wait_seconds: int = 30
) -> dict:
    """
    Optional pipeline runner for Services + Applications.
    1) (optional) run 'services_cmd' and wait for services_result_path
    2) (optional) run 'applications_cmd' and wait for applications_result_path
    3) Expand Service and Application into Final_output.xlsx (non-destructive)
    """
    procs = []
    try:
        if run_commands:
            if services_cmd:
                procs.append(_run_cmd(services_cmd))
                if not _wait_for_file(services_result_path, wait_seconds):
                    raise TimeoutError(f"Services result did not appear in {wait_seconds}s: {services_result_path}")
            if applications_cmd:
                procs.append(_run_cmd(applications_cmd))
                if not _wait_for_file(applications_result_path, wait_seconds):
                    raise TimeoutError(f"Applications result did not appear in {wait_seconds}s: {applications_result_path}")

        # Start from base (existing Final_output if present; else rule workbook)
        df_base = _load_base_df(rule_result_path, final_output_path, sheet_name)
        service_col = _resolve_header_case(df_base, service_col)
        application_col = _resolve_header_case(df_base, application_col)

        application_col = _resolve_header_case(df_base, application_col)


        # Expand Services
        svc_map = _load_services_map(services_result_path)
        df_svc, warn_svc = _expand_column_using_map(df_base, service_col, svc_map, separator)

        # Expand Applications
        app_map = _load_applications_map(applications_result_path)
        df_app, warn_app = _expand_column_using_map(df_svc, application_col, app_map, separator)

        _write_final_with_merge(
            df_app, final_output_path,
            {
                "rule_result_path": rule_result_path,
                "services_result_path": services_result_path,
                "applications_result_path": applications_result_path,
                "service_col": service_col,
                "application_col": application_col,
                "separator": separator
            },
            warn_svc + warn_app
        )

        return {
            "final_output_path": str(Path(final_output_path).resolve()),
            "rows": int(df_app.shape[0]),
            "service_total": int(df_app[f"{service_col}__count"].sum()),
            "application_total": int(df_app[f"{application_col}__count"].sum())
        }
    finally:
        for pr in procs:
            if pr and pr.poll() is None:
                try:
                    pr.terminate()
                except Exception:
                    pass


@mcp.tool()
def run_pipeline_all(
    run_commands: bool = False,
    wait_seconds: int = 60,
    # You can override any of these if needed; defaults are pre-filled
    address_cmd: str = DEFAULT_ADDRESS_CMD,
    address_result_path: str = DEFAULT_ADDRESS_RESULT_PATH,
    applications_cmd: str = DEFAULT_APPLICATIONS_CMD,
    applications_result_path: str = DEFAULT_APPLICATIONS_RESULT_PATH,
    services_cmd: str = DEFAULT_SERVICES_CMD,
    services_result_path: str = DEFAULT_SERVICES_RESULT_PATH,
    rule_cmd: str = DEFAULT_RULE_CMD,
    rule_result_path: str = DEFAULT_RULE_RESULT_PATH,
    final_output_path: str = DEFAULT_FINAL_OUTPUT_PATH,
    source_col: str = "Source Address",
    dest_col: str = "Destination Address",
    service_col: str = "Service",
    application_col: str = "Application",
    sheet_name: str = "rules",
    separator: str = ";"
) -> dict:
    """
    One-button pipeline (defaults pre-filled):
      1) Address MCP -> wait for address_result_path
      2) Rule combiner MCP -> wait for rule_result_path
      3) Expand Address (Source/Destination) into Final_output.xlsx
      4) Services MCP -> wait for services_result_path
      5) Applications MCP -> wait for applications_result_path
      6) Expand Service and Application into the same Final_output.xlsx
    """
    results = {}

    # Step 1-3: Address + Rule combiner + Address expansion
    res_addr = run_pipeline_address_expand(
        address_cmd=address_cmd,
        address_result_path=address_result_path,
        rule_cmd=rule_cmd,
        rule_result_path=rule_result_path,
        final_output_path=final_output_path,
        source_col=source_col,
        dest_col=dest_col,
        sheet_name=sheet_name,
        separator=separator,
        run_commands=run_commands,
        wait_seconds=wait_seconds
    )
    results["address_phase"] = res_addr

    # Step 4-6: Services + Applications (reuse same final_output_path)
    res_sa = run_pipeline_services_applications(
        services_cmd=services_cmd,
        services_result_path=services_result_path,
        applications_cmd=applications_cmd,
        applications_result_path=applications_result_path,
        rule_result_path=rule_result_path,
        final_output_path=final_output_path,
        service_col=service_col,
        application_col=application_col,
        sheet_name=sheet_name,
        separator=separator,
        run_commands=run_commands,
        wait_seconds=wait_seconds
    )
    results["services_applications_phase"] = res_sa

    results["final_output_path"] = res_sa.get("final_output_path", final_output_path)
    return results

@mcp.tool()
def run_export_curated_to_new_excel(
    final_output_path: str = "./expansions/Final_output.xlsx",
    output_path: str = "./expansions/Final_output_curated.xlsx",
    input_sheet: str = "rules_expanded",
    output_sheet: str = "rules_curated",
    purge_old: bool = True,
) -> dict:
    """
     Run this to view the final, more organized version of the sheet.    
    """
    return export_curated_to_new_excel(final_output_path, output_path, input_sheet, output_sheet, purge_old)


# --- STDIO entry ---
if __name__ == "__main__":
    mcp.run()
