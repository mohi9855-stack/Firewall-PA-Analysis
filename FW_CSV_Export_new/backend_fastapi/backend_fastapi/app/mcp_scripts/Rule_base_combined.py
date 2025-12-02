#!/usr/bin/env python3
"""
MCP server: Combine Panorama / Palo Alto rule-base CSVs into one Excel file.

Tools:
  - combine_rule_bases(input_paths: str | list[str],
                       output_path: str = "./expansions/rule_base_combined.xlsx",
                       recursive: bool = False) -> str
  - combine_rule_bases_text(input_text: str,
                            output_path: str = "./expansions/rule_base_combined.xlsx",
                            recursive: bool = False) -> str
  - debug_list_csvs(input_paths: str | list[str], recursive: bool = False) -> list[str]

CLI:
  python rules_mcp_combine_sane.py --input "./rules/*.csv" --output "./expansions/rule_base_combined.xlsx"
  python rules_mcp_combine_sane.py --input "./rules" --recursive
  python rules_mcp_combine_sane.py --mcp   # run as MCP stdio server
"""
from __future__ import annotations

import argparse
import csv
import glob
import os
import re
import sys
import unicodedata
from pathlib import Path
from typing import Iterable, List, Sequence, Union

import pandas as pd

def _is_csv(p: Path) -> bool:
    return p.suffix.lower() == ".csv"

def _is_excel(p: Path) -> bool:
    return p.suffix.lower() in (".xlsx", ".xls")

# Silence noisy SyntaxWarning from some pytz builds (harmless)
import warnings as _warnings
_warnings.filterwarnings("ignore", category=SyntaxWarning, module=r".*pytz.*")

# Official MCP Python SDK
try:
    from mcp.server.fastmcp import FastMCP  # pip install mcp
except Exception as e:
    raise SystemExit("Missing dependency 'mcp'. Install with: pip install mcp") from e


PREFERRED_ORDER: List[str] = [
    "Name", "Location", "Tags", "Type",
    "Source Zone", "Source Address", "Source User", "Source Device",
    "Destination Zone", "Destination Address", "Destination Device",
    "Application", "Service", "Action", "Profile", "Options", "Target",
    "Rule Usage Rule Usage", "Rule Usage Apps Seen", "Days With No New Apps",
    "Modified", "Created",
]


def sniff_delimiter(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            sample = fh.read(4096).decode("utf-8", errors="replace")
        try:
            return csv.Sniffer().sniff(sample, delimiters=[",", ";", "\t", "|"]).delimiter
        except Exception:
            return ","
    except Exception:
        # If we can't read the file, default to comma
        return ","


def clean_header(h: str) -> str:
    if h is None:
        return ""
    # strip BOM & zero-width/controls (keep tabs/newlines), fix NBSP, collapse spaces
    h = h.replace("\ufeff", "").replace("\xa0", " ")
    h = "".join(ch for ch in h if unicodedata.category(ch)[0] != "C" or ch in ("\t", "\n"))
    h = re.sub(r"\s+", " ", h).strip()
    return h


def read_frame(path: str) -> pd.DataFrame:
    p = Path(path)

    def _finalize(df: pd.DataFrame) -> pd.DataFrame:
        try:
            # Drop obvious index columns
            drop_candidates = [c for c in df.columns if str(c).lower().startswith("unnamed")]
            df = df.drop(columns=drop_candidates, errors="ignore")
            # Normalize headers
            df.columns = [clean_header(str(c)) for c in df.columns]
            # Trim string cells
            for c in df.columns:
                df[c] = df[c].astype(str).map(lambda x: x.strip() if x else "")
            # Add source file as first column
            if "Source_File" not in df.columns:
                df.insert(0, "Source_File", p.name)
            return df
        except Exception as e:
            # If finalization fails, return minimal dataframe with error info
            import warnings
            warnings.warn(f"Error finalizing dataframe for {path}: {e}")
            return pd.DataFrame({"Source_File": [p.name], "Error": [f"Finalization error: {str(e)}"]})

    if _is_csv(p):
        delim = sniff_delimiter(path)
        try:
            # Try with standard parameters first - robust CSV reading
            df = pd.read_csv(
                path, 
                sep=delim, 
                dtype=str, 
                keep_default_na=False, 
                engine="python",
                quoting=csv.QUOTE_MINIMAL,
                escapechar=None,
                on_bad_lines='skip',  # Skip malformed lines (pandas >= 1.3)
                encoding='utf-8',
                encoding_errors='replace'  # Use encoding_errors instead of errors
            )
            return _finalize(df)
        except (pd.errors.ParserError, csv.Error, UnicodeDecodeError) as e:
            # If parsing fails, try with more lenient settings
            try:
                df = pd.read_csv(
                    path,
                    sep=delim,
                    dtype=str,
                    keep_default_na=False,
                    engine="python",
                    quoting=csv.QUOTE_ALL,
                    on_bad_lines='skip',
                    encoding='utf-8',
                    encoding_errors='replace',  # Use encoding_errors instead of errors
                    skipinitialspace=True,
                    doublequote=True
                )
                return _finalize(df)
            except Exception as e2:
                # Last resort: try with C engine and skip bad lines
                try:
                    df = pd.read_csv(
                        path,
                        sep=delim,
                        dtype=str,
                        keep_default_na=False,
                        engine="c",
                        on_bad_lines='skip',
                        encoding='utf-8',
                        encoding_errors='replace',  # Use encoding_errors instead of errors
                        skipinitialspace=True
                    )
                    return _finalize(df)
                except Exception as e3:
                    # If all else fails, return empty dataframe with error message
                    import warnings
                    warnings.warn(f"Failed to parse CSV {path}: {e3}. Returning empty DataFrame.")
                    return pd.DataFrame({"Source_File": [p.name], "Error": [f"CSV parse error: {str(e3)}"]})

    if _is_excel(p):
        try:
            # Pick first sheet (adjust to a named sheet if you have a convention)
            xls = pd.ExcelFile(path)
            if not xls.sheet_names:
                import warnings
                warnings.warn(f"No sheets found in {path}")
                return pd.DataFrame({"Source_File": [p.name], "Error": ["No sheets found"]})
            sheet = xls.sheet_names[0]
            df = pd.read_excel(xls, sheet_name=sheet, dtype=str)
            df = df.fillna("")  # mirror keep_default_na=False
            return _finalize(df)
        except Exception as e:
            import warnings
            warnings.warn(f"Failed to parse Excel file {path}: {e}")
            return pd.DataFrame({"Source_File": [p.name], "Error": [f"Excel parse error: {str(e)}"]})

    # Unsupported type (collector should have filtered these out)
    return pd.DataFrame()



def collect_files(tokens: Iterable[str], recursive: bool = False) -> List[str]:
    """
    Collect input CSV/XLSX files from a list of tokens. Each token can be:
      - a file path
      - a directory path (we will add all *.csv/*.xlsx inside; recursive if requested)
      - a glob pattern

    Only files ending in .csv/.xlsx/.xls (case-insensitive) are included.
    """
    files: List[str] = []
    for item in tokens:
        pth = Path(item)
        if pth.is_dir():
            it = pth.rglob("*") if recursive else pth.glob("*")
            for f in it:
                if f.is_file() and (_is_csv(f) or _is_excel(f)):
                    files.append(str(f))
        else:
            # glob pattern or single file
            for m in glob.glob(item, recursive=True):
                f = Path(m)
                if f.is_file() and (_is_csv(f) or _is_excel(f)):
                    files.append(str(f))
            # direct single file fall-back
            if not files and pth.is_file() and (_is_csv(pth) or _is_excel(pth)):
                files.append(str(pth))

    # de-dup while preserving order
    seen = set()
    deduped = []
    for f in files:
        if f not in seen:
            seen.add(f)
            deduped.append(f)
    return deduped



def finalize_columns(frames: Sequence[pd.DataFrame]) -> List[str]:
    try:
        # Handle empty frames gracefully
        non_empty_frames = [f for f in frames if not f.empty]
        if not non_empty_frames:
            return ["Source_File"]
        
        all_cols = set().union(*[set(f.columns) for f in non_empty_frames])
        final_cols: List[str] = ["Source_File"]
        # Preferred order if present
        for c in PREFERRED_ORDER:
            if c in all_cols and c not in final_cols:
                final_cols.append(c)
        # Add remaining columns (sorted for determinism)
        for c in sorted(all_cols):
            if c not in final_cols:
                final_cols.append(c)
        return final_cols
    except Exception as e:
        # Fallback to basic columns if something goes wrong
        import warnings
        warnings.warn(f"Error in finalize_columns: {e}. Using default columns.")
        return ["Source_File", "Error"]


def combine_to_excel(paths: Sequence[str], output_path: str, purge_old: bool = True) -> str:
    out_path = Path(output_path)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise OSError(f"Failed to create output directory {out_path.parent}: {e}") from e

    # Purge old files if requested
    if purge_old and out_path.exists():
        try:
            out_path.unlink()
        except OSError:
            pass

    # Read all frames with error handling
    frames = []
    failed_files = []
    for p in paths:
        try:
            df = read_frame(p)
            # Only add non-empty dataframes (skip error-only dataframes if they're empty)
            if not df.empty or "Error" in df.columns:
                frames.append(df)
        except Exception as e:
            import warnings
            warnings.warn(f"Failed to read frame from {p}: {e}")
            failed_files.append(str(p))
            # Create error dataframe for failed file
            frames.append(pd.DataFrame({"Source_File": [Path(p).name], "Error": [f"Read error: {str(e)}"]}))

    if not frames:
        raise FileNotFoundError("No CSV frames to combine.")
    
    # Filter out completely empty dataframes (but keep error dataframes)
    frames = [f for f in frames if not f.empty or "Error" in f.columns]
    
    if not frames:
        raise FileNotFoundError("No valid data frames to combine after filtering.")
    
    try:
        final_cols = finalize_columns(frames)
    except Exception as e:
        raise ValueError(f"Failed to finalize columns: {e}") from e

    aligned = []
    for df in frames:
        try:
            # ensure all columns present
            for c in final_cols:
                if c not in df.columns:
                    df[c] = ""
            aligned.append(df[final_cols])
        except Exception as e:
            import warnings
            warnings.warn(f"Failed to align columns for dataframe: {e}")
            # Create minimal aligned dataframe
            minimal_df = pd.DataFrame({c: [""] * len(df) if c != "Source_File" else df.get("Source_File", [""] * len(df)) for c in final_cols})
            aligned.append(minimal_df)

    try:
        combined = pd.concat(aligned, ignore_index=True)
    except Exception as e:
        raise ValueError(f"Failed to concatenate dataframes: {e}") from e
    
    try:
        with pd.ExcelWriter(out_path, engine="xlsxwriter") as xlw:
            # main sheet (unchanged)
            combined.to_excel(xlw, index=False, sheet_name="rules")

            # NEW: summary of loaded files (file name + row count)
            if "Source_File" in combined.columns:
                df_loaded = (
                    combined["Source_File"]
                    .value_counts(dropna=False)
                    .rename_axis("Source_File")
                    .reset_index(name="Row_Count")
                    .sort_values("Source_File")
                )
            else:
                # fallback: list the discovered paths (shouldn't happen since read_frame adds Source_File)
                df_loaded = pd.DataFrame({"Source_File": paths})

            df_loaded.to_excel(xlw, index=False, sheet_name="Loaded Files")
            
            # Add error summary if there were failures
            if failed_files:
                df_errors = pd.DataFrame({
                    "Source_File": [Path(f).name for f in failed_files],
                    "Error": ["Failed to read file"] * len(failed_files)
                })
                df_errors.to_excel(xlw, index=False, sheet_name="Failed Files")
        
        return str(out_path.resolve())
    except Exception as e:
        raise IOError(f"Failed to write Excel file to {out_path}: {e}") from e



# --- MCP server definition ---
mcp = FastMCP("rules-mcp-server")


@mcp.tool()
def combine_rule_bases(
    input_paths: Union[str, List[str]],
    output_path: str = "./expansions/rule_base_combined.xlsx",
    recursive: bool = True,
    purge_old: bool = True,
) -> str:
    """
    Combine one or more Panorama/Palo Alto rule-base CSVs into a single Excel workbook
    with unified columns. Returns the absolute output path.
    Args:
      input_paths: a file path, directory, glob pattern, or a list with any mix of these.
      output_path: target .xlsx path (default: ./expansions/rule_base_combined.xlsx)
      recursive: set True to include subdirectories when a directory is provided
    """
    inputs = [input_paths] if isinstance(input_paths, str) else list(input_paths)
    files = collect_files(inputs, recursive=recursive)
    if not files:
        raise FileNotFoundError("No CSV files found from 'input_paths'.")
    return combine_to_excel(files, output_path, purge_old)


def _split_plain_text_paths(input_text: str) -> list[str]:
    """
    Split plain text into path tokens. Accepts newline or space-separated entries.
    Keeps quoted segments intact to allow spaces in filenames.
    """
    import shlex
    lines = [ln.strip() for ln in (input_text or "").splitlines() if ln.strip()]
    if len(lines) <= 1:
        # single line: use shell-like splitting to respect quotes
        return shlex.split(lines[0]) if lines else []
    # multi-line: each line is a path; strip surrounding quotes if present
    paths = []
    for ln in lines:
        ln = ln.strip()
        if (ln.startswith('"') and ln.endswith('"')) or (ln.startswith("'") and ln.endswith("'")):
            ln = ln[1:-1]
        paths.append(ln)
    return paths


@mcp.tool()
def combine_rule_bases_text(
    input_text: str,
    output_path: str = "./expansions/rule_base_combined.xlsx",
    recursive: bool = True,
) -> str:
    """
    Combine rule-base CSVs using *plain text* paths instead of JSON arrays.
    Paste paths either one per line (quotes optional), or space-separated
    (quote paths that contain spaces).
    """
    tokens = _split_plain_text_paths(input_text)
    files = collect_files(tokens, recursive=recursive)
    if not files:
        raise FileNotFoundError("No CSV files found from provided input_text.")
    return combine_to_excel(files, output_path)


@mcp.tool()
def debug_list_csvs(
    input_paths: Union[str, List[str]],
    recursive: bool = False,
) -> List[str]:
    """
    Diagnostic helper: return the list of CSV file paths that would be processed.
    Useful when calls to combine_rule_bases report 'No CSV files found'.
    """
    inputs = [input_paths] if isinstance(input_paths, str) else list(input_paths)
    files = collect_files(inputs, recursive=recursive)
    return files


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Combine Panorama/PA rule-base CSVs into one Excel.")
    ap.add_argument("--mcp", action="store_true", help="Run as MCP stdio server.")
    ap.add_argument("--input", nargs="+", required="--mcp" not in (argv or sys.argv),
                    help="Files, directories, or glob patterns (space-separated).")
    ap.add_argument("--output", default="./expansions/rule_base_combined.xlsx",
                    help="Output .xlsx path (default: ./expansions/rule_base_combined.xlsx)")
    ap.add_argument("--recursive", action="store_true",
                    help="Recurse into subdirectories when directories are given.")
    args = ap.parse_args(argv)

    if args.mcp:
        mcp.run()
        return 0

    files = collect_files(args.input or [], recursive=args.recursive)
    if not files:
        print("No CSV files found.", file=sys.stderr)
        return 2
    out = combine_to_excel(files, args.output)
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
