# TRACE Scraping Pipeline

Scrapes PoCs tied to CVEs, normalizes metadata across sources, and generates aggregate statistics and figures.
This pipeline is storage heavy (~200G) because it clones large PoC repositories. Generated figures are provided in `figures/`.

## Functionalities (CVE-PoC Ecosystem Study):
- Unified PoC metadata table across multiple sources.
- CVE publish dates and severity scores from NVD.
- Derived stats, plots, and overlap analyses.
- Code-level analysis (Python function counts, syscall estimates).

## Data Sources
- NVD (CVE metadata and scores)
- Exploit-DB
- Kernelhub
- PoC-in-GitHub
- Rhino Security Labs

## Requirements
- Python 3.10.12
- Git and network access for cloning repos
- ~200G disk for the cloned PoC repositories

## Configuration
- `config.py`: `START_YEAR` for PoC sources (Exploit-DB, Kernelhub, PoC-in-GitHub, RhinoSec).
- `scrape_cves/nvd_scrape.py`: `START_YEAR` and `END_YEAR` for NVD CVE scraping.
- PoC-in-GitHub uses `git@github.com` SSH cloning in `poc_in_gh/process_poc.py` (ensure SSH keys or switch to HTTPS).

## Quickstart
```bash
python3 -m venv env
source env/bin/activate
pip3 install -r requirements.txt
python3 main.py
```

Outputs land in:
- `total_folder/` (downloaded PoCs)
- `*.csv` and `*.pkl` (structured datasets)
- `figures/` (plots and charts)

## Pipeline (main.py)
1. `scrape_cves/nvd_scrape.py` -> `cves.csv`
2. `exploit_db/edb_main.py` -> `exploit_db/exploitdb-results.{csv,pkl}` + `total_folder/exploitdb/`
3. `kernelhub/kernelhub_scraper.py` -> `kernelhub/kernelhub_results.{csv,pkl}` + `total_folder/kernelhub/`
4. `poc_in_gh/process_poc.py` -> `poc_in_gh/poc-in-gh-results.{csv,pkl}` + `total_folder/poc-in-gh/`
5. `rhinoseclab/rhino_extract.py` -> `rhinoseclab/rhino_results.{csv,pkl}` + `total_folder/rhinoseclab/`
6. `concat_dataframes.py` -> `total_results.{csv,pkl}`
7. `copy_tags.py` -> updates `total_results.{csv,pkl}`
8. `boxplots.py`, `heatmaps.py` -> `figures/*.pdf`
9. `compute_cve_information.py`, `compute_stats.py`, `compute_source_cve_overlap.py`,
   `cve_count_statistics.py`, `date_differences.py` -> printed stats + figures

## Optional Workflows

### Python file discovery and function counting
```bash
# Build file lists in chunks
python3 get_python_files.py 0
python3 get_python_files.py 1
# ...repeat until "Index out of bounds of filename array"
python3 python-filenames/combine_arrays.py

# Count function calls in chunks
python3 count_function_calls.py 0
python3 count_function_calls.py 1
# ...repeat, then aggregate
python3 function_counts/aggregate_counts.py

# Summarize frequent functions
python3 function_counts/output_over_100.py
```

### Syscall counting (estimates)
```bash
python3 count_syscalls.py 0
# ...repeat for each index
```

### Execute PoCs (WIP)
```bash
python3 run_python_files.py
```

## PKL Catalog (Data and Columns)
Columns listed below reflect what the scripts write today. For mixed-source tables, expect NaNs where a source does not supply a field.

### Core datasets (DataFrame PKLs)
| PKL | Columns | Produced by |
| --- | --- | --- |
| `exploit_db/exploitdb-results.pkl` | `POC ID`, `CVE ID`, `CVE-Year`, `Foldername`, `Date`, `github-updated-at`, `github-pushed-at` | `exploit_db/edb_main.py` |
| `kernelhub/kernelhub_results.pkl` | `CVE ID`, `CVE-Year`, `Publish Date`, `Score`, `Foldername`, `Date`, `github-updated-at` | `kernelhub/kernelhub_scraper.py` |
| `rhinoseclab/rhino_results.pkl` | `CVE ID`, `CVE-Year`, `Publish Date`, `Score`, `Foldername`, `Date`, `github-updated-at` | `rhinoseclab/rhino_extract.py` |
| `poc_in_gh/poc-in-gh-results.pkl` | `POC ID`, `CVE ID`, `Foldername`, `CVE-Year`, `Date`, `github-updated-at`, `github-pushed-at` | `poc_in_gh/process_poc.py` |
| `total_results.pkl` | `index`, `POC ID`, `CVE ID`, `CVE-Year`, `Foldername`, `Date`, `github-updated-at`, `github-pushed-at`, `Publish Date`, `Score`, `Publish-Year`, `Tags` | `concat_dataframes.py` + `copy_tags.py` |
| `total_results_with_scores.pkl` | `Unnamed: 0`, `index`, `POC ID`, `CVE ID`, `CVE-Year`, `Foldername`, `Date`, `github-updated-at`, `github-pushed-at`, `Publish Date_x`, `Score_x`, `Publish-Year`, `Tags`, `Publish Date_y`, `Score_y` | `add_scores.py` |

In `total_results_with_scores.pkl`, `_x` columns come from `total_results.csv` and `_y` columns from `cves.csv`.

### Extension stats (dict PKLs)
| PKL | Structure | Produced by |
| --- | --- | --- |
| `total_extensions.pkl` | dict: `{extension: count}` | `compute_stats.py` |
| `source_extensions.pkl` | dict: `{source_folder: {extension: count}}` | `compute_stats.py` |

### Python file discovery (list PKLs)
| PKL | Structure | Produced by |
| --- | --- | --- |
| `directories.pkl` | list of `Foldername` strings from `total_results.pkl` | `get_python_files.py`, `get_num_files.py` |
| `python-filenames/pfa-<index>.pkl` | list of lists of `.py` file paths per folder slice | `get_python_files.py` |
| `python-filenames/lengths/pfa-<index>-length.pkl` | list of ints (# of `.py` files per folder slice) | `get_num_files.py` |
| `python-files.pkl` | list of `(python_file_path, foldername_relative)` tuples | `python-filenames/combine_arrays.py` |
| `python-filenames/pfa-<num>-array.pkl` | flattened list of `.py` file paths (debug/compare) | `python-filenames/check_arrays.py` |

### Function counting (dict + DataFrame PKLs)
| PKL | Structure | Produced by |
| --- | --- | --- |
| `function_counts/<index>-data.pkl` | dict with keys: `function_calls` (dict), `total`, `failed`, `python2`, `failed_dirs` (DataFrame: `Foldername`) | `count_function_calls.py` |
| `function_counts/function_counts_new.pkl` | dict: `{function_name: count}` | `function_counts/aggregate_counts.py` |
| `function_counts/failed_dirs_new.pkl` | DataFrame: `Foldername` | `function_counts/aggregate_counts.py` |
| `function_names.pkl` | list of function names above the threshold (default >=100) | `function_counts/output_over_100.py` |
| `failed.pkl` | DataFrame: `Foldername` (overwritten per run) | `count_function_calls.py` |

### Syscall counting (list PKLs)
| PKL | Structure | Produced by |
| --- | --- | --- |
| `count_syscalls/<index>-data-nop.pkl` | list of syscall counts per Python file | `count_syscalls.py` (and `hops.py`) |
| `failed.pkl` | DataFrame: `Foldername` (overwritten per run) | `count_syscalls.py` (and `hops.py`) |

### Execution helper (list PKL)
| PKL | Structure | Used by |
| --- | --- | --- |
| `foldernames.pkl` | list of `Foldername` strings to execute | `run_python_files.py` |
