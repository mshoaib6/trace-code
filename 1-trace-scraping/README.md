# TRACE Scraping

Scrapes PoCs tied to CVEs, normalizes metadata across sources, and generates the study figures. Cloning the PoC repositories needs ~200G. Generated figures are in `figures/`.

## Requirements

Python 3.10.12, git, network access.

```bash
pip3 install -r requirements.txt
```

## Sources

NVD, Exploit-DB, Kernelhub, PoC-in-GitHub, Rhino Security Labs.

## Configuration

| File | Setting |
|---|---|
| `config.py` | `START_YEAR` for the PoC sources |
| `scrape_cves/nvd_scrape.py` | `START_YEAR`, `END_YEAR` for NVD |
| `poc_in_gh/process_poc.py` | SSH cloning for PoC-in-GitHub |

## Usage

```bash
python3 main.py
```

Outputs land in `total_folder/` (PoCs), `*.csv` and `*.pkl` (datasets), and `figures/`.

## Pipeline

1. `scrape_cves/nvd_scrape.py` -> `cves.csv`
2. `exploit_db/edb_main.py`, `kernelhub/kernelhub_scraper.py`, `poc_in_gh/process_poc.py`, `rhinoseclab/rhino_extract.py` -> per-source `{csv,pkl}` and `total_folder/`
3. `concat_dataframes.py`, `copy_tags.py` -> `total_results.{csv,pkl}`
4. `boxplots.py`, `heatmaps.py` -> `figures/*.pdf`
5. `compute_cve_information.py`, `compute_stats.py`, `compute_source_cve_overlap.py`, `cve_count_statistics.py`, `date_differences.py` -> stats and figures

## Code-level analysis

```bash
python3 get_python_files.py <index>        # repeat until index out of bounds
python3 python-filenames/combine_arrays.py
python3 count_function_calls.py <index>    # repeat
python3 function_counts/aggregate_counts.py
python3 count_syscalls.py <index>          # repeat
```
