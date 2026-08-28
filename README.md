# TRACE

A three-stage pipeline that collects CVE PoC code, compiles PoCs into syscall template graphs, and aligns those templates against provenance graphs.

## Components

| Stage | Purpose |
|---|---|
| `1-trace-scraping/` | collects PoCs and metadata, builds the corpus, generates the study figures. The full scrape is storage-heavy (~200G); pre-generated figures are in `1-trace-scraping/figures/` |
| `2-trace-template-graph/` | compiles any Python PoC into syscall template graphs via AST parsing and syscall mappings |
| `3-trace-align/` | aligns template graphs to provenance graphs and reports paired and all-pairs results |

## Reproduce without scraping

`3-trace-align/` ships the public PoC and the template and provenance graphs for each of the paper's 45 CVEs (12 PoC Dataset and ATLASv2, plus 33 Splunk `attack_data`), so the results run on a laptop with no scraping and no network access.

```bash
cd 3-trace-align
python trace_batch_run.py --graphs_dir splunk_extend/graphs --trace_align ./trace_align.py
python trace_batch_run.py --graphs_dir poc_graphs/graphs   --trace_align ./trace_align.py
python trace_batch_run.py --graphs_dir splunk_extend/graphs --trace_align ./trace_align.py --all_pairs
```

This gives 45/45 paired alignment (33 Splunk + 12 PoC Dataset/ATLASv2), P@1 33/33, and 0 cross-CVE false alerts. Results are written to `output.txt` and `output-all_pairs.txt`.

Compile templates from the shipped PoCs with stage 2:

```bash
cd 2-trace-template-graph
python compile_pocs.py ../3-trace-align/poc_real/poc sig_out
```

For full-scale experiments, start from stage 1 and scrape the ~200GB PoC corpus.

## Workflow

```
1-trace-scraping/        ->  build the PoC corpus
2-trace-template-graph/  ->  compile PoCs into template graphs
3-trace-align/           ->  align templates against provenance graphs
```

Python 3.10.12 across the pipeline. Each stage has its own README with requirements and exact commands.
