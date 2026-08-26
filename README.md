# TRACE

A three-stage pipeline that collects CVE PoC code, compiles PoCs into syscall template graphs, and aligns those templates against provenance graphs.

## Components

| Stage | Purpose |
|---|---|
| `1-trace-scraping/` | collects PoCs and metadata, builds the corpus, generates the study figures. The full scrape is storage-heavy (~200G); pre-generated figures are in `1-trace-scraping/figures/` |
| `2-trace-template-graph/` | compiles any Python PoC into syscall template graphs via AST parsing and syscall mappings |
| `3-trace-align/` | aligns template graphs to provenance graphs and reports paired and all-pairs results |

`3-trace-align/` ships the paper's template and provenance graphs (12 PoC Dataset and ATLASv2 CVEs, plus the 33 Splunk `attack_data` CVEs), so the main findings can be reproduced end to end without scraping anything. For full-scale experiments, start from step 1 and scrape the ~200GB PoC corpus.

## Workflow

```
1-trace-scraping/   ->  build the PoC corpus
2-trace-template-graph/  ->  compile PoCs into template graphs
3-trace-align/      ->  align templates against provenance graphs
```

Python 3.10.12 across the pipeline. Each stage has its own README with requirements and exact commands.
