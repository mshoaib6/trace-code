# TRACE

Collects CVE PoC code, compiles PoCs into syscall template graphs, and aligns those templates against provenance graphs.

| Stage | Purpose |
|---|---|
| `1-trace-scraping/` | builds the PoC corpus and the study figures |
| `2-trace-template-graph/` | compiles a Python PoC into syscall template graphs |
| `3-trace-align/` | aligns template graphs against provenance graphs |

Python 3.10.12. Each stage has its own README.

## Results

`3-trace-align/` contains the provenance graphs for all 45 CVEs, so the pipeline runs end to end without scraping.

```bash
cd 2-trace-template-graph
python3 compile_pocs_family.py ../3-trace-align/poc_real/poc ../3-trace-align/sig_out

cd ../3-trace-align
python3 eval_family.py --family_dir sig_out \
    --prov_dir splunk_extend/graphs poc_graphs/graphs
python3 eval_family.py --family_dir sig_out \
    --prov_dir splunk_extend/graphs poc_graphs/graphs --all_pairs
```

```
45/45 CVEs aligned
0 cross-product false alerts
```

## Correspondence with the paper

`45/45` matches the 45 of 45 `eval.tex` reports at the CVE-associated grade: a CVE counts when some member of its compiled template family satisfies the alert predicate, scored per member and never pooled. Same 45 CVEs, same grade, compiled from PoC source.

`0 cross-product false alerts` is a cross-CVE check over all 1968 ordered pairs of the 45 captures: no template alerts on the capture of a CVE from a different product. The benign stream `eval.tex` also measures against exceeds this repository's size limit and is not included.

Parameters follow `design.tex`: τ 0.43, class weights (0.20, 0.33, 0.47), k 3, h 3, and the alert predicate `MS ≥ τ` with the mass floor `Σ wᵢnᵢ ≥ w₃`.
