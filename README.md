# TRACE

Collects CVE PoC code, compiles PoCs into syscall template graphs, and aligns those templates against provenance graphs.

| Stage | Purpose |
|---|---|
| `1-trace-scraping/` | builds the PoC corpus and the study figures |
| `2-trace-template-graph/` | compiles a Python PoC into syscall template graphs |
| `3-trace-align/` | aligns template graphs against provenance graphs |

Python 3.10.12. Each stage has its own README.

## Results

`3-trace-align/` ships the provenance graphs for all 45 CVEs, so the pipeline runs end to end without scraping.

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

`45/45` is the wider CVE-associated grade of `eval.tex`: a CVE counts when some member of its compiled template family satisfies the alert predicate, scored per member and never pooled. The paper reports the same grade over the same 45 CVEs. Its primary endpoint is the stricter qualifying-edge-matched grade, 31 of 45, which this code does not compute.

`0 cross-product false alerts` is a cross-CVE check over all 1968 ordered pairs of the 45 shipped captures: no template alerts on the capture of a CVE from a different product. It is not the benign-corpus measurement `eval.tex` reports, which uses a stream not included here. The three cross-CVE firings that remain are between CVE pairs exploited through one endpoint, where both PoCs request it: CrushFTP CVE-2024-4040 and CVE-2025-31161 at `/WebInterface/function/`, Ivanti CVE-2023-35078 and CVE-2023-35082 at `/api/v2/authorized/users`.

Parameters follow `design.tex`: τ 0.43, class weights (0.20, 0.33, 0.47), k 3, h 3, and the alert predicate `MS ≥ τ` with the mass floor `Σ wᵢnᵢ ≥ w₃`.
