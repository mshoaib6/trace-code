# TRACE

Collects CVE PoC code, compiles PoCs into syscall template graphs, and aligns those templates against provenance graphs.

| Stage | Purpose |
|---|---|
| `1-trace-scraping/` | builds the PoC corpus and the study figures |
| `2-trace-template-graph/` | compiles a Python PoC into syscall template graphs |
| `3-trace-align/` | aligns template graphs against provenance graphs |

Python 3.10.12. Each stage has its own README.

## Results

`3-trace-align/` contains the provenance graphs for the 45 evaluated CVEs, so the pipeline runs end to end on them. Unzip them first.

```bash
cd 3-trace-align/splunk_extend && unzip -q graphs.zip && cd ../..
cd 3-trace-align/poc_graphs   && unzip -q graphs.zip && cd ../..

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

The pretrained partial-order encoder is provided for testing.

## Correspondence with the paper

45/45 is the CVE-associated grade. A CVE counts when any member of its compiled template family meets the alert predicate. Scores are per member, never pooled.

0 cross-product false alerts covers all 1968 ordered pairs of the 45 captures. No template alerts on another product's capture.
