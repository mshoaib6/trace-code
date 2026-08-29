# TRACE

Collects CVE PoC code, compiles PoCs into syscall template graphs, and aligns those templates against provenance graphs.

| Stage | Purpose |
|---|---|
| `1-trace-scraping/` | builds the PoC corpus and the study figures |
| `2-trace-template-graph/` | compiles a Python PoC into syscall template graphs |
| `3-trace-align/` | aligns template graphs against provenance graphs |

Python 3.10.12. Each stage has its own README.

## Results

`3-trace-align/` contains the provenance graphs for the 45 evaluated CVEs, so the pipeline runs end to end on them without scraping. Unzip them first.

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

The pretrained partial-order encoder is provided for testing. Training from scratch can be done with the full dataset.

## Correspondence with the paper

`45/45` matches the 45 of 45 the paper reports at the CVE-associated grade: a CVE counts when some member of its compiled template family satisfies the alert predicate, scored per member and never pooled. Same 45 CVEs, same grade, compiled from PoC source.

`0 cross-product false alerts` is a cross-CVE check over all 1968 ordered pairs of the 45 captures: no template alerts on the capture of a CVE from a different product.

The operation map `2-trace-template-graph/syscall_mapping.json` holds 365 keys, covering 312 normalized API identifiers once alias forms of one call are collapsed as the paper describes, and `3-trace-align/collector_profiles.json` gives the 6 collector join specifications, one per collector profile over the five formats, alongside the 7 URL/path normalization profiles in `3-trace-align/normalization_profiles.json`.

Parameters follow the paper: τ 0.43, class weights (0.20, 0.33, 0.47), k 3, h 3, and the alert predicate `MS ≥ τ` with the mass floor `Σ wᵢnᵢ ≥ w₃`.
