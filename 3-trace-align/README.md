# TRACE Align

Aligns template graphs to provenance graphs with a partial-order screen followed by a constrained refinement step.

## Quick Start

Requirements: Python 3.10.12, `numpy`, `networkx`, `torch`

```
pip install numpy networkx torch
```

Extract `graphs.zip` in `poc_graphs/` or `splunk_extend/`, then run paired alignment:

```
python trace_batch_run.py --graphs_dir ./poc_graphs/graphs --trace_align ./trace_align.py
```

All-pairs:

```
python trace_batch_run.py --graphs_dir ./poc_graphs/graphs --trace_align ./trace_align.py --all_pairs
```

Results are written to `output.txt` and `output-all_pairs.txt`. Add `--show_mapping` to print vertex mappings, `--out_csv PATH` for a CSV summary.

## Graph Format

One entry per line:

```
NODE <id> <type> <label>
EDGE <src> <dst> <syscall>
```

Template labels may use wildcards (`*`) or alternatives (`A|B|C`); provenance labels are concrete runtime values.

## Method

1. **PO screen** embeds each process-centric subgraph and admits candidates whose order-violation energy `E = ||ReLU(z_sig - z_prov)||^2` is within `--po_eps`.
2. **Refinement** finds an injective mapping preserving types, labels, and syscall-constrained paths under `k`-tolerant traversal.
3. **Scoring** weights matched vertices by confidence class (`0.20`, `0.33`, `0.47`) and alerts when the normalized score reaches `--tau` (default `0.43`).

Key parameters: `--po_d` (128), `--k` (3), `--tau` (0.43), `--radius` (3).

## Code Layout

| File | Role |
|---|---|
| `trace_align.py` | CLI entrypoint |
| `trace_align_io.py` | graph parsing, label matching |
| `trace_align_gnn.py` | relation-aware GNN block |
| `trace_align_features.py` | feature construction |
| `trace_align_po.py` | PO encoder and energy |
| `trace_align_score.py` | confidence classes, match scoring |
| `trace_align_align.py` | refinement and alignment |
| `trace_batch_run.py` | batch driver |

## Public Datasets

The alignment code also runs on these public provenance corpora:

- DARPA Transparent Computing [E3](https://github.com/darpa-i2o/Transparent-Computing/blob/master/README-E3.md) and [E5](https://github.com/darpa-i2o/Transparent-Computing)
- [ATLASv2](https://bitbucket.org/sts-lab/atlasv2)
