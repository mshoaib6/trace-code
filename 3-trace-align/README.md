# TRACE Align

Aligns template graphs to provenance graphs with a partial-order screen followed by a constrained refinement step.

## Requirements

Python 3.10.12, `numpy`, `networkx`, `torch`

```bash
pip install numpy networkx torch
```

## Usage

The graphs are stored zipped. Extract them first:

```bash
cd splunk_extend && unzip -q graphs.zip && cd ..
cd poc_graphs   && unzip -q graphs.zip && cd ..
```

Then:

```bash
python3 trace_batch_run.py --graphs_dir ./poc_graphs/graphs --trace_align ./trace_align.py [--all_pairs]
```

For a compiled template family from stage 2:

```bash
python3 eval_family.py --family_dir <dir> --prov_dir splunk_extend/graphs poc_graphs/graphs [--all_pairs]
```

Add `--show_mapping` for vertex mappings, `--out_csv PATH` for a CSV summary.

## Graph Format

```
NODE <id> <type> <label>
EDGE <src> <dst> <syscall>
```

Template labels take wildcards (`*`) and alternatives (`A|B|C`); provenance labels are concrete runtime values.

## Method

1. **PO screen** embeds each process-centric subgraph and admits candidates whose order-violation energy `E = ||ReLU(z_sig - z_prov)||^2` is within `--po_eps`.
2. **Refinement** finds an injective mapping preserving types, labels, and syscall-constrained paths. Each template edge takes a simple path of at most `k` intermediate vertices whose terminal edge is of class σ and whose preceding edges are process creations.
3. **Scoring** weights matched vertices by confidence class (`0.20`, `0.33`, `0.47`) and alerts at `--tau` (default `0.43`).

Parameters: `--po_d` (128), `--k` (3), `--tau` (0.43), `--radius` (3).

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
| `trace_batch_run.py` | batch driver, paired and all-pairs |
| `eval_family.py` | template-family driver |

## Public Datasets

- DARPA Transparent Computing [E3](https://github.com/darpa-i2o/Transparent-Computing/blob/master/README-E3.md) and [E5](https://github.com/darpa-i2o/Transparent-Computing)
- [ATLASv2](https://bitbucket.org/sts-lab/atlasv2)
