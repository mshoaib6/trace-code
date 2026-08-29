# TRACE Template Graphs

Compiles a Python PoC into syscall template graphs by parsing its AST and resolving library calls through a syscall mapping.

The PoCs distributed here are those of the 45 evaluated CVEs, one per CVE, which is what the end-to-end demonstration compiles. To compile at scale, first build the full PoC corpus with `1-trace-scraping/`; the templates it produces can then be aligned against the public provenance corpora linked in `3-trace-align/`.

## Requirements

Python 3.10.12, `autopep8`, `networkx`, `pydot==1.4.2`

```bash
pip3 install -r requirements.txt
```

## Usage

One PoC:

```bash
python3 main.py path/to/poc.py [--locus auto|local|remote]
```

A corpus, emitting every template variant per PoC:

```bash
python3 compile_pocs_family.py <poc_dir> <out_dir>
```

## Inputs

| File | Role |
|---|---|
| `syscall_mapping.json` | library call to syscall and argument selectors |
| `type_mapping.json` | syscall to object type and edge direction |
| `anchor_exclusions.json` | anchors excluded per CVE |

## Outputs

`graphs/graph-<n>.txt` for a single PoC, `<out_dir>/sig-<CVE>--<NN>.txt` plus `manifest.json` for a corpus.

## Pipeline

1. `main.py` calls `convert_graph.convert_graph`.
2. `helpers.clean_file` normalizes source and parses the AST.
3. `split_tree.split_tree` expands branches into AST variants.
4. `convert_graph.handle_tree` resolves calls to syscalls and builds the graph.
5. Unique graphs are written to `graphs/`.
