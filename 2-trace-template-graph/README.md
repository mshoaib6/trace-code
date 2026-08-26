# TRACE Template Graphs

Generates system-call template graphs from Python PoC code by parsing ASTs, resolving library calls to syscall types,
and exporting unique directed graphs.

## Requirements
- Python 3.10+ (tested with 3.10.12 via pyenv)
- `autopep8`, `networkx`, `pydot==1.4.2`

## Quickstart
```bash
python3 -m venv env
source env/bin/activate
pip3 install -r requirements.txt

python3 main.py path/to/poc.py
```

## Inputs
- `main.py`: pass a Python PoC file path (absolute or workspace-relative) as the first argument.
- `type_mapping.json`: maps syscalls to object types and edge directions.
- `syscall_mapping.json`: maps library calls to syscalls and argument selectors.

## Outputs
- `graphs/graph-<n>.txt`: template graphs in the `NODE`/`EDGE` format stage 3 consumes.

Graphs are de-duplicated via isomorphism across branch variants.

## Pipeline Overview
1. `main.py` calls `convert_graph.convert_graph`.
2. `helpers.clean_file` normalizes source (autopep8/lib2to3) and parses the AST.
3. `split_tree.split_tree` expands branches into multiple AST variants.
4. `convert_graph.handle_tree` resolves calls to syscalls and builds a directed graph of `Node` objects.
5. Unique graphs are written to `graphs/`.

## Notes
- Process nodes are rendered as `*.*` so templates stay invariant to PoC filenames.
- Syscall labels are generalized (`execute`, `spawn`, `send`, `receive`, `memory`) for cross-platform templates.
- To generate templates at scale, first scrape the ~200G PoC corpus via `1-trace-scraping/`.

## Reading a Template Graph

Point `main.py` at any Python PoC:

```bash
python3 main.py path/to/poc.py
```

A local-privilege-escalation PoC that drops a payload and registers it for persistence, for example, yields a graph of the form:

- process → payload script and process → persistence config (file creation/modification)
- payload script → process and config → process (file read/use)
- process → permission and service-control commands (privileged execution flow)

Together these edges encode the template: a process writes a payload, modifies a persistence entry, and executes commands to load it. That behavior is what detection matches on, so the template holds even when filenames or paths differ.