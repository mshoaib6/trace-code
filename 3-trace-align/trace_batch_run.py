#!/usr/bin/env python3
"""
trace_batch_run.py
Batch runner for TRACE alignment using trace_align.py.

What it does:
  - Loads many signature graphs (sig-*.txt) and provenance graphs (prov-*.txt)
  - Trains the PO encoder once (fast, "online per run" style for quick and fully reproducible evaluation from scratch)
  - Runs alignment for each (sig, prov) pair
    * default pairing: match by key (e.g., CVE-2023-23488) extracted from filenames
Dependencies (same as trace_align.py):
  - Python 3.10.12
  - numpy
  - networkx

Example:
  python trace_batch_run.py --graphs_dir ./graphs --trace_align ./trace_align.py --show_mapping
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple, Optional


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            s.write(data)

    def flush(self):
        for s in self.streams:
            s.flush()


def load_trace_align_module(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"trace_align.py not found: {path}")

    module_name = "trace_align_dyn"
    if module_name in sys.modules:
        del sys.modules[module_name]

    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not import trace_align from: {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod  # critical for @dataclass in Python 3.10
    spec.loader.exec_module(mod)  # type: ignore
    return mod

def discover_graphs(root: Path) -> Tuple[List[Path], List[Path]]:
    sigs = sorted(root.rglob("sig-*.txt"))
    provs = sorted(root.rglob("prov-*.txt"))
    if not sigs:
        raise ValueError(f"No signature graphs found under {root} (expected sig-*.txt).")
    if not provs:
        raise ValueError(f"No provenance graphs found under {root} (expected prov-*.txt).")
    return sigs, provs


def key_from_filename(p: Path) -> str:
    stem = p.stem
    if stem.startswith("sig-"):
        return stem[len("sig-"):]
    if stem.startswith("prov-"):
        return stem[len("prov-"):]
    return stem


@dataclass
class Pair:
    key: str
    sig_path: Path
    prov_path: Path


def _cve_of(name: str) -> str:
    m = re.search(r"(CVE-\d{4}-\d+)", name or "")
    return m.group(1) if m else (name or "")


def report_all_pairs_metrics(rows, graphs_dir: Path) -> None:
    """P@1 and cross-CVE false alerts over the all-pairs matrix.

    Some vendor bundles are published as one co-exercised capture covering
    several CVEs at once (the four Junos J-Web CVEs are one such chain), so
    those CVEs share identical signature and provenance files. A pair drawn
    from inside such a group compares a capture with a copy of itself rather
    than two different CVEs, and is not a cross-CVE comparison.
    """
    group: Dict[str, str] = {}
    for sp in graphs_dir.rglob("sig-*.txt"):
        cve = _cve_of(sp.name)
        pp = sp.with_name(sp.name.replace("sig-", "prov-", 1))
        if pp.exists():
            group[cve] = (hashlib.md5(sp.read_bytes()).hexdigest()
                          + hashlib.md5(pp.read_bytes()).hexdigest())

    by_sig: Dict[str, list] = {}
    for r in rows:
        by_sig.setdefault(_cve_of(r[1]), []).append(r)

    p_at_1 = 0
    cross_alerts = 0
    considered = 0
    for cve, rs in by_sig.items():
        if any(r[3] for r in rs if _cve_of(r[2]) == cve):
            p_at_1 += 1
        for r in rs:
            other = _cve_of(r[2])
            if other == cve or group.get(other, other) == group.get(cve, cve):
                continue
            considered += 1
            if r[3]:
                cross_alerts += 1

    print(f"P@1 (correct provenance aligned): {p_at_1}/{len(by_sig)}")
    print(f"Cross-CVE false alerts: {cross_alerts}/{considered}")


def build_pairs(sig_paths: List[Path], prov_paths: List[Path], all_pairs: bool) -> List[Pair]:
    if all_pairs:
        pairs: List[Pair] = []
        for sp in sig_paths:
            sk = key_from_filename(sp)
            for pp in prov_paths:
                pk = key_from_filename(pp)
                pairs.append(Pair(key=f"{sk}__VS__{pk}", sig_path=sp, prov_path=pp))
        return pairs

    sig_by_key: Dict[str, Path] = {key_from_filename(p): p for p in sig_paths}
    prov_by_key: Dict[str, Path] = {key_from_filename(p): p for p in prov_paths}
    keys = sorted(set(sig_by_key.keys()) & set(prov_by_key.keys()))
    if not keys:
        raise ValueError(
            "No matching keys between sig-* and prov-* filenames.\n"
            "Either rename files so keys match (sig-KEY.txt with prov-KEY.txt)\n"
            "or use --all_pairs."
        )
    return [Pair(key=k, sig_path=sig_by_key[k], prov_path=prov_by_key[k]) for k in keys]


def main() -> None:
    ap = argparse.ArgumentParser(description="Batch runner for trace_align.py on many sig/prov graphs.")
    ap.add_argument("--graphs_dir", type=str, required=True, help="Directory containing sig-*.txt and prov-*.txt (recursively).")
    ap.add_argument("--trace_align", type=str, default="trace_align.py", help="Path to trace_align.py (default: ./trace_align.py).")

    ap.add_argument("--all_pairs", action="store_true", help="Run all signature graphs against all provenance graphs (cross product).")
    ap.add_argument("--show_mapping", action="store_true", help="Print the final vertex mapping for successful alignments.")
    ap.add_argument("--out_csv", type=str, default="", help="Optional: write a CSV summary to this path.")

    ap.add_argument("--po_d", type=int, default=128)
    ap.add_argument("--tau", type=float, default=0.43, help="Alert threshold on the confidence-weighted match score.")
    ap.add_argument("--po_eps", type=float, default=1.0)
    ap.add_argument("--po_theta", type=float, default=0.0)
    ap.add_argument("--k", type=int, default=3)
    ap.add_argument("--radius", type=int, default=3)

    # PO-GNN feature block params
    ap.add_argument("--gnn_hidden", type=int, default=32)
    ap.add_argument("--gnn_hash", type=int, default=8)
    ap.add_argument("--gnn_layers", type=int, default=1)
    ap.add_argument("--gnn_seed", type=int, default=7)

    ap.add_argument("--train_steps", type=int, default=450)
    ap.add_argument("--train_lr", type=float, default=0.03)
    ap.add_argument("--train_seed", type=int, default=0)

    ap.add_argument("--verbose", action="store_true", help="Verbose stage1 candidate prints per pair.")
    args = ap.parse_args()

    graphs_dir = Path(args.graphs_dir).expanduser().resolve()
    trace_align_path = Path(args.trace_align).expanduser().resolve()

    out_name = "output-all_pairs.txt" if args.all_pairs else "output.txt"
    out_path = Path(out_name).resolve()
    out_file = out_path.open("w", encoding="utf-8")
    stdout = sys.stdout
    sys.stdout = Tee(stdout, out_file)
    try:
        run_batch(graphs_dir, trace_align_path, args)
    finally:
        sys.stdout.flush()
        sys.stdout = stdout
        out_file.close()

def run_batch(graphs_dir: Path, trace_align_path: Path, args) -> None:
    mod = load_trace_align_module(trace_align_path)

    sig_paths, prov_paths = discover_graphs(graphs_dir)
    pairs = build_pairs(sig_paths, prov_paths, all_pairs=args.all_pairs)

    sig_by_path = {p: mod.parse_graph_txt(p) for p in sig_paths}
    prov_by_path = {p: mod.parse_graph_txt(p) for p in prov_paths}
    sig_graphs = list(sig_by_path.values())
    prov_graphs = list(prov_by_path.values())

    def build_model(sig_train, prov_train):
        vocab = mod.build_count_vocab(list(sig_train) + list(prov_train))
        node_types = sorted({d.get("type", "other") for G in (list(sig_train) + list(prov_train)) for _, d in G.nodes(data=True)} | {"other"})
        edge_types = sorted({str(d.get("syscall", "other")) for G in (list(sig_train) + list(prov_train)) for _, _, d in G.edges(data=True)} | {"other"})
        gspec = mod.GNNSpec(hidden=args.gnn_hidden, hash_dim=args.gnn_hash, layers=max(1, args.gnn_layers), seed=args.gnn_seed)
        gnn = mod.RelationalGNN(node_types=node_types, edge_types=edge_types, spec=gspec)
        feature_space = mod.FeatureSpace(vocab=vocab, gnn=gnn, counts_dim=vocab.size)
        tspec = mod.TrainSpec(d=args.po_d, lr=args.train_lr, steps=args.train_steps, eps=args.po_eps, seed=args.train_seed)
        encoder = mod.train_po_encoder(feature_space, list(sig_train), list(prov_train), tspec)
        return feature_space, encoder

    global_model = build_model(sig_graphs, prov_graphs)
    models_by_key = {}
    for sp in sig_paths:
        key = key_from_filename(sp)
        if key in models_by_key:
            continue
        sig_train = [g for p, g in sig_by_path.items() if key_from_filename(p) != key]
        prov_train = [g for p, g in prov_by_path.items() if key_from_filename(p) != key]
        if not sig_train or not prov_train:
            models_by_key[key] = global_model
        else:
            models_by_key[key] = build_model(sig_train, prov_train)

    align_spec = mod.AlignSpec(
        po_eps=args.po_eps,
        po_theta=args.po_theta,
        radius=args.radius,
        refine=mod.RefineSpec(k=args.k, max_depth=5),
        score=mod.ScoreSpec(tau=args.tau),
    )

    rows = []
    ok_count = 0

    for pair in pairs:
        Gsig = sig_by_path[pair.sig_path]
        Gprov = prov_by_path[pair.prov_path]
        model = models_by_key.get(key_from_filename(pair.sig_path), global_model)
        feature_space, encoder = model
        res = mod.align_one(Gsig, Gprov, feature_space, encoder, align_spec, verbose=args.verbose)

        if res.found:
            ok_count += 1

        print(f"\n[{pair.key}]")
        print(f"  sig:  {pair.sig_path.name}")
        print(f"  prov: {pair.prov_path.name}")
        print(f"  Alignment found? {res.found}")
        if res.found:
            print(f"  Anchor process subgraph: {res.anchor_proc}")
            if args.show_mapping:
                print("  Vertex mapping (sig -> prov):")
                for k in sorted(res.mapping.keys()):
                    print(f"    {k:>12} -> {res.mapping[k]}")

        rows.append((
            pair.key,
            pair.sig_path.name,
            pair.prov_path.name,
            bool(res.found),
            res.anchor_proc or "",
            len(res.mapping) if res.mapping else 0,
        ))

    print(f"\n=== Batch summary ===")
    print(f"Pairs evaluated: {len(pairs)}")
    print(f"Alignments found: {ok_count}")

    if args.all_pairs:
        report_all_pairs_metrics(rows, graphs_dir)

    if args.out_csv:
        outp = Path(args.out_csv).expanduser().resolve()
        outp.parent.mkdir(parents=True, exist_ok=True)
        with outp.open("w", encoding="utf-8") as f:
            f.write("pair_key,sig_file,prov_file,found,anchor_proc,mapping_size\n")
            for r in rows:
                f.write(",".join([
                    str(r[0]),
                    str(r[1]),
                    str(r[2]),
                    "1" if r[3] else "0",
                    str(r[4]),
                    str(r[5]),
                ]) + "\n")
        print(f"Wrote CSV: {outp}")


if __name__ == "__main__":
    main()
