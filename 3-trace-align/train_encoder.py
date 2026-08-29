"""Fit the partial-order encoder on a provenance corpus.

The encoder narrows the candidate space by order embedding for subgraph
containment. Training minimizes the order-embedding max-margin loss over pairs:
a positive is a rooted subgraph and a graph containing it, with loss
E(z_sub, z_sup); a negative corrupts one, either by resampling another graph's
rooted subgraph or by perturbing labels and edges, with loss max(0, alpha - E)^2
at margin alpha = 1.

No training corpus is distributed with this repository, so this is not run as
part of any result here. The encoder in po_encoder.npz is frozen: it was fitted
once, offline, and every evaluation loads it through
trace_align_po.load_po_encoder. Point --corpus at a directory of provenance
graphs in the NODE/EDGE format to refit.

Usage:
  python3 train_encoder.py --corpus <dir> [--out po_encoder.npz]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from trace_align_io import parse_graph_txt
from trace_align_features import Vocab, FeatureSpace
from trace_align_gnn import GNNSpec, RelationalGNN
from trace_align_po import POEncoder, order_violation_energy

ALPHA = 1.0


def _grad(W, x_sub, x_sup):
    """Gradient of E(z_sub, z_sup) in W, for the order-embedding loss."""
    pre_sub, pre_sup = W @ x_sub, W @ x_sup
    diff = np.maximum(0.0, np.maximum(0.0, pre_sub) - np.maximum(0.0, pre_sup))
    d_sub = 2.0 * diff * (pre_sub > 0).astype(float)
    d_sup = -2.0 * diff * (pre_sup > 0).astype(float)
    return np.outer(d_sub, x_sub) + np.outer(d_sup, x_sup)


def rooted_subgraph(G, rng, radius=2):
    nodes = list(G.nodes)
    if not nodes:
        return None
    root = str(rng.choice(nodes))
    seen, frontier = {root}, {root}
    for _ in range(radius):
        nxt = set()
        for u in frontier:
            nxt |= {v for _, v in G.out_edges(u)} | {v for v, _ in G.in_edges(u)}
        nxt -= seen
        seen |= nxt
        frontier = nxt
        if not frontier:
            break
    return G.subgraph(seen).copy()


def perturb(H, rng):
    P = H.copy()
    edges = list(P.edges(keys=True))
    if edges and rng.random() < 0.5:
        u, v, k = edges[int(rng.integers(0, len(edges)))]
        P.remove_edge(u, v, key=k)
    else:
        for n in list(P.nodes):
            if rng.random() < 0.3:
                P.nodes[n]["label"] = f"perturbed_{rng.integers(10_000)}"
    return P


def main() -> int:
    ap = argparse.ArgumentParser(description="Fit the partial-order encoder.")
    ap.add_argument("--corpus", required=True, help="Directory of provenance graphs.")
    ap.add_argument("--out", default="po_encoder.npz")
    ap.add_argument("--vocab", default="encoder_vocab.json")
    ap.add_argument("--d", type=int, default=128)
    ap.add_argument("--steps", type=int, default=6000)
    ap.add_argument("--lr", type=float, default=0.01)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    graphs = [parse_graph_txt(p) for p in sorted(Path(args.corpus).rglob("*.txt"))]
    if not graphs:
        raise SystemExit(f"No graphs found under {args.corpus}")

    V = json.loads(Path(args.vocab).read_text(encoding="utf-8"))["vocab"]
    classes = sorted(k.split(":", 1)[1] for k in V if k.startswith("edge:"))
    types = sorted(k.split(":", 1)[1] for k in V if k.startswith("ntype:"))
    gnn = RelationalGNN(node_types=types, edge_types=classes,
                        spec=GNNSpec(hidden=32, hash_dim=8, layers=1, seed=7))
    fs = FeatureSpace(vocab=Vocab(idx=V), gnn=gnn, counts_dim=len(V))

    rng = np.random.default_rng(args.seed)
    pairs = []
    for G in graphs:
        sub = rooted_subgraph(G, rng)
        if sub is None or sub.number_of_nodes() == 0:
            continue
        x_sub = fs.vectorize(sub)
        pairs.append((x_sub, fs.vectorize(G), 1))
        other = graphs[int(rng.integers(0, len(graphs)))]
        alt = rooted_subgraph(other, rng)
        if alt is not None and alt.number_of_nodes():
            pairs.append((fs.vectorize(alt), fs.vectorize(G), 0))
        pairs.append((x_sub, fs.vectorize(perturb(G, rng)), 0))
    if not pairs:
        raise SystemExit("No training pairs could be formed.")

    enc = POEncoder(d=args.d, F=fs.dim, seed=args.seed)
    init = np.zeros((args.d, fs.dim))
    for i in range(args.d):
        init[i, i % fs.dim] = 1.0
    enc.W = init + np.abs(rng.standard_normal((args.d, fs.dim))) * 0.001

    for step in range(args.steps):
        x_sub, x_sup, y = pairs[int(rng.integers(0, len(pairs)))]
        E = order_violation_energy(enc.embed(x_sub), enc.embed(x_sup))
        if y == 1:
            enc.W -= args.lr * _grad(enc.W, x_sub, x_sup)
        elif E < ALPHA:
            enc.W += args.lr * _grad(enc.W, x_sub, x_sup)
        enc.clip_nonneg()
        if (step + 1) % 100 == 0:
            enc.W *= 0.99

    np.savez(args.out, W=enc.W, d=args.d, F=fs.dim, vocab=json.dumps(V),
             gnn_hidden=32, gnn_hash=8, gnn_layers=1, gnn_seed=7)
    print(f"fitted on {len(pairs)} pairs from {len(graphs)} graphs -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
