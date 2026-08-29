from __future__ import annotations

import argparse
import os
import sys

_module_dir = os.path.dirname(os.path.abspath(__file__))
if _module_dir not in sys.path:
    sys.path.insert(0, _module_dir)

from trace_align_io import parse_graph_txt, expand_paths, label_matches
from trace_align_gnn import GNNSpec, RelationalGNN
from trace_align_features import Vocab, build_count_vocab, FeatureSpace
from trace_align_po import POEncoder, order_violation_energy, apo_score, load_po_encoder
from trace_align_align import process_centric_subgraphs, RefineSpec, AlignSpec, AlignResult, align_one, validation_suite
from trace_align_score import ScoreSpec, classify_vertices, classify_label, match_score


def main() -> None:
    ap = argparse.ArgumentParser(description="TRACE PO-GNN + partial-order screening + refinement alignment.")
    ap.add_argument("--sig", nargs="+", required=True, help="Signature graph .txt file(s) or directory(ies).")
    ap.add_argument("--prov", nargs="+", required=True, help="Provenance graph .txt file(s) or directory(ies).")
    ap.add_argument("--po_d", type=int, default=128, help="Embedding dimension d.")
    ap.add_argument("--tau", type=float, default=0.43, help="Alert threshold on the confidence-weighted match score.")
    ap.add_argument("--po_eps", type=float, default=1.0, help="PO margin eps for Apo = max(0, eps - E).")
    ap.add_argument("--po_theta", type=float, default=0.0, help="PO screening threshold on Apo.")
    ap.add_argument("--k", type=int, default=3, help="k tolerance (intermediate vertices) in refinement.")
    ap.add_argument("--radius", type=int, default=3, help="Process-centric subgraph radius (in hops).")
    ap.add_argument("--gnn_hidden", type=int, default=32, help="Hidden size for the PO-GNN feature block.")
    ap.add_argument("--gnn_hash", type=int, default=8, help="Hashed label feature size for PO-GNN.")
    ap.add_argument("--gnn_layers", type=int, default=1, help="Number of message-passing layers (>=1).")
    ap.add_argument("--gnn_seed", type=int, default=7, help="Random seed for fixed PO-GNN weights.")
    ap.add_argument("--train_steps", type=int, default=450, help="Training steps for PO projection (fast).")
    ap.add_argument("--train_lr", type=float, default=0.03, help="Learning rate for PO projection.")
    ap.add_argument("--train_seed", type=int, default=0, help="Training seed.")
    ap.add_argument("--verbose", action="store_true", help="Verbose alignment output.")
    ap.add_argument("--validate", action="store_true", help="Run aggressive validation suite.")
    args = ap.parse_args()

    sig_paths = expand_paths(args.sig)
    prov_paths = expand_paths(args.prov)

    sig_graphs = [parse_graph_txt(p) for p in sig_paths]
    prov_graphs = [parse_graph_txt(p) for p in prov_paths]

    feature_space, encoder = load_po_encoder()

    align_spec = AlignSpec(po_eps=args.po_eps, po_theta=args.po_theta, radius=args.radius,
                           refine=RefineSpec(k=args.k, max_depth=5), score=ScoreSpec(tau=args.tau))

    for si, Gsig in enumerate(sig_graphs):
        for pj, Gprov in enumerate(prov_graphs):
            res = align_one(Gsig, Gprov, feature_space, encoder, align_spec, verbose=args.verbose)
            print(f"\nSignature[{si}] vs Provenance[{pj}]")
            print(f"Alignment found? {res.found}")
            if res.found:
                print(f"Anchor process subgraph: {res.anchor_proc}")
                print("Vertex mapping (sig -> prov):")
                for k in sorted(res.mapping.keys()):
                    print(f"  {k:>10} -> {res.mapping[k]}")

        if args.validate and prov_graphs:
            validation_suite(Gsig, prov_graphs[0], feature_space, encoder, align_spec)


if __name__ == "__main__":
    main()
