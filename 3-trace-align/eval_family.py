#!/usr/bin/env python3
"""Grade compiled template *families* against provenance graphs.

`trace_batch_run.py` pairs one signature with one provenance graph. Stage 2,
though, emits a family of templates per PoC (branch variants, anchor splits,
and -- since the locus is inferred, not known -- both the runner-side and
target-side readings), and `compile_pocs.py` keeps only the richest member.
The paper's grade counts a CVE as detected when *any* family member satisfies
the alert predicate, so this runner evaluates the whole family:

  detected(CVE)      := any variant of CVE aligns against prov-CVE
  false alert(A, B)  := any variant of A aligns against prov-B, for B a
                        different capture from A

Reporting both matters. Widening the family can only raise detection, so the
detection number alone is not evidence of anything; the cross-CVE alert count
under the *same* widened family is what says whether the extra members are
discriminative or merely permissive.

Encoder training mirrors `trace_batch_run.py`: one leave-one-CVE-out model per
CVE, trained on the other CVEs' family members and provenance graphs, so a
template is never scored by an encoder that saw it.

Usage:
  python3 eval_family.py --family_dir DIR --prov_dir D [D ...] [--all_pairs]

Family members are `sig-<CVE>--<NN>.txt`; provenance graphs are `prov-<CVE>.txt`.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_CVE_RE = re.compile(r"(CVE-\d{4}-\d+)")


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
    name = "trace_align_dyn"
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not import trace_align from: {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore
    return mod


def cve_of(name: str) -> str:
    m = _CVE_RE.search(name or "")
    return m.group(1) if m else (name or "")


def discover_family(family_dir: Path) -> Dict[str, List[Path]]:
    fam: Dict[str, List[Path]] = defaultdict(list)
    for p in sorted(family_dir.rglob("sig-*.txt")):
        fam[cve_of(p.name)].append(p)
    if not fam:
        raise ValueError(f"No family templates found under {family_dir} (expected sig-*.txt).")
    return dict(fam)


def discover_prov(prov_dirs: List[Path]) -> Dict[str, Path]:
    provs: Dict[str, Path] = {}
    for d in prov_dirs:
        for p in sorted(d.rglob("prov-*.txt")):
            cve = cve_of(p.name)
            if cve in provs and provs[cve].read_bytes() != p.read_bytes():
                raise ValueError(f"Two different provenance graphs for {cve}: "
                                 f"{provs[cve]} and {p}")
            provs.setdefault(cve, p)
    if not provs:
        raise ValueError(f"No provenance graphs found under {prov_dirs} (expected prov-*.txt).")
    return provs


def capture_groups(provs: Dict[str, Path]) -> Dict[str, str]:
    """CVEs sharing a byte-identical capture are one co-exercised bundle.

    Some vendor bundles publish a single capture that exercises several CVEs at
    once (the four Junos J-Web CVEs are one such chain). A pair drawn from
    inside such a group compares a capture against itself, not two different
    CVEs, so it is not a cross-CVE comparison.
    """
    return {cve: hashlib.md5(p.read_bytes()).hexdigest() for cve, p in provs.items()}


def _restrict(members: List[Path], manifest: Optional[dict], args) -> List[Path]:
    """Apply the family-axis ablation flags to one CVE's members."""
    if manifest is None:
        return members
    by_file = {e["file"]: e for e in manifest}
    keep = []
    for p in members:
        e = by_file.get(p.name)
        if e is None:
            keep.append(p)
            continue
        if args.locus and e.get("locus") not in args.locus:
            continue
        if args.san and e.get("san") not in args.san:
            continue
        keep.append(p)
    if args.richest_only and keep:
        def score(p: Path):
            e = by_file.get(p.name, {})
            return (e.get("edges", 0), e.get("nodes", 0), p.name)
        keep = [max(keep, key=score)]
    return keep


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--family_dir", required=True,
                    help="Directory of sig-<CVE>--<NN>.txt family members (from compile_pocs_family.py).")
    ap.add_argument("--prov_dir", nargs="+", required=True,
                    help="Directory(ies) containing prov-<CVE>.txt.")
    ap.add_argument("--trace_align", default="trace_align.py")
    ap.add_argument("--all_pairs", action="store_true",
                    help="Also score every family against every other CVE's provenance.")
    ap.add_argument("--out_csv", default="")
    ap.add_argument("--out", default="",
                    help="Tee stdout to this file (default: eval_family[-all_pairs].txt).")

    # Family-axis ablation (needs manifest.json in --family_dir).
    ap.add_argument("--locus", nargs="*", default=None, choices=["local", "remote"],
                    help="Restrict the family to these loci.")
    ap.add_argument("--san", nargs="*", default=None, choices=["plain", "keep-call-chain"],
                    help="Restrict the family to these sanitizer modes.")
    ap.add_argument("--richest_only", action="store_true",
                    help="Keep only the most-edges member, reproducing compile_pocs.py.")

    ap.add_argument("--po_d", type=int, default=128)
    ap.add_argument("--tau", type=float, default=0.43)
    ap.add_argument("--po_eps", type=float, default=1.0)
    ap.add_argument("--po_theta", type=float, default=0.0)
    ap.add_argument("--k", type=int, default=3)
    ap.add_argument("--radius", type=int, default=3)
    ap.add_argument("--gnn_hidden", type=int, default=32)
    ap.add_argument("--gnn_hash", type=int, default=8)
    ap.add_argument("--gnn_layers", type=int, default=1)
    ap.add_argument("--gnn_seed", type=int, default=7)
    ap.add_argument("--train_steps", type=int, default=450)
    ap.add_argument("--train_lr", type=float, default=0.03)
    ap.add_argument("--train_seed", type=int, default=0)
    args = ap.parse_args()

    out_name = args.out or ("eval_family-all_pairs.txt" if args.all_pairs else "eval_family.txt")
    out_path = Path(out_name).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_file = out_path.open("w", encoding="utf-8")
    stdout = sys.stdout
    sys.stdout = Tee(stdout, out_file)
    try:
        run(args)
    finally:
        sys.stdout.flush()
        sys.stdout = stdout
        out_file.close()
    print(f"Wrote {out_path}")


def run(args) -> None:
    mod = load_trace_align_module(Path(args.trace_align).expanduser().resolve())

    family_dir = Path(args.family_dir).expanduser().resolve()
    prov_dirs = [Path(d).expanduser().resolve() for d in args.prov_dir]

    family = discover_family(family_dir)
    provs = discover_prov(prov_dirs)

    manifest_path = family_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    if (args.locus or args.san or args.richest_only) and not manifest:
        raise SystemExit(f"--locus/--san/--richest_only need {manifest_path}")

    family = {cve: _restrict(ms, manifest.get(cve), args) for cve, ms in family.items()}
    family = {cve: ms for cve, ms in family.items() if ms}

    sig_by_path = {p: mod.parse_graph_txt(p) for ms in family.values() for p in ms}
    prov_by_cve = {cve: mod.parse_graph_txt(p) for cve, p in provs.items()}
    groups = capture_groups(provs)

    def build_model(sig_train, prov_train):
        vocab = mod.build_count_vocab(list(sig_train) + list(prov_train))
        node_types = sorted({d.get("type", "other")
                             for G in (list(sig_train) + list(prov_train))
                             for _, d in G.nodes(data=True)} | {"other"})
        edge_types = sorted({str(d.get("syscall", "other"))
                             for G in (list(sig_train) + list(prov_train))
                             for _, _, d in G.edges(data=True)} | {"other"})
        gspec = mod.GNNSpec(hidden=args.gnn_hidden, hash_dim=args.gnn_hash,
                            layers=max(1, args.gnn_layers), seed=args.gnn_seed)
        gnn = mod.RelationalGNN(node_types=node_types, edge_types=edge_types, spec=gspec)
        feature_space = mod.FeatureSpace(vocab=vocab, gnn=gnn, counts_dim=vocab.size)
        tspec = mod.TrainSpec(d=args.po_d, lr=args.train_lr, steps=args.train_steps,
                              eps=args.po_eps, seed=args.train_seed)
        return feature_space, mod.train_po_encoder(feature_space, list(sig_train),
                                                   list(prov_train), tspec)

    all_sigs = list(sig_by_path.values())
    all_provs = list(prov_by_cve.values())
    global_model = build_model(all_sigs, all_provs)

    models: Dict[str, tuple] = {}
    for cve in sorted(set(family) | set(prov_by_cve)):
        held = set(family.get(cve, []))
        sig_train = [g for p, g in sig_by_path.items() if p not in held]
        prov_train = [g for c, g in prov_by_cve.items() if c != cve]
        models[cve] = build_model(sig_train, prov_train) if (sig_train and prov_train) else global_model

    align_spec = mod.AlignSpec(
        po_eps=args.po_eps,
        po_theta=args.po_theta,
        radius=args.radius,
        refine=mod.RefineSpec(k=args.k, max_depth=5),
        score=mod.ScoreSpec(tau=args.tau),
    )

    def aligns(cve: str, sig_path: Path, prov_cve: str):
        feature_space, encoder = models.get(cve, global_model)
        return mod.align_one(sig_by_path[sig_path], prov_by_cve[prov_cve],
                             feature_space, encoder, align_spec, verbose=False)

    rows = []
    paired_cves = sorted(c for c in family if c in prov_by_cve)

    print("=== Paired: family vs own provenance ===")
    detected = 0
    for cve in paired_cves:
        members = family[cve]
        hits = []
        for sp in members:
            res = aligns(cve, sp, cve)
            rows.append((cve, sp.name, cve, bool(res.found), res.anchor_proc or "",
                         len(res.mapping) if res.mapping else 0))
            if res.found:
                hits.append(sp.name)
        if hits:
            detected += 1
        mark = "OK " if hits else "-- "
        print(f"{mark}{cve:<20} {len(hits)}/{len(members):<3} members align"
              + (f"   first: {hits[0]}" if hits else ""))
    print(f"\nDetected under the family rule: {detected}/{len(paired_cves)}")

    no_template = sorted(c for c in prov_by_cve if c not in family)
    if no_template:
        print(f"No template compiled ({len(no_template)}): {', '.join(no_template)}")
    no_prov = sorted(c for c in family if c not in prov_by_cve)
    if no_prov:
        print(f"Family compiled but no provenance graph ({len(no_prov)}): {', '.join(no_prov)}")

    if args.all_pairs:
        print("\n=== Cross-CVE: family vs other captures ===")
        considered = 0
        alerting = 0
        offenders = defaultdict(list)
        for cve in paired_cves:
            for other in sorted(prov_by_cve):
                if other == cve or groups.get(other) == groups.get(cve):
                    continue
                considered += 1
                hit = None
                for sp in family[cve]:
                    res = aligns(cve, sp, other)
                    rows.append((cve, sp.name, other, bool(res.found), res.anchor_proc or "",
                                 len(res.mapping) if res.mapping else 0))
                    if res.found and hit is None:
                        hit = sp.name
                if hit is not None:
                    alerting += 1
                    offenders[cve].append((other, hit))
        print(f"Cross-CVE false alerts (family rule): {alerting}/{considered}")
        for cve in sorted(offenders):
            for other, member in offenders[cve]:
                print(f"  {cve} -> prov-{other}  via {member}")

    if args.out_csv:
        outp = Path(args.out_csv).expanduser().resolve()
        outp.parent.mkdir(parents=True, exist_ok=True)
        with outp.open("w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["cve", "sig_file", "prov_cve", "found", "anchor_proc", "mapping_size"])
            for r in rows:
                w.writerow([r[0], r[1], r[2], 1 if r[3] else 0, r[4], r[5]])
        print(f"Wrote CSV: {outp}")


if __name__ == "__main__":
    main()
