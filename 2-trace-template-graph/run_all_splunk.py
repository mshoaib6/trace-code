"""Run stage 2 on every poc_splunk/*.py and collect sig-*.txt graphs.

For each PoC, stage 2 may emit multiple path-variant graphs; we keep the largest
(most edges) as the canonical sig, mirroring how the paper's stage-2 evaluation
selects the richest variant per CVE.

Output: sig_splunk/sig-CVE-*.txt  (stage-3-ready NODE/EDGE format).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).parent
POC_DIR = HERE / "poc_splunk"
TMP_OUT = HERE / "graphs"
SIG_DIR = HERE / "sig_splunk"


def _pick_richest(graph_files):
    """Pick the graph variant with the most EDGE lines; break ties by most NODE lines."""
    best = None
    best_score = (-1, -1)
    for p in graph_files:
        text = p.read_text(encoding="utf-8")
        n_edges = text.count("\nEDGE ") + (1 if text.startswith("EDGE ") else 0)
        n_nodes = text.count("\nNODE ") + (1 if text.startswith("NODE ") else 0)
        score = (n_edges, n_nodes)
        if score > best_score:
            best_score = score
            best = p
    return best


def main() -> int:
    SIG_DIR.mkdir(exist_ok=True)
    summary = []
    for poc in sorted(POC_DIR.glob("CVE-*.py")):
        cve = poc.stem
        # Wipe prior graphs/ output so each PoC starts clean.
        if TMP_OUT.exists():
            for f in TMP_OUT.glob("graph-*"):
                f.unlink()
        else:
            TMP_OUT.mkdir()

        rc = subprocess.call(
            [sys.executable, "main.py", str(poc), "--format", "txt"],
            cwd=HERE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        variants = sorted(TMP_OUT.glob("graph-*.txt"))
        if rc != 0 or not variants:
            summary.append((cve, 0, 0, "FAILED"))
            continue

        chosen = _pick_richest(variants)
        text = chosen.read_text()
        n_edges = text.count("\nEDGE ") + (1 if text.startswith("EDGE ") else 0)
        n_nodes = text.count("\nNODE ") + (1 if text.startswith("NODE ") else 0)
        # Reject vacuous sigs (just the base process, no edges): they would
        # match every prov and blow up the false-positive rate.
        if n_edges == 0:
            summary.append((cve, n_nodes, n_edges, "REJECTED (0 edges, PoC has no log-evident anchor)"))
            continue
        dst = SIG_DIR / f"sig-{cve}.txt"
        shutil.copyfile(chosen, dst)
        summary.append((cve, n_nodes, n_edges, f"{len(variants)} variants"))

    print(f"{'CVE':<22} {'NODE':>5} {'EDGE':>5}  status")
    print("-" * 60)
    for cve, n, e, status in summary:
        print(f"{cve:<22} {n:>5} {e:>5}  {status}")
    ok = sum(1 for _, _, e, _ in summary if e > 0)
    print(f"\n{ok}/{len(summary)} sigs produced with >=1 edge")
    return 0 if ok == len(summary) else 1


if __name__ == "__main__":
    sys.exit(main())
