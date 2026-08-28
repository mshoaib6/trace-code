"""Run stage 2 over every PoC and collect one sig-*.txt template per CVE.

Usage:  python3 compile_pocs.py <poc_dir> <out_dir>
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
TMP = HERE / "graphs"


def _richest(paths):
    """The variant with the most EDGE lines; ties broken by most NODE lines."""
    best, best_score = None, (-1, -1)
    for p in paths:
        text = p.read_text(encoding="utf-8")
        edges = text.count("\nEDGE ") + (1 if text.startswith("EDGE ") else 0)
        nodes = text.count("\nNODE ") + (1 if text.startswith("NODE ") else 0)
        if (edges, nodes) > best_score:
            best_score, best = (edges, nodes), p
    return best, best_score


def _compile(poc: Path, san: Path, keep_call_chain: bool):
    """Sanitize then compile one PoC; return the richest graph variant or None."""
    cmd = [sys.executable, "sanitize_poc.py", str(poc), "--out", str(san)]
    if keep_call_chain:
        cmd.append("--keep-call-chain")
    if subprocess.call(cmd, cwd=HERE, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL) != 0:
        return None, (0, 0)
    if not san.exists() or not san.read_text().strip():
        return None, (0, 0)
    shutil.rmtree(TMP, ignore_errors=True)
    TMP.mkdir(parents=True, exist_ok=True)
    subprocess.call([sys.executable, "main.py", str(san), "--format", "txt"],
                    cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    variants = sorted(TMP.glob("graph-*.txt"))
    if not variants:
        return None, (0, 0)
    return _richest(variants)


def main() -> int:
    poc_dir = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    san_dir = HERE / "_sanitized"
    san_dir.mkdir(exist_ok=True)

    rows = []
    for poc in sorted(poc_dir.glob("CVE-*.py")):
        cve = poc.stem
        san = san_dir / f"{cve}.py"
        chosen, (edges, nodes) = _compile(poc, san, keep_call_chain=False)
        note = ""
        if chosen is None or edges == 0:
            chosen, (edges, nodes) = _compile(poc, san, keep_call_chain=True)
            note = "retry:keep-call-chain"
        if chosen is None or edges == 0:
            rows.append((cve, 0, 0, "NO TEMPLATE (no log-evident anchor)"))
            continue
        (out_dir / f"sig-{cve}.txt").write_text(chosen.read_text(encoding="utf-8"),
                                                encoding="utf-8")
        rows.append((cve, nodes, edges, note))
    shutil.rmtree(TMP, ignore_errors=True)

    print(f"{'CVE':<22}{'NODE':>5}{'EDGE':>5}  note")
    print("-" * 62)
    for cve, n, e, note in rows:
        print(f"{cve:<22}{n:>5}{e:>5}  {note}")
    ok = sum(1 for _, _, e, _ in rows if e > 0)
    print(f"\n{ok}/{len(rows)} templates compiled with >=1 edge")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
