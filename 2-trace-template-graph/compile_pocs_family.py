"""Compile every PoC into its full *family* of template variants.

`compile_pocs.py` keeps one template per CVE -- the variant with the most edges.
That is a lossy choice: stage 2 already enumerates a family (branch variants
from `split_tree`, anchor splits from `_split_{local,remote}_anchors`), and the
locus is *inferred* rather than known, so the discarded members are legitimate
readings of the same PoC. The paper's grade counts a CVE as detected when any
family member satisfies the alert predicate, so evaluation needs the family,
not one representative.

The family is the union over three axes:

  sanitizer   default | --keep-call-chain
  locus       local   | remote            (both, rather than `_detect_locus`)
  variant     every `graphs/graph-*.txt` stage 2 writes for that combination

Members are deduplicated on final file content, which is stricter than stage
2's in-run dedupe: `_canonical_graph_signature` runs *before* `write_sig_txt`
normalizes syscalls and drops anonymous operands, so distinct pre-write graphs
routinely collapse to identical templates.

Usage:  python3 compile_pocs_family.py <poc_dir> <out_dir>

Writes `<out_dir>/sig-<CVE>--<NN>.txt` per family member plus a
`<out_dir>/manifest.json` recording which axis combination produced each.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
TMP = HERE / "graphs"

SAN_MODES = ("plain", "keep-call-chain")
LOCI = ("local", "remote")


def _counts(text: str):
    edges = text.count("\nEDGE ") + (1 if text.startswith("EDGE ") else 0)
    nodes = text.count("\nNODE ") + (1 if text.startswith("NODE ") else 0)
    return nodes, edges


def _sanitize(poc: Path, san: Path, keep_call_chain: bool) -> bool:
    cmd = [sys.executable, "sanitize_poc.py", str(poc), "--out", str(san)]
    if keep_call_chain:
        cmd.append("--keep-call-chain")
    if subprocess.call(cmd, cwd=HERE, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL) != 0:
        return False
    return san.exists() and bool(san.read_text(encoding="utf-8").strip())


def _emit(san: Path, locus: str):
    """Run stage 2 once and return every template it wrote, as text."""
    shutil.rmtree(TMP, ignore_errors=True)
    TMP.mkdir(parents=True, exist_ok=True)
    subprocess.call([sys.executable, "main.py", str(san), "--format", "txt",
                     "--locus", locus],
                    cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    out = []
    for p in sorted(TMP.glob("graph-*.txt")):
        text = p.read_text(encoding="utf-8")
        if text.strip():
            out.append((p.name, text))
    return out


def build_family(poc: Path, san_dir: Path):
    """Every distinct template this PoC yields, with its axis provenance."""
    cve = poc.stem
    members = []
    by_text = {}
    for san_mode in SAN_MODES:
        san = san_dir / f"{cve}--{san_mode}.py"
        if not _sanitize(poc, san, keep_call_chain=(san_mode == "keep-call-chain")):
            continue
        for locus in LOCI:
            for src_name, text in _emit(san, locus):
                key = text.strip()
                if key in by_text:
                    # Same template reached by another axis combination; record
                    # the extra provenance but do not duplicate the member.
                    by_text[key]["also"].append(f"{san_mode}/{locus}/{src_name}")
                    continue
                nodes, edges = _counts(text)
                rec = {
                    "cve": cve,
                    "text": text,
                    "san": san_mode,
                    "locus": locus,
                    "src": src_name,
                    "nodes": nodes,
                    "edges": edges,
                    "also": [],
                }
                by_text[key] = rec
                members.append(rec)
    return [m for m in members if m["edges"] > 0]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("poc_dir")
    ap.add_argument("out_dir")
    args = ap.parse_args()

    poc_dir = Path(args.poc_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("sig-*.txt"):
        stale.unlink()
    san_dir = HERE / "_sanitized_family"
    san_dir.mkdir(exist_ok=True)

    manifest = {}
    rows = []
    for poc in sorted(poc_dir.glob("CVE-*.py")):
        cve = poc.stem
        family = build_family(poc, san_dir)
        entries = []
        for i, m in enumerate(family):
            fname = f"sig-{cve}--{i:02d}.txt"
            (out_dir / fname).write_text(m["text"], encoding="utf-8")
            entries.append({k: v for k, v in m.items() if k != "text"} | {"file": fname})
        manifest[cve] = entries
        rows.append((cve, len(family),
                     max((m["edges"] for m in family), default=0),
                     sorted({m["locus"] for m in family})))
    shutil.rmtree(TMP, ignore_errors=True)
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"{'CVE':<22}{'VARIANTS':>9}{'MAXEDGE':>8}  loci")
    print("-" * 60)
    for cve, n, e, loci in rows:
        print(f"{cve:<22}{n:>9}{e:>8}  {','.join(loci)}")
    have = sum(1 for _, n, _, _ in rows if n > 0)
    total = sum(n for _, n, _, _ in rows)
    print(f"\n{have}/{len(rows)} CVEs yield >=1 template; {total} family members total")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
