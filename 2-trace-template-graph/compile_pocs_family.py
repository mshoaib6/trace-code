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


EXCLUSIONS = HERE / "anchor_exclusions.json"


def _load_exclusions():
    if not EXCLUSIONS.exists():
        return {}
    raw = json.loads(EXCLUSIONS.read_text(encoding="utf-8"))
    return {k: set(v.get("exclude", ())) for k, v in raw.items()
            if not k.startswith("_") and isinstance(v, dict)}


def apply_exclusions(cve, text, excluded):
    if not excluded:
        return text, 0
    out, dropped = [], 0
    for line in text.splitlines():
        f = line.split(None, 3)
        if not f or f[0] != "NODE" or len(f) < 4:
            out.append(line)
            continue
        brs = [b.strip() for b in f[3].split("|") if b.strip()]
        keep = [b for b in brs if b not in excluded]
        if len(keep) == len(brs):
            out.append(line)
            continue
        dropped += len(brs) - len(keep)
        if not keep:
            return None, dropped
        out.append(f"{f[0]} {f[1]} {f[2]} " + " | ".join(keep))
    return "\n".join(out) + ("\n" if out else ""), dropped


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Compile every PoC into its full family of template variants.")
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

    exclusions = _load_exclusions()
    excluded_total = 0
    manifest = {}
    rows = []
    for poc in sorted(poc_dir.glob("CVE-*.py")):
        cve = poc.stem
        family = build_family(poc, san_dir)
        drop = exclusions.get(cve, set())
        entries = []
        kept = []
        for m in family:
            text, n = apply_exclusions(cve, m["text"], drop)
            excluded_total += n
            if text is None:
                continue
            kept.append((m, text))
        family = [m for m, _ in kept]
        for i, (m, text) in enumerate(kept):
            fname = f"sig-{cve}--{i:02d}.txt"
            (out_dir / fname).write_text(text, encoding="utf-8")
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
    if excluded_total:
        print(f"anchor_exclusions.json: dropped {excluded_total} label branch(es) "
              f"across {len(exclusions)} CVE(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
