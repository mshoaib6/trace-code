#!/usr/bin/env python3
"""Compile every generated PoC with stage 2 and align it against its trace.

Reports, per CVE: whether a template was produced, whether it carries a
discriminating (non-degenerate) anchor, and whether it alerts (alignment plus
the paper's mass floor). No per-CVE logic runs here -- the compiler lowers each
PoC blind; this only measures the outcome.
"""
from __future__ import annotations
import json, shutil, subprocess, sys
from pathlib import Path

HERE = Path(__file__).parent
REPO = HERE.parent.parent
S2 = REPO / "2-trace-template-graph"
S3 = REPO / "3-trace-align"
sys.path.insert(0, str(S3))
from trace_align_io import parse_graph_txt
from trace_align_features import build_count_vocab, FeatureSpace
from trace_align_gnn import GNNSpec, RelationalGNN
from trace_align_po import TrainSpec, train_po_encoder
from trace_align_align import align_one, AlignSpec, RefineSpec
from trace_align_score import ScoreSpec, classify_vertices, match_score, WEIGHTS, C2, C3, classify_label

MANIFEST = json.loads((HERE / "manifest.json").read_text())


def prov_for(cve):
    for d in (S3 / "poc_graphs/graphs", S3 / "splunk_extend/graphs"):
        p = d / f"prov-{cve}.txt"
        if p.exists():
            return p
    return None


def compile_poc(cve, locus):
    g = S2 / "graphs"
    if g.exists():
        shutil.rmtree(g)
    subprocess.run([sys.executable, "main.py", str(HERE / "poc" / f"{cve}.py"), "--locus", locus],
                   cwd=S2, capture_output=True, text=True, timeout=120)
    vs = sorted(g.glob("*.txt")) if g.exists() else []
    if not vs:
        return None
    best = max(vs, key=lambda v: v.read_text().count("EDGE "))
    return best.read_text() if best.read_text().count("EDGE ") else None


def has_discriminating_anchor(sig_text):
    for line in sig_text.splitlines():
        p = line.split(None, 3)
        if len(p) == 4 and p[0] == "NODE":
            lbl = p[3].strip()
            if classify_label(lbl) in (C2, C3) and lbl not in ("*", "*.(executable)", "*.*"):
                return True
    return False


def align(sig_text, prov_path):
    tmp = HERE / "_tmp_sig.txt"
    tmp.write_text(sig_text)
    sig = parse_graph_txt(tmp)
    prov = parse_graph_txt(prov_path)
    vocab = build_count_vocab([sig, prov])
    nts = sorted({d.get("type", "other") for G in (sig, prov) for _, d in G.nodes(data=True)} | {"other"})
    ets = sorted({str(d.get("syscall", "other")) for G in (sig, prov) for _, _, d in G.edges(data=True)} | {"other"})
    fs = FeatureSpace(vocab=vocab, gnn=RelationalGNN(nts, ets, GNNSpec()), counts_dim=vocab.size)
    enc = train_po_encoder(fs, [sig], [prov], TrainSpec())
    res = align_one(sig, prov, fs, enc, AlignSpec(po_eps=1.0, radius=3,
                    refine=RefineSpec(k=3, max_depth=5), score=ScoreSpec(tau=0.43)))
    if not res.found:
        return "no-align", 0.0, 0.0
    ms, raw, _ = match_score(classify_vertices(sig), res.mapping)
    return ("alert" if raw >= WEIGHTS[C3] else "weak-floor"), ms, raw


def main():
    rows = []
    for cve in sorted(MANIFEST):
        locus = MANIFEST[cve]["locus"]
        prov = prov_for(cve)
        sig_text = compile_poc(cve, locus)
        if sig_text is None:
            rows.append((cve, locus, "no-template", 0, 0, False))
            continue
        disc = has_discriminating_anchor(sig_text)
        status, ms, raw = align(sig_text, prov)
        rows.append((cve, locus, status, ms, raw, disc))
    print(f"{'CVE':16}{'locus':7}{'status':12}{'ms':>6}{'mass':>7}  disc-anchor")
    print("-" * 62)
    good = 0
    for cve, locus, status, ms, raw, disc in rows:
        ok = status == "alert" and disc
        good += ok
        flag = "" if ok else "   <-- FIX"
        print(f"{cve:16}{locus:7}{status:12}{ms:6.2f}{raw:7.2f}  {disc}{flag}")
    print(f"\nDETECTED (alert + discriminating anchor): {good}/{len(rows)}")
    tmp = HERE / "_tmp_sig.txt"
    if tmp.exists():
        tmp.unlink()


if __name__ == "__main__":
    main()
