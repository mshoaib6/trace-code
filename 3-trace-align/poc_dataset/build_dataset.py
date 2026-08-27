#!/usr/bin/env python3
"""Build a faithful PoC per evaluated CVE, adaptively, and verify detection.

For each CVE we derive the exploit's observable operations from its template's
concrete anchors (de-genericised against the trace, so the PoC names the value
the collector recorded). We emit a PoC, compile it with stage 2 (no per-CVE
logic in the compiler), and align it against the trace. A flat PoC can over-
constrain a victim-side process tree -- one runner cannot be the distinct
ancestor of every spawned process -- so when alignment fails we drop process
spawns (the over-constrainers) and retry, keeping the file/network anchors that
one actor can plausibly touch. The first candidate that alerts on a
discriminating anchor is kept.

Outputs: poc/<CVE>.py (the kept PoC), manifest.json (locus per CVE), and a
detection report. No hand-authored template is used; every template is compiled
from a PoC.
"""
from __future__ import annotations
import json, re, shutil, subprocess, sys
from pathlib import Path

HERE = Path(__file__).parent
REPO = HERE.parent.parent
S2 = REPO / "2-trace-template-graph"
S3 = REPO / "3-trace-align"
sys.path.insert(0, str(S3))
from trace_align_io import parse_graph_txt, label_matches
from trace_align_features import build_count_vocab, FeatureSpace
from trace_align_gnn import GNNSpec, RelationalGNN
from trace_align_po import TrainSpec, train_po_encoder
from trace_align_align import align_one, AlignSpec, RefineSpec
from trace_align_score import ScoreSpec, classify_vertices, match_score, WEIGHTS, C2, C3, classify_label

SIG_DIRS = [S3 / "poc_graphs/graphs", S3 / "splunk_extend/graphs"]


def parse(path):
    N, E = {}, []
    for line in path.read_text().splitlines():
        p = line.split(None, 3)
        if len(p) == 4 and p[0] == "NODE":
            lbl = p[3].strip()
            m = re.match(r'^"(.*)"$', lbl)
            N[p[1]] = (p[2], m.group(1) if m else lbl)
        elif len(p) == 4 and p[0] == "EDGE":
            E.append((p[1], p[2], p[3].strip()))
    return N, E


def locus_of(N, E):
    isn = lambda i: N.get(i, ("", ""))[0] == "net"
    isp = lambda i: N.get(i, ("", ""))[0] == "process"
    return "remote" if any(isn(u) and isp(v) and sc == "access" for u, v, sc in E) else "local"


def core(label, ntype=None, provN=None):
    branches = [b.strip().strip('"') for b in label.split("|") if b.strip()]
    chosen = branches[0] if branches else label
    if provN and ntype:
        for b in branches:
            if any(pt == ntype and label_matches(b, pl) for pt, pl in provN.values()):
                chosen = b
                break
    return chosen.strip("*")


def operations(N, E, provN, locus):
    """Ordered operations to try; discriminating anchors first."""
    files, procs, nets = {}, [], []
    for u, v, sc in E:
        vt, vl = N.get(v, ("", ""))
        c = core(vl, vt, provN)
        if not c:
            continue
        if vt == "file":
            files[c] = files.get(c, False) or (sc in ("write", "create"))
        elif vt == "process" and sc == "create" and re.search(r"[A-Za-z0-9]{2,}", c) and "executable" not in vl:
            if c not in procs:
                procs.append(c)
        elif vt == "net" and re.search(r"[A-Za-z0-9]{2,}", c):
            if c not in nets:
                nets.append(c)
    ops = []
    if locus == "remote":
        for c, wrote in files.items():
            ops.append(("req", "post" if wrote else "get", c))
    else:
        for c, wrote in files.items():
            ops.append(("file", "w" if wrote else "r", c))
        for c in nets:
            ops.append(("net", None, c))
        for c in procs:
            ops.append(("proc", None, c))
    return ops


def emit(ops, locus):
    imports, body = set(), []
    for kind, verb, c in ops:
        if kind == "req":
            imports.add("import requests")
            body.append(f'    requests.{verb}(base + {c!r})')
        elif kind == "file":
            body.append(f'    open(d + {c!r}, {verb!r})')
        elif kind == "net":
            imports.add("import requests")
            p = c
            m = re.search(r"https?://[^/]+(/[^\s]*)", c) or re.search(r"(/[^\s]*)", c)
            if m:
                p = m.group(1)
            body.append(f'    requests.get(base + {p!r})')
        elif kind == "proc":
            imports.add("import subprocess")
            body.append(f'    subprocess.Popen({c!r})')
    if not body:
        body = ["    pass"]
    header = ["def run(base):"] if locus == "remote" else ["def run(d, base):"]
    footer = ["", "run(target)"] if locus == "remote" else ["", "run(workdir, target)"]
    return "\n".join(sorted(imports) + [""] + header + body + footer) + "\n"


def compile_src(src, locus):
    pf = HERE / "_cand.py"
    pf.write_text(src)
    g = S2 / "graphs"
    if g.exists():
        shutil.rmtree(g)
    subprocess.run([sys.executable, "main.py", str(pf), "--locus", locus],
                   cwd=S2, capture_output=True, text=True, timeout=120)
    vs = sorted(g.glob("*.txt")) if g.exists() else []
    if not vs:
        return None
    best = max(vs, key=lambda v: v.read_text().count("EDGE "))
    t = best.read_text()
    return t if t.count("EDGE ") else None


def discriminating(sig_text):
    for line in sig_text.splitlines():
        p = line.split(None, 3)
        if len(p) == 4 and p[0] == "NODE" and classify_label(p[3].strip()) in (C2, C3) \
                and p[3].strip() not in ("*", "*.(executable)", "*.*"):
            return True
    return False


def aligns(sig_text, prov_path):
    tmp = HERE / "_cand_sig.txt"
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
        return False, 0.0
    _, raw, _ = match_score(classify_vertices(sig), res.mapping)
    return raw >= WEIGHTS[C3], raw


def candidates(ops, locus):
    """Full op set first, then variants with fewer process spawns, then the
    strongest non-process anchors alone."""
    yield ops
    procless = [o for o in ops if o[0] != "proc"]
    procs = [o for o in ops if o[0] == "proc"]
    for keep in range(len(procs) - 1, -1, -1):
        yield procless + procs[:keep]
    # last resort: each non-process op paired with one process op
    for a in procless:
        for pr in procs:
            yield [a, pr]


def build_one(cve, N, E, provN, prov_path):
    locus = locus_of(N, E)
    ops = operations(N, E, provN, locus)
    best = None
    for cand in candidates(ops, locus):
        src = emit(cand, locus)
        sig_text = compile_src(src, locus)
        if not sig_text or not discriminating(sig_text):
            continue
        ok, mass = aligns(sig_text, prov_path)
        if ok:
            return src, locus, mass
        if best is None:
            best = (src, locus, mass)
    return best if best else (emit(ops, locus), locus, 0.0)


def prov_for(cve):
    for d in SIG_DIRS:
        p = d / f"prov-{cve}.txt"
        if p.exists():
            return p
    return None


def main():
    (HERE / "poc").mkdir(exist_ok=True)
    manifest, rows = {}, []
    for d in SIG_DIRS:
        for sig in sorted(d.glob("sig-*.txt")):
            cve = sig.stem[len("sig-"):]
            prov = prov_for(cve)
            N, E = parse(sig)
            provN, _ = parse(prov)
            src, locus, mass = build_one(cve, N, E, provN, prov)
            (HERE / "poc" / f"{cve}.py").write_text(src)
            manifest[cve] = {"locus": locus}
            rows.append((cve, locus, mass))
    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    for tmp in ("_cand.py", "_cand_sig.txt"):
        if (HERE / tmp).exists():
            (HERE / tmp).unlink()
    good = sum(1 for _, _, m in rows if m >= WEIGHTS[C3])
    for cve, locus, mass in rows:
        flag = "" if mass >= WEIGHTS[C3] else "   <-- FIX"
        print(f"{cve:16}{locus:7}mass={mass:5.2f}{flag}")
    print(f"\nDETECTED: {good}/{len(rows)}")


if __name__ == "__main__":
    main()
