from __future__ import annotations

import re
from pathlib import Path
from typing import List, Sequence

import networkx as nx


_NODE_RE = re.compile(r'^\s*NODE\s+(\S+)\s+(\S+)\s+(.+?)\s*$')
_EDGE_RE = re.compile(r'^\s*EDGE\s+(\S+)\s+(\S+)\s+(\S+)\s*$')
_QUOTED_RE = re.compile(r'^\s*"(.*)"\s*$')


def _strip_inline_comment(line: str) -> str:
    in_q = False
    out_chars = []
    for ch in line:
        if ch == '"':
            in_q = not in_q
        if ch == "#" and not in_q:
            break
        out_chars.append(ch)
    return "".join(out_chars).rstrip()


def _strip_quotes(s: str) -> str:
    m = _QUOTED_RE.match(s)
    return m.group(1) if m else s.strip()


def parse_graph_txt(path: str | Path) -> nx.MultiDiGraph:
    G = nx.MultiDiGraph()
    p = Path(path)
    for line in p.read_text(encoding="utf-8").splitlines():
        line = _strip_inline_comment(line).strip()
        if not line or line.startswith("#"):
            continue
        m = _NODE_RE.match(line)
        if m:
            nid, ntype, label = m.group(1), m.group(2), _strip_quotes(m.group(3))
            G.add_node(nid, type=ntype, label=label)
            continue
        m = _EDGE_RE.match(line)
        if m:
            src, dst, syscall = m.group(1), m.group(2), m.group(3)
            if src not in G.nodes:
                G.add_node(src, type="other", label=src)
            if dst not in G.nodes:
                G.add_node(dst, type="other", label=dst)
            G.add_edge(src, dst, syscall=syscall)
            continue
        raise ValueError(f"Unrecognized line in {p}: {line}")
    return G


def expand_paths(paths: Sequence[str]) -> List[str]:
    out: List[str] = []
    for s in paths:
        p = Path(s)
        if p.is_dir():
            for child in sorted(p.rglob("*.txt")):
                out.append(str(child))
        else:
            out.append(str(p))
    if not out:
        raise ValueError("No input graph files found.")
    return out


def _wildcard_to_regex(pattern: str) -> re.Pattern:
    esc = re.escape(pattern).replace(r"\*", ".*")
    return re.compile(rf"^{esc}$")


def label_matches(sig_label: str, prov_label: str) -> bool:
    s = (sig_label or "").strip()
    p = (prov_label or "").strip()
    if "|" in s:
        parts = [seg.strip() for seg in s.split("|") if seg.strip()]
        return any(label_matches(part, p) for part in parts)
    if re.fullmatch(r"sys\.argv\[\d+\]", s):
        return True
    if s.lower() in {"url", "payload", "argv", "argument"}:
        return True
    if "(executable)" in s or s.lower().endswith(".executable") or s.lower().endswith("*.executable"):
        return True
    if "*" in s:
        return bool(_wildcard_to_regex(s).match(p))
    return s == p
