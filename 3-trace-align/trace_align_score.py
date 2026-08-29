
from __future__ import annotations

import dataclasses
import re
from typing import Dict, Optional, Tuple

import networkx as nx

C1 = "C1"
C2 = "C2"
C3 = "C3"

WEIGHTS: Dict[str, float] = {C1: 0.20, C2: 0.33, C3: 0.47}

DEFAULT_TAU = 0.43

MIN_LINEAGES = 2

_LINEAGE_CACHE: Optional[Dict[str, int]] = None


def _lineage_table() -> Dict[str, int]:
    """Anchor to the number of independent PoC lineages it was observed in."""
    global _LINEAGE_CACHE
    if _LINEAGE_CACHE is None:
        import json
        from pathlib import Path
        f = Path(__file__).parent / "lineage.json"
        if f.exists():
            raw = json.loads(f.read_text(encoding="utf-8"))
            _LINEAGE_CACHE = {k: len(v) for k, v in raw.items() if not k.startswith("_")}
        else:
            _LINEAGE_CACHE = {}
    return _LINEAGE_CACHE

_ARGV_RE = re.compile(r"^sys\.argv\[\d+\]$")
_PLACEHOLDERS = {"url", "payload", "argv", "argument"}


def _is_host_dependent(token: str) -> bool:
    t = token.strip()
    if not t:
        return True
    if t == "*":
        return True
    if _ARGV_RE.match(t):
        return True
    if t.lower() in _PLACEHOLDERS:
        return True
    if "(executable)" in t or t.lower().endswith(".executable"):
        return True
    return False


def classify_label(label: str, recurrence: int = 0) -> str:
    """Assign an evidence class to one template vertex label.

    C3 is reserved for an anchor observed in at least two independent PoC
    lineages: recurrence across authors is what makes a concrete label evidence
    rather than one author's incidental choice. A concrete label seen in fewer
    than two lineages is C2, the same class as a label that carries literal text
    beside a wildcard. Labels that depend on user input or host-specific values
    are C1.

    `recurrence` is the number of distinct lineage components the anchor was
    observed in, supplied by the caller from the lineage manifest.
    """
    s = (label or "").strip()
    if not s:
        return C1

    branches = [b.strip() for b in s.split("|") if b.strip()] if "|" in s else [s]
    if not branches:
        return C1

    concrete = [b for b in branches if not _is_host_dependent(b) and "*" not in b]
    if concrete and recurrence >= MIN_LINEAGES:
        return C3

    partial = [b for b in branches if not _is_host_dependent(b) and "*" in b]
    if concrete or partial:
        return C2

    return C1


def classify_vertices(Gsig: nx.MultiDiGraph,
                      lineage: Optional[Dict[str, int]] = None) -> Dict[str, str]:
    lin = _lineage_table() if lineage is None else lineage
    out = {}
    for n, d in Gsig.nodes(data=True):
        label = str(d.get("label", ""))
        r = max((lin.get(b.strip(), 0) for b in label.split("|")), default=0)
        out[n] = classify_label(label, r)
    return out


def category_totals(kappa: Dict[str, str]) -> Dict[str, int]:
    totals = {C1: 0, C2: 0, C3: 0}
    for c in kappa.values():
        if c in totals:
            totals[c] += 1
    return totals


def match_score(kappa: Dict[str, str], mapping: Dict[str, str]) -> Tuple[float, float, Dict[str, int]]:
    matched = {C1: 0, C2: 0, C3: 0}
    for n in mapping:
        c = kappa.get(n)
        if c in matched:
            matched[c] += 1

    raw = sum(WEIGHTS[c] * matched[c] for c in matched)
    totals = category_totals(kappa)
    denom = sum(WEIGHTS[c] * totals[c] for c in totals)
    norm = (raw / denom) if denom > 0 else 0.0
    return norm, raw, matched


@dataclasses.dataclass
class ScoreSpec:
    tau: float = DEFAULT_TAU


def raises_alert(score: float, spec: ScoreSpec) -> bool:
    return score >= spec.tau
