"""Vertex confidence classification and match scoring.

Implements the scoring stage described in the paper's alignment refinement
section: template vertices are assigned a confidence category, a refined
mapping is scored by weighting matched vertices per category, and an alert is
raised only when the score reaches the alert threshold tau.

Categories follow the paper's definitions:

  C3 (high)   concrete, non-wildcard labels (repeating URLs / filepaths that a
              cross-PoC consistency check keeps).
  C2 (medium) unique but variable identifiers: labels that carry literal text
              but also a wildcard, or an alternation with a concrete branch.
  C1 (low)    labels that depend on user input or host-specific values and
              cannot be predefined: bare wildcards and argv/url/payload
              placeholders.

Scoring uses the fixed weights (w1, w2, w3) = (0.20, 0.33, 0.47) and reports
the score normalized by the template's own maximum, so it lies in [0, 1] and
is comparable across templates of different sizes.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Dict, Tuple

import networkx as nx

C1 = "C1"
C2 = "C2"
C3 = "C3"

# Fixed a priori category weights (low, medium, high confidence).
WEIGHTS: Dict[str, float] = {C1: 0.20, C2: 0.33, C3: 0.47}

# Default alert threshold.
DEFAULT_TAU = 0.43

_ARGV_RE = re.compile(r"^sys\.argv\[\d+\]$")
_PLACEHOLDERS = {"url", "payload", "argv", "argument"}


def _is_host_dependent(token: str) -> bool:
    """True when a single (non-alternation) label cannot be predefined."""
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


def classify_label(label: str) -> str:
    """Assign a confidence category to one template vertex label."""
    s = (label or "").strip()
    if not s:
        return C1

    branches = [b.strip() for b in s.split("|") if b.strip()] if "|" in s else [s]
    if not branches:
        return C1

    # A branch that is neither host-dependent nor wildcarded is fully concrete.
    concrete = [b for b in branches if not _is_host_dependent(b) and "*" not in b]
    if concrete:
        return C3

    # Otherwise, any branch carrying literal text alongside a wildcard is a
    # unique-but-variable identifier.
    partial = [b for b in branches if not _is_host_dependent(b) and "*" in b]
    if partial:
        return C2

    return C1


def classify_vertices(Gsig: nx.MultiDiGraph) -> Dict[str, str]:
    """Map every template vertex to its confidence category."""
    return {n: classify_label(str(d.get("label", ""))) for n, d in Gsig.nodes(data=True)}


def category_totals(kappa: Dict[str, str]) -> Dict[str, int]:
    totals = {C1: 0, C2: 0, C3: 0}
    for c in kappa.values():
        if c in totals:
            totals[c] += 1
    return totals


def match_score(kappa: Dict[str, str], mapping: Dict[str, str]) -> Tuple[float, float, Dict[str, int]]:
    """Score a refined mapping.

    Returns (normalized_score, raw_score, matched counts per category).
    The raw score is sum(w_i * n_i) over matched vertices; the normalized score
    divides it by the same sum over all template vertices.
    """
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
