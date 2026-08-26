from __future__ import annotations

import dataclasses
import math
import re
from typing import Dict, List

import numpy as np
import networkx as nx


@dataclasses.dataclass
class GNNSpec:
    hidden: int = 32
    hash_dim: int = 8
    layers: int = 1
    seed: int = 7


class RelationalGNN:
    def __init__(self, node_types: List[str], edge_types: List[str], spec: GNNSpec):
        self.node_types = list(node_types)
        self.edge_types = list(edge_types)
        self.ntype2i = {t: i for i, t in enumerate(self.node_types)}
        self.etype2i = {e: i for i, e in enumerate(self.edge_types)}
        self.spec = spec

        self.F0 = len(self.node_types) + spec.hash_dim + 2

        rng = np.random.default_rng(spec.seed)
        self.W_self_0 = np.abs(rng.standard_normal((spec.hidden, self.F0))) / math.sqrt(self.F0)
        self.W_rel_0 = {
            e: np.abs(rng.standard_normal((spec.hidden, self.F0))) / math.sqrt(self.F0)
            for e in self.edge_types
        }

        self.W_self = []
        self.W_rel = []
        for _ in range(max(0, spec.layers - 1)):
            self.W_self.append(np.abs(rng.standard_normal((spec.hidden, spec.hidden))) / math.sqrt(spec.hidden))
            self.W_rel.append({
                e: np.abs(rng.standard_normal((spec.hidden, spec.hidden))) / math.sqrt(spec.hidden)
                for e in self.edge_types
            })

    def _hash_label(self, label: str) -> np.ndarray:
        """Bag-of-tokens hash of a vertex label.

        Labels are split into tokens and each token is hashed into a fixed
        number of buckets. Tokens that cannot be predefined (wildcards,
        argv/url/payload placeholders) contribute nothing, and a label offering
        alternatives requires none of them, so a template label never demands a
        feature its matching provenance label lacks. This keeps the embedding
        monotone under containment, which the partial-order screen relies on.
        """
        v = np.zeros(self.spec.hash_dim, dtype=float)
        s = (label or "").strip()
        if not s:
            return v
        # A disjunction constrains nothing on its own.
        if "|" in s:
            return v
        low = s.lower()
        if s == "*" or low in {"url", "payload", "argv", "argument"}:
            return v
        if "(executable)" in s or low.endswith(".executable"):
            return v
        if re.match(r"^sys\.argv\[\d+\]$", s):
            return v

        for tok in re.split(r"[^A-Za-z0-9]+", s):
            if not tok or "*" in tok:
                continue
            h = 0
            for i, ch in enumerate(tok.lower()):
                h = (h * 1315423911 + ord(ch) * 2654435761 + i) % 1000003
            v[h % self.spec.hash_dim] += 1.0
        return v

    def _node_feature(self, G: nx.MultiDiGraph, nid: str) -> np.ndarray:
        data = G.nodes[nid]
        ntype = data.get("type", "other")
        label = str(data.get("label", ""))

        x = np.zeros(self.F0, dtype=float)
        if ntype not in self.ntype2i:
            if "other" in self.ntype2i:
                x[self.ntype2i["other"]] = 1.0
        else:
            x[self.ntype2i[ntype]] = 1.0

        off = len(self.node_types)
        x[off:off + self.spec.hash_dim] = self._hash_label(label)

        in_deg = G.in_degree(nid)
        out_deg = G.out_degree(nid)
        x[-2] = math.log1p(in_deg)
        x[-1] = math.log1p(out_deg)
        return x

    @staticmethod
    def _relu(a: np.ndarray) -> np.ndarray:
        return np.maximum(0.0, a)

    def graph_pool(self, G: nx.MultiDiGraph) -> np.ndarray:
        if G.number_of_nodes() == 0:
            return np.zeros(self.spec.hidden, dtype=float)

        X: Dict[str, np.ndarray] = {nid: self._node_feature(G, nid) for nid in G.nodes}

        H0: Dict[str, np.ndarray] = {}
        for v in G.nodes:
            msg = self.W_self_0 @ X[v]
            for u, _, edata in G.in_edges(v, data=True):
                rel = str(edata.get("syscall", "other"))
                W = self.W_rel_0.get(rel, self.W_rel_0.get("other"))
                if W is None:
                    continue
                msg = msg + (W @ X[u])
            H0[v] = self._relu(msg)

        H_prev = H0

        for li in range(len(self.W_self)):
            H_next: Dict[str, np.ndarray] = {}
            for v in G.nodes:
                msg = self.W_self[li] @ H_prev[v]
                for u, _, edata in G.in_edges(v, data=True):
                    rel = str(edata.get("syscall", "other"))
                    W = self.W_rel[li].get(rel, self.W_rel[li].get("other"))
                    if W is None:
                        continue
                    msg = msg + (W @ H_prev[u])
                H_next[v] = self._relu(msg)
            H_prev = H_next

        pooled = np.zeros(self.spec.hidden, dtype=float)
        for v in G.nodes:
            pooled += H_prev[v]
        return pooled
