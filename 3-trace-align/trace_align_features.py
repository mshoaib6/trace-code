from __future__ import annotations

import dataclasses
from typing import Dict, Iterable

import numpy as np
import networkx as nx

from trace_align_gnn import RelationalGNN


@dataclasses.dataclass
class Vocab:
    idx: Dict[str, int]

    @property
    def size(self) -> int:
        return len(self.idx)


def build_count_vocab(graphs: Iterable[nx.MultiDiGraph]) -> Vocab:
    idx: Dict[str, int] = {}
    def add(tok: str):
        if tok not in idx:
            idx[tok] = len(idx)

    for G in graphs:
        for _, data in G.nodes(data=True):
            add(f"ntype:{data.get('type','other')}")
        for _, _, data in G.edges(data=True):
            add(f"edge:{data.get('syscall','other')}")
    add("ntype:other")
    add("edge:other")
    return Vocab(idx=idx)


@dataclasses.dataclass
class FeatureSpace:
    vocab: Vocab
    gnn: RelationalGNN
    counts_dim: int

    @property
    def dim(self) -> int:
        return self.counts_dim + self.gnn.spec.hidden

    def vectorize(self, G: nx.MultiDiGraph) -> np.ndarray:
        x_counts = np.zeros(self.counts_dim, dtype=float)
        for _, data in G.nodes(data=True):
            t = data.get("type", "other")
            key = f"ntype:{t}"
            if key in self.vocab.idx:
                x_counts[self.vocab.idx[key]] += 1.0
            else:
                x_counts[self.vocab.idx["ntype:other"]] += 1.0

        for _, _, data in G.edges(data=True):
            e = str(data.get("syscall", "other"))
            key = f"edge:{e}"
            if key in self.vocab.idx:
                x_counts[self.vocab.idx[key]] += 1.0
            else:
                x_counts[self.vocab.idx["edge:other"]] += 1.0

        x_gnn = self.gnn.graph_pool(G)
        return np.concatenate([x_counts, x_gnn], axis=0)
