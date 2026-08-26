from __future__ import annotations

import dataclasses
import math
from typing import List, Tuple

import numpy as np
import networkx as nx

from trace_align_features import FeatureSpace


class POEncoder:
    def __init__(self, d: int, F: int, seed: int = 0):
        rng = np.random.default_rng(seed)
        self.W = np.abs(rng.standard_normal((d, F))) * 0.01

    @staticmethod
    def relu(a: np.ndarray) -> np.ndarray:
        return np.maximum(0.0, a)

    def embed(self, x: np.ndarray) -> np.ndarray:
        return self.relu(self.W @ x)

    def clip_nonneg(self) -> None:
        self.W = np.maximum(0.0, self.W)


def order_violation_energy(z_sig: np.ndarray, z_prov: np.ndarray) -> float:
    diff = np.maximum(0.0, z_sig - z_prov)
    return float(diff @ diff)


def apo_score(z_sig: np.ndarray, z_prov: np.ndarray, eps: float) -> float:
    E = order_violation_energy(z_sig, z_prov)
    return max(0.0, eps - E)


@dataclasses.dataclass
class TrainSpec:
    d: int = 128
    lr: float = 0.03
    steps: int = 450
    eps: float = 1.0
    seed: int = 0
    hard_neg_prob: float = 0.65


def _grad_W_for_pair(W: np.ndarray, x_sig: np.ndarray, x_prov: np.ndarray) -> np.ndarray:
    pre_sig = W @ x_sig
    pre_prov = W @ x_prov
    z_sig = np.maximum(0.0, pre_sig)
    z_prov = np.maximum(0.0, pre_prov)

    diff = np.maximum(0.0, z_sig - z_prov)
    m_sig = (pre_sig > 0).astype(float)
    m_prov = (pre_prov > 0).astype(float)

    dE_dpre_sig = 2.0 * diff * m_sig
    dE_dpre_prov = -2.0 * diff * m_prov

    g = np.outer(dE_dpre_sig, x_sig) + np.outer(dE_dpre_prov, x_prov)
    return g


def train_po_encoder(feature_space: FeatureSpace,
                     sig_graphs: List[nx.MultiDiGraph],
                     prov_graphs: List[nx.MultiDiGraph],
                     spec: TrainSpec) -> POEncoder:

    rng = np.random.default_rng(spec.seed)
    encoder = POEncoder(d=spec.d, F=feature_space.dim, seed=spec.seed)

    pairs: List[Tuple[np.ndarray, np.ndarray, int]] = []

    def make_superset(G: nx.MultiDiGraph, noise: int = 3) -> nx.MultiDiGraph:
        H = G.copy()
        for i in range(noise):
            nid = f"noise_{rng.integers(1_000_000)}"
            H.add_node(nid, type="process", label=f"benign_{i}.exe")
            if H.number_of_nodes() >= 2:
                src = rng.choice(list(H.nodes))
                H.add_edge(src, nid, syscall=str(rng.choice(["openat", "read", "write", "connect", "sendto", "recvfrom"])))
        return H

    for Gs in sig_graphs:
        base = prov_graphs[int(rng.integers(0, len(prov_graphs)))]
        Pplus = base.copy()
        for n, d in Gs.nodes(data=True):
            if n not in Pplus:
                Pplus.add_node(n, **d)
        for u, v, k, ed in Gs.edges(keys=True, data=True):
            Pplus.add_edge(u, v, **ed)
        Pplus = make_superset(Pplus, noise=int(rng.integers(2, 6)))

        Pminus = Pplus.copy()
        if Pminus.number_of_edges() > 0 and rng.random() < 0.7:
            sig_edges = list(Gs.edges(keys=True, data=True))
            if sig_edges:
                eu, ev, ek, _ = sig_edges[int(rng.integers(0, len(sig_edges)))]
                removed = False
                for kk, ed in list(Pminus.get_edge_data(eu, ev, default={}).items()):
                    if removed:
                        break
                    Pminus.remove_edge(eu, ev, key=kk)
                    removed = True
            else:
                u, v, k = list(Pminus.edges(keys=True))[0]
                Pminus.remove_edge(u, v, key=k)
        else:
            nodes = list(Pminus.nodes)
            if nodes:
                t = rng.choice(nodes)
                Pminus.nodes[t]["label"] = "benign_swap.exe"

        x_sig = feature_space.vectorize(Gs)
        x_plus = feature_space.vectorize(Pplus)
        x_minus = feature_space.vectorize(Pminus)
        pairs.append((x_sig, x_plus, 1))
        pairs.append((x_sig, x_minus, 0))

    for _ in range(12):
        Gs = nx.MultiDiGraph()
        a = f"s_{rng.integers(1_000_000)}"
        b = f"s_{rng.integers(1_000_000)}"
        Gs.add_node(a, type="process", label="*.(executable)")
        Gs.add_node(b, type="net", label="http://*.*.*.*/x")
        Gs.add_edge(a, b, syscall="connect")

        Pplus = make_superset(Gs, noise=int(rng.integers(3, 8)))
        Pminus = make_superset(Gs, noise=int(rng.integers(3, 8)))
        for u, v, k in list(Pminus.edges(keys=True)):
            if Pminus.edges[u, v, k].get("syscall") == "connect":
                Pminus.remove_edge(u, v, key=k)
                break

        pairs.append((feature_space.vectorize(Gs), feature_space.vectorize(Pplus), 1))
        pairs.append((feature_space.vectorize(Gs), feature_space.vectorize(Pminus), 0))

    for step in range(spec.steps):
        x_sig, x_prov, y = pairs[int(rng.integers(0, len(pairs)))]
        z_sig = encoder.embed(x_sig)
        z_prov = encoder.embed(x_prov)
        E = order_violation_energy(z_sig, z_prov)

        if y == 1:
            grad = _grad_W_for_pair(encoder.W, x_sig, x_prov)
            encoder.W -= spec.lr * grad
        else:
            if E < spec.eps:
                grad = _grad_W_for_pair(encoder.W, x_sig, x_prov)
                encoder.W += spec.lr * grad

        encoder.clip_nonneg()

        if (step + 1) % 100 == 0:
            encoder.W *= 0.99

    return encoder
