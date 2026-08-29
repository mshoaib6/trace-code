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


def load_po_encoder(path: str | None = None):
    """Load the frozen encoder and the feature space it was fitted on.

    The encoder is trained once, offline, on synthetic order-embedding pairs
    generated from the entity types and event classes of Sigma_sigma. No
    evaluated CVE, PoC or provenance graph takes part in fitting it, and the
    feature vocabulary is frozen alongside the weights so the input space does
    not depend on the corpus a run is scoring.
    """
    import json
    from pathlib import Path
    from trace_align_features import Vocab, FeatureSpace
    from trace_align_gnn import GNNSpec, RelationalGNN

    here = Path(__file__).parent
    z = np.load(str(path) if path else str(here / "po_encoder.npz"), allow_pickle=False)
    vocab_idx = json.loads(str(z["vocab"]))
    vocab = Vocab(idx=vocab_idx)
    classes = sorted(k.split(":", 1)[1] for k in vocab_idx if k.startswith("edge:"))
    types = sorted(k.split(":", 1)[1] for k in vocab_idx if k.startswith("ntype:"))
    gnn = RelationalGNN(node_types=types, edge_types=classes,
                        spec=GNNSpec(hidden=int(z["gnn_hidden"]),
                                     hash_dim=int(z["gnn_hash"]),
                                     layers=int(z["gnn_layers"]),
                                     seed=int(z["gnn_seed"])))
    feature_space = FeatureSpace(vocab=vocab, gnn=gnn, counts_dim=vocab.size)
    encoder = POEncoder(d=int(z["d"]), F=int(z["F"]), seed=0)
    encoder.W = z["W"]
    return feature_space, encoder
