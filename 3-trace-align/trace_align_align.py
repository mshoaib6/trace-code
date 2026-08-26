from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional, Tuple

import networkx as nx

from trace_align_io import label_matches
from trace_align_features import FeatureSpace
from trace_align_po import POEncoder, order_violation_energy, apo_score
from trace_align_score import (
    C1,
    C3,
    WEIGHTS as _CONF_WEIGHT,
    ScoreSpec,
    classify_vertices,
    match_score,
    raises_alert,
)


def process_centric_subgraphs(Gprov: nx.MultiDiGraph, radius: int = 2) -> Dict[str, nx.MultiDiGraph]:
    out: Dict[str, nx.MultiDiGraph] = {}
    if radius < 0:
        radius = 0

    for nid, data in Gprov.nodes(data=True):
        if data.get("type") != "process":
            continue

        frontier = {nid}
        seen = {nid}
        for _ in range(radius):
            nxt = set()
            for x in frontier:
                nxt.update(u for u, _ in Gprov.in_edges(x))
                nxt.update(v for _, v in Gprov.out_edges(x))
            nxt -= seen
            seen |= nxt
            frontier = nxt
            if not frontier:
                break

        H = Gprov.subgraph(seen).copy()
        out[nid] = H
    return out


@dataclasses.dataclass
class RefineSpec:
    k: int = 3
    max_depth: int = 5


def _node_compat(sig_node: str, prov_node: str, Gsig: nx.MultiDiGraph, Gprov: nx.MultiDiGraph) -> bool:
    sd = Gsig.nodes[sig_node]
    pd = Gprov.nodes[prov_node]
    if sd.get("type") != pd.get("type"):
        return False
    return label_matches(str(sd.get("label", "")), str(pd.get("label", "")))


def _edge_compat(syscall_sig: str, syscall_prov: str) -> bool:
    return syscall_sig == syscall_prov


def _iter_edges_by_syscall(G: nx.MultiDiGraph, src: str, syscall: str) -> List[Tuple[str, str, int]]:
    hits = []
    for _, v, k, data in G.out_edges(src, keys=True, data=True):
        if str(data.get("syscall", "")) == syscall:
            hits.append((src, v, k))
    return hits


def _find_k_tolerant_path(G: nx.MultiDiGraph, src: str, dst: str, syscall: str, k: int,
                          max_depth: int = 5) -> bool:
    if src == dst:
        return True
    # A template edge may span at most k intermediate vertices, and no search
    # runs deeper than the refinement depth bound d_max.
    max_len = min(k + 1, max_depth)
    from collections import deque
    q = deque([(src, 0, False)])
    visited = {(src, 0, False)}
    while q:
        u, depth, seen = q.popleft()
        if depth >= max_len:
            continue
        for _, v, _, ed in G.out_edges(u, keys=True, data=True):
            seen2 = seen or (str(ed.get("syscall", "")) == syscall)
            state = (v, depth + 1, seen2)
            if state in visited:
                continue
            if v == dst and seen2:
                return True
            visited.add(state)
            q.append(state)
    return False


def refine_alignment(Gsig: nx.MultiDiGraph,
                     Gcand: nx.MultiDiGraph,
                     refine_spec: RefineSpec,
                     verbose: bool = False,
                     kappa: Optional[Dict[str, str]] = None) -> Tuple[bool, Dict[str, str]]:
    kappa = kappa or classify_vertices(Gsig)
    sig_nodes = list(Gsig.nodes)
    prov_nodes = list(Gcand.nodes)

    cand_map: Dict[str, List[str]] = {}
    for sn in sig_nodes:
        cand_map[sn] = [pn for pn in prov_nodes if _node_compat(sn, pn, Gsig, Gcand)]

    sig_nodes.sort(key=lambda n: len(cand_map[n]))

    sig_edges = []
    for u, v, _, ed in Gsig.edges(keys=True, data=True):
        sig_edges.append((u, v, str(ed.get("syscall", ""))))

    assignment: Dict[str, str] = {}
    used_prov: set[str] = set()

    def consistent_partial(sn: str, pn: str) -> bool:
        tmp_assign = dict(assignment)
        tmp_assign[sn] = pn
        for su, sv, sc in sig_edges:
            if su in tmp_assign and sv in tmp_assign:
                pu, pv = tmp_assign[su], tmp_assign[sv]
                ok = _find_k_tolerant_path(Gcand, pu, pv, sc, refine_spec.k,
                                           max_depth=refine_spec.max_depth)
                if not ok:
                    return False
        return True

    # Every template vertex must find a counterpart: refinement is seeded from
    # the high-confidence vertices and expands until the whole template is
    # mapped, so a template vertex with no consistent counterpart means the
    # candidate subgraph does not contain the template.
    if any(not cand_map[sn] for sn in sig_nodes):
        if verbose:
            print("  [refine] a template vertex has no compatible counterpart")
        return False, {}

    def backtrack(i: int) -> bool:
        if i >= len(sig_nodes):
            return True
        sn = sig_nodes[i]
        for pn in cand_map[sn]:
            if pn in used_prov:
                continue
            if not consistent_partial(sn, pn):
                continue
            assignment[sn] = pn
            used_prov.add(pn)
            if backtrack(i + 1):
                return True
            used_prov.remove(pn)
            assignment.pop(sn, None)
        return False

    ok = backtrack(0)
    return ok, assignment if ok else {}


@dataclasses.dataclass
class AlignSpec:
    po_eps: float = 1.0
    po_theta: float = 0.0
    radius: int = 3
    refine: RefineSpec = dataclasses.field(default_factory=RefineSpec)
    score: ScoreSpec = dataclasses.field(default_factory=ScoreSpec)


@dataclasses.dataclass
class AlignResult:
    found: bool
    anchor_proc: Optional[str]
    mapping: Dict[str, str]


def align_one(Gsig: nx.MultiDiGraph,
              Gprov: nx.MultiDiGraph,
              feature_space: FeatureSpace,
              encoder: POEncoder,
              spec: AlignSpec,
              verbose: bool = False) -> AlignResult:
    z_sig = encoder.embed(feature_space.vectorize(Gsig))
    kappa = classify_vertices(Gsig)

    proc_subs = process_centric_subgraphs(Gprov, radius=spec.radius)
    candidates: List[Tuple[str, float, float]] = []
    for proc, H in proc_subs.items():
        z_p = encoder.embed(feature_space.vectorize(H))
        E = order_violation_energy(z_sig, z_p)
        s = apo_score(z_sig, z_p, eps=spec.po_eps)
        # Screen admits a candidate when the order-violation energy is within
        # the margin; the score then ranks the survivors.
        if E <= spec.po_eps and s >= spec.po_theta:
            candidates.append((proc, s, E))

    candidates.sort(key=lambda t: (-t[1], t[2]))

    if verbose:
        print(f"[stage1] candidates passing PO screen: {len(candidates)}/{len(proc_subs)}")

    # The confidence-weighted match score gates the alert; it is used here and
    # never surfaced, since only the alert decision is meaningful downstream.
    for proc, s, E in candidates:
        ok, mapping = refine_alignment(Gsig, proc_subs[proc], spec.refine, verbose=verbose, kappa=kappa)
        if not ok:
            continue
        ms, _, _ = match_score(kappa, mapping)
        if raises_alert(ms, spec.score):
            return AlignResult(True, proc, mapping)

    return AlignResult(False, None, {})


def _required_sig_elements(Gsig: nx.MultiDiGraph) -> Tuple[set[str], set[str]]:
    labels = set(str(d.get("label", "")) for _, d in Gsig.nodes(data=True))
    syscalls = set(str(d.get("syscall", "")) for _, _, d in Gsig.edges(data=True))
    return labels, syscalls


def validation_suite(Gsig: nx.MultiDiGraph,
                     Gprov: nx.MultiDiGraph,
                     feature_space: FeatureSpace,
                     encoder: POEncoder,
                     spec: AlignSpec) -> None:
    print("\n=== Validation: PO-GNN + Partial-Order Screen + Refinement ===")
    print(f"Feature vector: counts_dim={feature_space.counts_dim}, gnn_hidden={feature_space.gnn.spec.hidden}, total_dim={feature_space.dim}")
    print(f"PO encoder: z_dim={encoder.W.shape[0]}, PO eps={spec.po_eps}, PO theta={spec.po_theta}")
    print(f"GNN: layers={feature_space.gnn.spec.layers}, hash_dim={feature_space.gnn.spec.hash_dim}, seed={feature_space.gnn.spec.seed}")
    print(f"Refinement: k={spec.refine.k}, max_depth={spec.refine.max_depth} (depth bound is enforced via k-tolerant BFS)")

    pos = align_one(Gsig, Gprov, feature_space, encoder, spec, verbose=False)
    print(f"\n[POS] Expected True.  Found? {pos.found}")
    if pos.found:
        print(f"     Anchor process subgraph: {pos.anchor_proc}")
        print("     Vertex mapping (sig -> prov):")
        for k in sorted(pos.mapping.keys()):
            print(f"       {k:>10} -> {pos.mapping[k]}")
    else:
        print("     (If this fails, lower --po_theta or increase --po_eps; refinement is the final arbiter.)")

    z_sig = encoder.embed(feature_space.vectorize(Gsig))
    proc_subs = process_centric_subgraphs(Gprov, radius=spec.radius)
    energies = []
    for proc, H in proc_subs.items():
        z_p = encoder.embed(feature_space.vectorize(H))
        E = order_violation_energy(z_sig, z_p)
        energies.append((E, proc))
    energies.sort()
    _, req_syscalls = _required_sig_elements(Gsig)
    req_syscalls = sorted(req_syscalls)
    print("\n[NEG-A] Remove ALL occurrences of each required syscall (should become False):")
    for sc in req_syscalls:
        Gneg = Gprov.copy()
        to_remove = [(u, v, k) for u, v, k, d in Gneg.edges(keys=True, data=True)
                     if str(d.get("syscall", "")) == sc]
        if not to_remove:
            print(f"  - syscall={sc}: (no such edge present; skipping)")
            continue
        for u, v, k in to_remove:
            if Gneg.has_edge(u, v, key=k):
                Gneg.remove_edge(u, v, key=k)

        neg = align_one(Gsig, Gneg, feature_space, encoder, spec, verbose=False)

        proc_subs2 = process_centric_subgraphs(Gneg, radius=spec.radius)
        bestE = float("inf")
        for _, H in proc_subs2.items():
            z_p = encoder.embed(feature_space.vectorize(H))
            bestE = min(bestE, order_violation_energy(z_sig, z_p))

        print(f"  - remove syscall {sc:>8}: Alignment found? {neg.found} | best PO E={bestE:.4f}")

    print("\n[VAL SUMMARY]")
    print("  - POS should be True (signature contained in provenance + noise).")
    print("  - NEG-A should be False for each removed required syscall edge.")
    print("  - The best PO energy reported in NEG-A should increase when required behaviors are missing.")
    print("  - Final correctness is enforced by refinement (injective mapping + k-tolerant syscall-constrained paths).")
