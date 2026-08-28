from __future__ import annotations

import dataclasses
import os
import re
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


# ---------------------------------------------------------------------------
# Request/response normalization
#
# read and write are two event classes, and for a filesystem edge the
# difference is real: a dropper WRITING a payload and the payload later being
# READ is a genuine ordering that a template is entitled to test.  For one
# specific kind of edge the difference is not real at all.  When a service
# handles an HTTP request, the collectors in this corpus record the whole
# transaction as a single edge between the service process and the request
# target, and they do not agree on its direction -- some record the service
# reading the request target, some record it writing the response, and some
# captures contain both directions for the same target.  Direction therefore
# carries no information on a request/response edge, so read and write collapse
# to one event class there, and only there.
#
# The scope is decided per edge from the vertices the edge touches, never from
# which template is being matched.  Evidence that an object is a web resource
# rather than a file on disk:
#
#   * its name carries a path segment that a web server executes to answer a
#     request (.aspx, .jsp, .php, ...).  Such an object is a web resource
#     wherever it happens to sit on disk, so this counts on either graph.
#   * it is an HTTP request target: a rooted path, the origin-form that a
#     request line carries.  On the template side a label is a pattern the
#     compiler wrote from the exploit's request target, so a rooted pattern is
#     a request target by construction.  On the provenance side a rooted path
#     is just as likely an ordinary POSIX file, so it counts only for a service
#     the capture shows being reached from the network -- the
#     net -> process -> resource shape.
#
# Both endpoints of the comparison must show such evidence.  A template that
# names an ordinary file, or a provenance edge that touches one, keeps read and
# write apart.
# ---------------------------------------------------------------------------

_REQUEST_CLASSES = {"read", "write"}

# Pages a web server executes to answer a request.
_WEB_HANDLER_EXT = (
    ".asp", ".aspx", ".ashx", ".asmx", ".axd",
    ".jsp", ".jspx", ".jsf", ".do", ".action",
    ".php", ".php3", ".php4", ".php5", ".php7", ".phtml",
    ".cgi", ".fcgi", ".cfm", ".cfc", ".vm",
)

# A header or metadata pseudo-object an HTTP-aware collector attaches to the
# transaction rather than to a file, e.g. ``ua::curl/7.81.0``.
_PSEUDO_OBJECT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_+.-]*::")

# The edge a capture records when a remote peer reaches a service.
_REMOTE_ACCESS = "access"


def _label_branches(label: str) -> List[str]:
    s = str(label or "")
    return [b.strip() for b in s.split("|")] if "|" in s else [s.strip()]


def _names_web_handler(branch: str) -> bool:
    """True when a path segment of the name is a server-executed page."""
    head = branch.replace("\\", "/").split("?", 1)[0]
    return any(seg.strip("*").lower().endswith(_WEB_HANDLER_EXT) for seg in head.split("/"))


def _is_request_target(branch: str) -> bool:
    """True for an HTTP request target: the rooted origin-form path.

    A leading wildcard is how a template writes "any scheme and authority", so
    it is stripped first.  A backslash means the name is a Windows or UNC
    filesystem path that merely happens to be rooted, not a request target.
    """
    s = branch.lstrip("*")
    return s.startswith("/") and "\\" not in s


def _process_and_object(G: nx.MultiDiGraph, u: str, v: str) -> Tuple[Optional[str], Optional[str]]:
    """Orient one edge into (process endpoint, object endpoint).

    Captures record a read either way round, so the endpoints are inspected in
    both orders.
    """
    for p, o in ((u, v), (v, u)):
        if G.nodes[p].get("type") == "process" and G.nodes[o].get("type") != "process":
            return p, o
    return None, None


def _reached_from_network(G: nx.MultiDiGraph, proc: str) -> bool:
    """True when the capture shows a remote peer reaching this process."""
    return any(G.nodes[a].get("type") == "net" and str(d.get("syscall", "")) == _REMOTE_ACCESS
               for a, _, d in G.in_edges(proc, data=True))


def _template_request_edge(Gsig: nx.MultiDiGraph, u: str, v: str) -> bool:
    """True when a template edge is written against a web resource."""
    proc, obj = _process_and_object(Gsig, u, v)
    if obj is None:
        return False
    return any(_is_request_target(b) or _names_web_handler(b)
               for b in _label_branches(str(Gsig.nodes[obj].get("label", ""))))


def _observed_request_edge(G: nx.MultiDiGraph, u: str, v: str) -> bool:
    """True when a provenance edge records a web resource being served."""
    proc, obj = _process_and_object(G, u, v)
    if obj is None:
        return False
    label = str(G.nodes[obj].get("label", "")).strip()
    if any(_names_web_handler(b) for b in _label_branches(label)):
        return True
    if not _reached_from_network(G, proc):
        return False
    return label.startswith("/") or _PSEUDO_OBJECT_RE.match(label) is not None


def _sc_eq(syscall_prov: str, syscall_sig: str,
           G: Optional[nx.MultiDiGraph] = None,
           u: Optional[str] = None, v: Optional[str] = None,
           template_request: bool = False) -> bool:
    """Event-class match.

    Exact, except that read and write are one class on a request/response edge
    against a web resource -- which needs the template edge to be written
    against one and the provenance edge to record one.
    """
    if syscall_prov == syscall_sig:
        return True
    if not template_request or G is None:
        return False
    if syscall_prov not in _REQUEST_CLASSES or syscall_sig not in _REQUEST_CLASSES:
        return False
    return _observed_request_edge(G, u, v)


def _iter_edges_by_syscall(G: nx.MultiDiGraph, src: str, syscall: str) -> List[Tuple[str, str, int]]:
    hits = []
    for _, v, k, data in G.out_edges(src, keys=True, data=True):
        if str(data.get("syscall", "")) == syscall:
            hits.append((src, v, k))
    return hits


# Classes that record one process creating another. A staging prefix is a
# descendancy chain, so only these may precede a terminal occurrence.
_PROCESS_CREATION = {"create", "spawn", "fork", "exec", "procstart"}

# On by default: path refinement as specified -- a simple path of at most k
# intermediate vertices whose terminal edge is of class sigma and whose every
# preceding edge is a process creation. The alternative below accepts a
# sigma-class edge anywhere along the path, with any intermediate class and
# repeated vertices, which lets a template reach an object through activity
# that has no relation to the subject it matched. Set TRACE_ALIGN_STRICT_PATH=0
# to restore it.
_STRICT_PATH = os.environ.get("TRACE_ALIGN_STRICT_PATH", "1") not in ("0", "false", "False")


def _service_endpoints(G: nx.MultiDiGraph, proc: str) -> frozenset:
    """The network endpoints a process is recorded serving on."""
    return frozenset(v for _, v, d in G.out_edges(proc, data=True)
                     if G.nodes.get(v, {}).get("type") == "net"
                     and str(d.get("syscall", "")) == "connect")


def _same_service(G: nx.MultiDiGraph, u: str, w: str) -> bool:
    """True when two process vertices are one service under two names.

    A collector may record one server under several images -- a bare host name
    and a fully qualified one, or one name per virtual host -- so a single
    service's operations arrive split across process vertices. They are the same
    service when the capture shows both serving the *same* network endpoint:
    one listening socket cannot belong to two hosts. Crossing that identity is
    not staging, so it does not consume a descendancy hop.
    """
    if u == w:
        return False
    if G.nodes.get(u, {}).get("type") != "process" or G.nodes.get(w, {}).get("type") != "process":
        return False
    shared = _service_endpoints(G, u) & _service_endpoints(G, w)
    return bool(shared)


def _strict_path(G: nx.MultiDiGraph, src: str, dst: str, syscall: str, k: int,
                 template_request: bool) -> bool:
    """The specified refinement rule.

    Each template edge takes a simple directed path of at most k intermediate
    vertices whose terminal occurrence is of class sigma, every preceding edge a
    process creation -- the prefix keeps the two matched entities' relation
    intact by allowing staging only through subject-spawned processes.

    Gapless classes have no prefix at all: an edge *into* the subject, such as
    an inbound protocol record, has no incoming descendancy to stage through,
    so its path is the terminal occurrence alone.
    """
    def terminal(u, v):
        return any(_sc_eq(str(d.get("syscall", "")), syscall, G, u, v, template_request)
                   for _, w, d in G.out_edges(u, data=True) if w == v)

    # The subject may be recorded under more than one image; an alias serving
    # the same endpoint is the same subject, not a staging hop.
    origins = [src] + [w for w in G.nodes if _same_service(G, src, w)]
    if any(terminal(o, dst) for o in origins):
        return True
    # An edge into the subject has no incoming descendancy to stage through.
    if (G.nodes.get(dst, {}).get("type") == "process"
            and G.nodes.get(src, {}).get("type") != "process"):
        return False

    # Walk descendancy chains of at most k intermediate vertices, then require
    # the terminal occurrence out of the vertex the chain reached.
    frontier = [(o, {o}) for o in origins]
    for _ in range(k):
        nxt = []
        for u, seen in frontier:
            for _, w, d in G.out_edges(u, data=True):
                if w in seen:
                    continue              # simple path: no repeated vertex
                if str(d.get("syscall", "")) not in _PROCESS_CREATION:
                    continue              # a prefix edge must be a creation
                if terminal(w, dst):
                    return True
                nxt.append((w, seen | {w}))
        if not nxt:
            return False
        frontier = nxt
    return False


def _find_k_tolerant_path(G: nx.MultiDiGraph, src: str, dst: str, syscall: str, k: int,
                          max_depth: int = 5, template_request: bool = False) -> bool:
    if src == dst:
        return True
    if _STRICT_PATH:
        return _strict_path(G, src, dst, syscall, k, template_request)
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
            seen2 = seen or _sc_eq(str(ed.get("syscall", "")), syscall, G, u, v, template_request)
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
        sig_edges.append((u, v, str(ed.get("syscall", "")), _template_request_edge(Gsig, u, v)))

    assignment: Dict[str, str] = {}
    used_prov: set[str] = set()

    def consistent_partial(sn: str, pn: str) -> bool:
        tmp_assign = dict(assignment)
        tmp_assign[sn] = pn
        for su, sv, sc, req in sig_edges:
            if su in tmp_assign and sv in tmp_assign:
                pu, pv = tmp_assign[su], tmp_assign[sv]
                ok = _find_k_tolerant_path(Gcand, pu, pv, sc, refine_spec.k,
                                           max_depth=refine_spec.max_depth,
                                           template_request=req)
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
        ms, raw, _ = match_score(kappa, mapping)
        if raises_alert(ms, spec.score) and raw >= _CONF_WEIGHT[C3]:
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
