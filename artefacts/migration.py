#!/usr/bin/env python3
"""
Reference implementation of Algorithm 1 ("Valid migration strategies with
implicit dependency detection") for the PQQS'26 paper
"Cryptographic Migration with Implicit Dependencies".

The system model is loaded from assets/graphdb/setup_graph_db.cypher, which
carries the dependency class on each edge:

    explicit                 68   dependencies derivable from the CBOM (E_0)
    functional_dependency    21   implicit, service -> key material  (oracle-visible)
    shared_keys               8   implicit, cross-device shared key  (oracle-visible)
    communication_dependency  2   implicit, pinned peer key          (oracle-visible)
    secure_boot              24   implicit, chain of trust           (oracle-INvisible)
    secure_access             5   implicit, access control           (oracle-INvisible)

Semantics of an edge u -> v: "u cannot be migrated before v"
(Sec. 2.1 of the paper).  A cluster is migratable when it is a *sink* of the
condensation, i.e. it has no outgoing edge to an unmigrated node.

All iteration is over sorted collections so that runs are reproducible; the
listings currently in the paper are Python `set` dumps and are therefore not
order-stable across interpreter runs.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# Graph loading
# --------------------------------------------------------------------------

SEC_CLASSES = ("secure_boot", "secure_access")
FUNC_IMPLICIT_CLASSES = (
    "functional_dependency",
    "shared_keys",
    "communication_dependency",
)


def load_cypher(path: Path):
    """Return (nodes, edges_by_class) from the Neo4j setup script."""
    txt = path.read_text()
    names = dict(re.findall(r"CREATE \((\w+):Node \{name: .(.*?).\}\)", txt))
    containers = dict(re.findall(r"CREATE \((\w+):Container \{name: .(.*?).\}\)", txt))
    owner = {}
    for c, n in re.findall(r"CREATE \((\w+)\)-\[:contains\]->\((\w+)\)", txt):
        owner[n] = containers.get(c, c)

    by_class: dict[str, set[tuple[str, str]]] = {}
    for u, cls, v in re.findall(r"CREATE \((\w+)\)-\[:(\w+)\]->\((\w+)\)", txt):
        if cls == "contains":
            continue
        by_class.setdefault(cls, set()).add((u, v))

    labels = {n: f"{names[n]}@{owner.get(n, '?')}" for n in names}
    return sorted(names), by_class, labels


# --------------------------------------------------------------------------
# Graph utilities (Tarjan SCC + condensation), all deterministic
# --------------------------------------------------------------------------


def sccs(nodes, edges):
    """Tarjan's algorithm. Returns list of components (each a sorted tuple)."""
    adj = {n: [] for n in nodes}
    ns = set(nodes)
    for u, v in sorted(edges):
        if u in ns and v in ns:
            adj[u].append(v)

    index = {}
    low = {}
    on_stack = {}
    stack = []
    out = []
    counter = [0]

    for root in nodes:
        if root in index:
            continue
        # iterative Tarjan to stay safe on deep graphs
        work = [(root, 0)]
        while work:
            node, pi = work[-1]
            if pi == 0:
                index[node] = low[node] = counter[0]
                counter[0] += 1
                stack.append(node)
                on_stack[node] = True
            recursed = False
            for i in range(pi, len(adj[node])):
                w = adj[node][i]
                if w not in index:
                    work[-1] = (node, i + 1)
                    work.append((w, 0))
                    recursed = True
                    break
                if on_stack.get(w):
                    low[node] = min(low[node], index[w])
            if recursed:
                continue
            if low[node] == index[node]:
                comp = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    comp.append(w)
                    if w == node:
                        break
                out.append(tuple(sorted(comp)))
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
    return sorted(out)


def sink_clusters(nodes, edges):
    """Sink SCCs of the condensation: no outgoing edge leaving the component."""
    comps = sccs(nodes, edges)
    of = {n: c for c in comps for n in c}
    ns = set(nodes)
    sinks = []
    for c in comps:
        members = set(c)
        if not any(
            v in ns and v not in members
            for u, v in edges
            if u in members and v in ns
        ):
            sinks.append(c)
    return sorted(sinks), of


# --------------------------------------------------------------------------
# Oracle and test function
# --------------------------------------------------------------------------


@dataclass
class Oracle:
    """zeta: certifies Pi_func only (Def. C2).

    Returns 0 iff some functionally relevant dependency u->v has u migrated
    and v not migrated (Hypothesis 3).  Security dependencies are invisible
    to it, by construction -- this is the asymmetry the paper is about.
    """

    func_edges: set[tuple[str, str]]
    calls: int = 0
    rejections: int = 0

    def __call__(self, migrated: set[str]) -> bool:
        self.calls += 1
        for u, v in sorted(self.func_edges):
            if u in migrated and v not in migrated:
                self.rejections += 1
                return False
        return True

    def witnesses(self, migrated: set[str]):
        """Violated functional dependencies -- the evidence a CI/CD run leaves
        behind (failed smoke scenarios, logs, traces). Used by the diagnostic
        refinement, never by the verdict."""
        return sorted(
            (u, v) for u, v in self.func_edges if u in migrated and v not in migrated
        )


@dataclass
class TestFunction:
    """P: the disjunction of the partial test functions currently available.

    `active` names the dependency classes whose partial test has been
    implemented so far.  Diagnostic refinement (Sec. 5.2.2) activates a
    further class in response to an oracle rejection.
    """

    by_class: dict[str, set[tuple[str, str]]]
    active: set[str] = field(default_factory=set)
    evaluations: int = 0

    def edges(self) -> set[tuple[str, str]]:
        out: set[tuple[str, str]] = set()
        for cls in sorted(self.active):
            out |= self.by_class.get(cls, set())
        return out

    def __call__(self, u: str, v: str) -> bool:
        self.evaluations += 1
        return (u, v) in self.edges()

    def refine(self, witnesses, available_classes) -> set[str]:
        """Domain-specific analysis guided by the failed step.

        Returns the newly activated classes.  We model the realistic case:
        the engineer inspects the violated dependencies exposed by the failing
        smoke scenarios and implements the partial test function for the
        *class* those dependencies belong to (e.g. after seeing a SecOC frame
        rejected, they write the ECU-extract key-identifier comparison of
        Sec. 5.2.3).  One refinement step yields one new partial test.
        """
        for cls in available_classes:
            if cls in self.active:
                continue
            if any(w in self.by_class.get(cls, set()) for w in witnesses):
                self.active.add(cls)
                return {cls}
        return set()


# --------------------------------------------------------------------------
# Algorithm 1
# --------------------------------------------------------------------------


@dataclass
class Result:
    status: str
    sequence: list[tuple[str, ...]] = field(default_factory=list)
    oracle_calls: int = 0
    oracle_rejections: int = 0
    failed_iterations: int = 0
    refinement_rounds: list[dict] = field(default_factory=list)
    edges_final: int = 0
    edges_initial: int = 0
    p_evaluations: int = 0
    first_rejection_at: int | None = None
    proposed_steps: int = 0


def algorithm1(nodes, E0, P: TestFunction, zeta: Oracle, refine_classes,
               max_iter=10_000) -> Result:
    """Algorithm 1 of the paper, with the diagnostic refinement loop."""
    E = set(E0)
    # --- preprocessing: saturate with P (lines 1-3) ---
    E |= P.edges()
    P.evaluations += len(nodes) * (len(nodes) - 1)

    res = Result(status="running", edges_initial=len(E0))
    S: list[tuple[str, ...]] = []
    M: set[str] = set()

    it = 0
    while M != set(nodes):
        it += 1
        if it > max_iter:
            res.status = "ITERATION-LIMIT"
            break

        remaining = [n for n in nodes if n not in M]
        sinks, _ = sink_clusters(remaining, E)
        if not sinks:
            res.status = "NO-SINK"
            break
        C = sinks[0]  # deterministic choice

        res.proposed_steps += 1
        if zeta(M | set(C)):
            S.append(C)
            M |= set(C)
            continue

        # --- oracle rejected: diagnostic refinement (else branch) ---
        res.failed_iterations += 1
        if res.first_rejection_at is None:
            res.first_rejection_at = res.proposed_steps

        witnesses = zeta.witnesses(M | set(C))
        before = len(E)
        new_classes = P.refine(witnesses, refine_classes)
        E |= P.edges()
        P.evaluations += len(nodes) * (len(nodes) - 1)
        added = len(E) - before

        res.refinement_rounds.append(
            {
                "iteration": it,
                # number of clusters already accepted when the rejection happened,
                # i.e. the rejection occurs between accepted step N and N+1
                "after_accepted": len(S),
                "rejected_cluster": C,
                "witnesses": witnesses[:3],
                "n_witnesses": len(witnesses),
                "activated": sorted(new_classes),
                "edges_added": added,
                "edges_total": len(E),
            }
        )

        if added == 0:
            res.status = "Inconclusive"
            break
    else:
        res.status = "OK"

    res.sequence = S
    res.oracle_calls = zeta.calls
    res.oracle_rejections = zeta.rejections
    res.edges_final = len(E)
    res.p_evaluations = P.evaluations
    return res


# --------------------------------------------------------------------------
# Admissibility check (independent of the algorithm -- this is the referee)
# --------------------------------------------------------------------------


def check_admissible(sequence, E_bar_func, E_bar_sec):
    """Verify Def. 5.3 directly: after every prefix, no relevant dependency
    points from a migrated node to an unmigrated one."""
    migrated: set[str] = set()
    viol_func, viol_sec = [], []
    for step, C in enumerate(sequence, 1):
        migrated |= set(C)
        for u, v in sorted(E_bar_func):
            if u in migrated and v not in migrated:
                viol_func.append((step, u, v))
        for u, v in sorted(E_bar_sec):
            if u in migrated and v not in migrated:
                viol_sec.append((step, u, v))
    return viol_func, viol_sec
