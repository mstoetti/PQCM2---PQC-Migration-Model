#!/usr/bin/env python3
"""
Experiment driver for "Cryptographic Migration with Implicit Dependencies".

Four configurations over the same 62-node automotive system:

  A  full knowledge      P detects all five implicit classes      (paper's Strategy A)
  B  CBOM only           P == 0                                   (paper's Strategy B)
  C  security-complete   P detects the two SECURITY classes only; the three
                         oracle-visible implicit classes are missing and must
                         be recovered by the diagnostic refinement loop
                                                                  (NEW: exercises Algorithm 1)
  D  (C1) violated       P detects everything EXCEPT secure_access; the oracle
                         cannot see the gap, so the algorithm terminates
                         "successfully" with a silently insecure plan
                                                                  (NEW: failure mode)
  E  functional only     P detects only the FUNCTIONAL implicit classes -- the
                         "get it working first, review security later" workflow
                                                                  (NEW: failure mode)

Run:  python3 run_experiments.py [path/to/setup_graph_db.cypher]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from migration import (
    FUNC_IMPLICIT_CLASSES,
    SEC_CLASSES,
    Oracle,
    Result,
    TestFunction,
    algorithm1,
    check_admissible,
    load_cypher,
    sccs,
)

HERE = Path(__file__).resolve().parent
DEFAULT_GRAPH = HERE.parent / "cypher" / "setup_graph_db.cypher"

ALL_IMPLICIT = tuple(SEC_CLASSES) + tuple(FUNC_IMPLICIT_CLASSES)

# Order in which an engineer would plausibly implement further partial tests
# once a failing smoke scenario points at them (Sec. 5.2.3).
REFINE_ORDER = ("shared_keys", "communication_dependency", "functional_dependency")


def build(graph_path: Path):
    nodes, by_class, labels = load_cypher(graph_path)
    E0 = by_class["explicit"]
    E_sec = set().union(*(by_class.get(c, set()) for c in SEC_CLASSES))
    E_func_implicit = set().union(
        *(by_class.get(c, set()) for c in FUNC_IMPLICIT_CLASSES)
    )
    E_bar_func = E0 | E_func_implicit          # oracle-visible ground truth
    E_bar_sec = E_sec                          # oracle-INvisible ground truth
    return nodes, by_class, labels, E0, E_bar_func, E_bar_sec


def run(name, nodes, by_class, E0, E_bar_func, E_bar_sec,
        active_classes, refine_classes):
    P = TestFunction(by_class=by_class, active=set(active_classes))
    zeta = Oracle(func_edges=set(E_bar_func))
    res = algorithm1(nodes, E0, P, zeta, refine_classes)
    vf, vs = check_admissible(res.sequence, E_bar_func, E_bar_sec)
    return {
        "config": name,
        "result": res,
        "violations_func": vf,
        "violations_sec": vs,
        "P_final_classes": sorted(P.active),
    }


def summarize(r, labels):
    res: Result = r["result"]
    seq = res.sequence
    multi = [c for c in seq if len(c) > 1]
    print(f"\n{'='*74}\nCONFIG {r['config']}\n{'='*74}")
    print(f"  status                      : {res.status}")
    print(f"  |E| initial (explicit)      : {res.edges_initial}")
    print(f"  |E| after saturation+refine : {res.edges_final}")
    print(f"    -> edges recovered        : {res.edges_final - res.edges_initial}")
    print(f"  proposed steps              : {res.proposed_steps}")
    print(f"  accepted steps (clusters)   : {len(seq)}")
    print(f"  clusters with |C| > 1       : {len(multi)}")
    print(f"  largest cluster             : {max((len(c) for c in seq), default=0)}")
    print(f"  oracle invocations          : {res.oracle_calls}")
    print(f"    -> of which rejected      : {res.oracle_rejections}")
    print(f"  failed iterations           : {res.failed_iterations}")
    print(f"  first rejection at step     : {res.first_rejection_at}")
    print(f"  refinement rounds           : {len(res.refinement_rounds)}")
    for rr in res.refinement_rounds:
        w = ", ".join(f"{labels[u]}->{labels[v]}" for u, v in rr["witnesses"])
        print(
            f"     round {len(rr['activated']) and rr['iteration']:>4}: "
            f"rejected {[labels[x] for x in rr['rejected_cluster']]}, "
            f"{rr['n_witnesses']} witness(es) [{w}...], "
            f"activated {rr['activated']}, +{rr['edges_added']} edges "
            f"(total {rr['edges_total']})"
        )
    print(f"  P final classes             : {r['P_final_classes']}")
    print(f"  ADMISSIBILITY CHECK (independent):")
    print(f"    functional violations     : {len(r['violations_func'])}")
    print(f"    SECURITY violations       : {len(r['violations_sec'])}", end="")
    if r["violations_sec"]:
        first = r["violations_sec"][0]
        print(f"   <-- e.g. step {first[0]}: {labels[first[1]]} -> {labels[first[2]]}")
    else:
        print()
    return res


def main():
    graph_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_GRAPH
    nodes, by_class, labels, E0, E_bar_func, E_bar_sec = build(graph_path)

    print(f"System model: {graph_path}")
    print(f"  |V| = {len(nodes)}")
    for c in ("explicit",) + ALL_IMPLICIT:
        print(f"  {c:26s} {len(by_class.get(c, set())):3d}")
    print(f"  Ebar_func (oracle-visible)  {len(E_bar_func):3d}")
    print(f"  Ebar_sec  (oracle-blind)    {len(E_bar_sec):3d}")

    runs = [
        run("A  full knowledge", nodes, by_class, E0, E_bar_func, E_bar_sec,
            active_classes=ALL_IMPLICIT, refine_classes=()),
        run("B  CBOM only", nodes, by_class, E0, E_bar_func, E_bar_sec,
            active_classes=(), refine_classes=()),
        run("C  security-complete, functional incomplete", nodes, by_class, E0,
            E_bar_func, E_bar_sec,
            active_classes=SEC_CLASSES, refine_classes=REFINE_ORDER),
        run("D  (C1) violated: secure_access missing", nodes, by_class, E0,
            E_bar_func, E_bar_sec,
            active_classes=("secure_boot",) + FUNC_IMPLICIT_CLASSES,
            refine_classes=REFINE_ORDER),
        run("E  functional knowledge only", nodes, by_class, E0,
            E_bar_func, E_bar_sec,
            active_classes=FUNC_IMPLICIT_CLASSES, refine_classes=REFINE_ORDER),
    ]

    results = {}
    for r in runs:
        res = summarize(r, labels)
        results[r["config"]] = {
            "status": res.status,
            "clusters": len(res.sequence),
            "multi": len([c for c in res.sequence if len(c) > 1]),
            "largest": max((len(c) for c in res.sequence), default=0),
            "oracle_calls": res.oracle_calls,
            "oracle_rejections": res.oracle_rejections,
            "failed_iterations": res.failed_iterations,
            "first_rejection_at": res.first_rejection_at,
            "proposed_steps": res.proposed_steps,
            "edges_initial": res.edges_initial,
            "edges_final": res.edges_final,
            # a round that recovers no edge terminates with Inconclusive and is not a
# refinement; Tab. 1 counts only rounds that added at least one edge
            "refinement_rounds": sum(1 for r in res.refinement_rounds if r["edges_added"]),
            "refinement_attempts": len(res.refinement_rounds),
            "sec_violations": len(r["violations_sec"]),
            "func_violations": len(r["violations_func"]),
            "sequence": [[labels[n] for n in c] for c in res.sequence],
        }

    # Does the recovered plan (C) equal the full-knowledge plan (A)?
    a = [tuple(sorted(c)) for c in runs[0]["result"].sequence]
    c = [tuple(sorted(c)) for c in runs[2]["result"].sequence]
    print(f"\n{'='*74}")
    print(f"Plan A == Plan C (set of clusters) : {set(a) == set(c)}")
    print(f"Plan A == Plan C (exact order)     : {a == c}")
    print(f"{'='*74}")

    out = HERE / "results.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
