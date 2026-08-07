#!/usr/bin/env python3
"""
A separate experiment: what happens if the oracle is instrumented for security?

Configurations A-E in run_experiments.py hold the oracle fixed and vary P0.
This varies the oracle instead, so it is not one of the lettered
configurations and does not appear in results.json.

Sec. 5.6 argues that zeta, being confined to Pi_func, gives no feedback on
Pi_sec, so correctness with respect to security reduces to the completeness of
P on Ebar_sec.  That is a property of the oracle we assume, not of
execution-based validation as such.  A digital twin that exercises the security
mechanisms themselves -- boot a tampered image and confirm rejection, attempt an
unauthorized write to a key slot and confirm refusal -- observes violations of
Pi_sec directly.

Crucially such probes do NOT consult Ebar_sec.  They exercise a mechanism and
observe the outcome, exactly as the functional oracle observes breakage without
consulting Ebar_func.  The dependency structure is implicit in the mechanism.

This script measures what that buys: starting from P0 = {} (no dependency
knowledge at all), does Algorithm 1 still reach an admissible plan?

    python3 security_aware_oracle.py

Idealization, stated plainly: the probes here decide their verdict from the
ground-truth edge list, so this models a security oracle with *perfect*
coverage.  Real probes have gaps, and (C1a) is then replaced by a coverage
condition on the twin rather than removed.  This is the same idealization the
paper already makes for the functional oracle.
"""

from __future__ import annotations

from pathlib import Path

from migration import (
    FUNC_IMPLICIT_CLASSES,
    SEC_CLASSES,
    Oracle,
    TestFunction,
    algorithm1,
    check_admissible,
    load_cypher,
)

HERE = Path(__file__).resolve().parent
GRAPH = HERE.parent / "assets" / "graphdb" / "setup_graph_db.cypher"


class SecurityAwareOracle(Oracle):
    """zeta extended with property-level security probes."""

    def __init__(self, func_edges, sec_edges):
        super().__init__(func_edges=set(func_edges))
        self.sec_edges = set(sec_edges)
        self.sec_rejections = 0

    def __call__(self, migrated: set[str]) -> bool:
        if not super().__call__(migrated):
            return False                      # functional failure, already counted
        for u, v in sorted(self.sec_edges):   # security probe
            if u in migrated and v not in migrated:
                self.sec_rejections += 1
                self.rejections += 1
                return False
        return True

    def witnesses(self, migrated):
        w = super().witnesses(migrated)
        w += [(u, v) for u, v in sorted(self.sec_edges)
              if u in migrated and v not in migrated]
        return w


class Learner(TestFunction):
    """P that is repaired from whatever the oracle witnesses."""

    def __init__(self, have, truth):
        self.by_class = {}
        self.active = set()
        self._e = set(have)
        self._truth = set(truth)
        self.evaluations = 0

    def edges(self):
        return set(self._e)

    def refine(self, witnesses, available):
        new = {w for w in witnesses if w in self._truth} - self._e
        self._e |= new
        return {"recovered"} if new else set()


def main() -> None:
    nodes, by_class, labels = load_cypher(GRAPH)
    E0 = by_class["explicit"]
    FUNC = set().union(*(by_class[c] for c in FUNC_IMPLICIT_CLASSES))
    SEC = set().union(*(by_class[c] for c in SEC_CLASSES))
    truth = E0 | FUNC | SEC

    print(f"|V| = {len(nodes)}   |E_0| = {len(E0)}   "
          f"|Ebar_func \\ E_0| = {len(FUNC)}   |Ebar_sec| = {len(SEC)}\n")

    header = (f"{'oracle':<26} {'P0':<18} {'status':<7} {'clusters':>8} "
              f"{'calls':>6} {'rej':>5} {'sec-rej':>8} {'SEC viol':>9}")
    print(header)
    print("-" * len(header))

    scenarios = [
        ("functional only",  "all implicit",  Oracle(func_edges=set(E0 | FUNC)), FUNC | SEC),
        ("functional only",  "functional",    Oracle(func_edges=set(E0 | FUNC)), FUNC),
        ("functional only",  "empty",         Oracle(func_edges=set(E0 | FUNC)), set()),
        ("+ security probes", "functional",   SecurityAwareOracle(E0 | FUNC, SEC), FUNC),
        ("+ security probes", "empty",        SecurityAwareOracle(E0 | FUNC, SEC), set()),
    ]
    for oname, pname, z, start in scenarios:
        r = algorithm1(nodes, E0, Learner(start, truth), z, ("recovered",))
        _, vs = check_admissible(r.sequence, E0 | FUNC, SEC)
        secrej = getattr(z, "sec_rejections", 0)
        print(f"{oname:<26} {pname:<18} {r.status:<7} {len(r.sequence):>8} "
              f"{z.calls:>6} {z.rejections:>5} {secrej:>8} "
              f"{len({(u, v) for _, u, v in vs}):>9}")

    print("\nReading: with a functional-only oracle, security violations track the\n"
          "incompleteness of P on Ebar_sec and are never signalled. With security\n"
          "probes, P0 can be empty and the algorithm still converges to an\n"
          "admissible plan -- at the cost of additional oracle invocations.")


if __name__ == "__main__":
    main()
