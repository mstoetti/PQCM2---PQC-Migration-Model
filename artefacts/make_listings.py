#!/usr/bin/env python3
"""
Generate the migration-strategy listings included by sections/baseline.tex.

Emits, in the paper's own naming convention (K_1, K_pr2, AES128 CMAC (ECU), ...)
rather than raw Python identifiers, and in a deterministic order:

    example.txt    configuration A -- CBOM + implicit + test function
    example_2.txt  configuration B -- CBOM only
    example_3.txt  configuration C -- security-complete, functional incomplete

Run:  python3 make_listings.py
"""

from __future__ import annotations

import re
from pathlib import Path

from migration import (
    FUNC_IMPLICIT_CLASSES,
    SEC_CLASSES,
    Oracle,
    TestFunction,
    algorithm1,
    load_cypher,
)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
GRAPH = ROOT / "cypher" / "setup_graph_db.cypher"
REFINE_ORDER = ("shared_keys", "communication_dependency", "functional_dependency")

CONTAINER = {"ECU": "ECU", "TCU": "TCU", "Server": "Srv"}


def pretty(label: str) -> str:
    """'K_pb_2@ECU' -> 'K_pb2 (ECU)';  'AES128 CMAC@ECU' -> 'AES128 CMAC (ECU)'."""
    name, _, owner = label.partition("@")
    name = re.sub(r"^K_(pb|pr)_(\d+)$", r"K_\1\2", name)
    name = name.replace("RAS2048", "RSA2048")          # typo in the source model
    return f"{name} ({CONTAINER.get(owner, owner)})"


def why_joint(cluster, by_class):
    """Explain a multi-node cluster by the dependency class that induced it."""
    members = set(cluster)
    reasons = []
    for cls, text in (
        ("secure_boot", "secure boot"),
        ("secure_access", "secure access"),
        ("shared_keys", "shared key"),
        ("communication_dependency", "pinned peer key"),
    ):
        if any(u in members and v in members for u, v in by_class.get(cls, ())):
            reasons.append(text)
    return " / ".join(reasons)


def wrap(text, width=58):
    import textwrap
    return "\n".join(
        line
        for para in text.split("\n")
        for line in (textwrap.wrap(para, width) or [""])
    )


def render(title, headline, res, labels, by_class, notes=None, tail=None):
    out = [wrap(title), "=" * min(len(title), 58), "", wrap(headline), ""]
    for i, C in enumerate(res.sequence, 1):
        names = ", ".join(pretty(labels[n]) for n in C)
        line = f"{i:3d}  {{ {names} }}"
        out.append(line)
        if len(C) > 1:
            out.append(f"       ^ joint cluster: {why_joint(C, by_class)}")
        for n_at, txt in (notes or {}).items():
            if n_at == i:
                out += [f"     {ln}" for ln in txt.split("\n")]
    if tail:
        out += ["", *tail]
    return "\n".join(out) + "\n"


def main():
    nodes, by_class, labels = load_cypher(GRAPH)
    E0 = by_class["explicit"]
    Ebar_func = E0 | set().union(*(by_class[c] for c in FUNC_IMPLICIT_CLASSES))
    all_implicit = tuple(SEC_CLASSES) + tuple(FUNC_IMPLICIT_CLASSES)

    # ---- A: full knowledge -------------------------------------------------
    P = TestFunction(by_class=by_class, active=set(all_implicit))
    z = Oracle(func_edges=set(Ebar_func))
    a = algorithm1(nodes, E0, P, z, ())
    (ROOT / "example.txt").write_text(
        render(
            "Configuration A -- CBOM + implicit dependencies + test function",
            f"Result: valid migration strategy. {len(a.sequence)} clusters over "
            f"{len(nodes)} nodes; {a.oracle_calls} oracle invocations, "
            f"{a.oracle_rejections} rejected.",
            a, labels, by_class,
        )
    )

    # ---- B: CBOM only ------------------------------------------------------
    P = TestFunction(by_class=by_class, active=set())
    z = Oracle(func_edges=set(Ebar_func))
    b = algorithm1(nodes, E0, P, z, ())
    # the order the CBOM-only condensation would propose, for reference only
    P2 = TestFunction(by_class=by_class, active=set())
    z2 = Oracle(func_edges=set())          # oracle that accepts everything
    b2 = algorithm1(nodes, E0, P2, z2, ())
    ref = [
        "For reference, the order proposed by the CBOM-only",
        "condensation is given below. It is NOT an output of",
        "Algorithm 1 (which halts at step 1); it is shown only",
        "to indicate where a CBOM-only plan first fails.",
        "",
    ]
    # Annotate each proposed step with the functional dependency it would
    # violate, computed rather than assumed: the order below is a topological
    # order of E_0 alone and changes if the model changes.
    migrated: set[str] = set()
    seen: set[tuple[str, str]] = set()
    for i, C in enumerate(b2.sequence, 1):
        migrated |= set(C)
        viol = {
            (u, v) for u, v in Ebar_func if u in migrated and v not in migrated
        }
        new = sorted(viol - seen)
        seen |= viol
        names = ", ".join(pretty(labels[n]) for n in C)
        ref.append(f"{i:3d}  {{ {names} }}")
        if new:
            u, v = new[0]
            verb = "REJECTED here" if i == 1 else "would also fail"
            extra = f" (+{len(new) - 1} more)" if len(new) > 1 else ""
            ref.append(
                f"       <- {verb}: {pretty(labels[u])} "
                f"needs {pretty(labels[v])}{extra}"
            )
    (ROOT / "example_2.txt").write_text(
        render(
            "Configuration B -- CBOM only (P = 0)",
            "Result: INCONCLUSIVE. Algorithm 1 selects the sink "
            "{ K_1 (ECU) }; the oracle rejects it, because secure "
            "onboard communication with K_8 in the TCU fails. Since "
            "P = 0, the diagnostic scan adds no edge and the same "
            "sink is selected again, so the algorithm returns "
            f"INCONCLUSIVE after {b.oracle_calls} oracle invocation. "
            "No cluster is migrated.",
            b, labels, by_class, tail=ref,
        )
    )

    # ---- C: security-complete, functional incomplete ------------------------
    P = TestFunction(by_class=by_class, active=set(SEC_CLASSES))
    z = Oracle(func_edges=set(Ebar_func))
    c = algorithm1(nodes, E0, P, z, REFINE_ORDER)
    notes = {}
    for rr in c.refinement_rounds:
        rejected = ", ".join(pretty(labels[n]) for n in rr["rejected_cluster"])
        u, v = rr["witnesses"][0]
        notes[rr["after_accepted"]] = wrap(
            f">>> oracle REJECTED {{ {rejected} }} here, violating "
            f"{pretty(labels[u])} -> {pretty(labels[v])}. Refinement "
            f"implemented the {', '.join(rr['activated'])} test, "
            f"adding {rr['edges_added']} edges.",
            52,
        )
    (ROOT / "example_3.txt").write_text(
        render(
            "Configuration C -- P0 detects security dependencies only",
            f"Result: valid migration strategy, identical to configuration A. "
            f"{len(c.sequence)} clusters; {c.oracle_calls} oracle invocations, "
            f"{c.oracle_rejections} rejected; {len(c.refinement_rounds)} refinement "
            f"rounds recovered the {c.edges_final - 68 - 29} edges missing from P0.",
            c, labels, by_class, notes=notes,
        )
    )

    same = [tuple(sorted(x)) for x in a.sequence] == [tuple(sorted(x)) for x in c.sequence]
    print(f"example.txt   : A, {len(a.sequence)} clusters")
    print(f"example_2.txt : B, {b.status}")
    print(f"example_3.txt : C, {len(c.sequence)} clusters, identical to A: {same}")


if __name__ == "__main__":
    main()
