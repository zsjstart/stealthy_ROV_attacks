"""
demo.py — end-to-end on a synthetic graph, no data files required.

Shows: build engine -> pick a hijack -> sweep the route-leak probability and
watch direct/indirect impact grow, then a Monte-Carlo average over leaker draws.

    python examples/demo.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bench"))

import numpy as np
from src.engine import BGPEngine, csr_from_nx, compute_impact, compute_impact_mc
from synth import make_synth_graph


def main():
    print("building synthetic graph (~20k nodes)...")
    G = make_synth_graph(n_tier1=12, n_mid=800, n_edge=20000, seed=1)
    print(f"  nodes={G.number_of_nodes()}  directed-edges={G.number_of_edges()}")

    nodes = list(G.nodes())
    rng = np.random.default_rng(7)

    # equal-prefix hijack, edge attacker vs a different edge victim: legitimate
    # routes compete with the hijack, so impact is well below 100% and leaks matter.
    attacker = next(n for n in nodes if n.startswith("E_"))
    victim   = next(n for n in nodes if n.startswith("E_") and n != attacker)

    # deployment: 5% of ASes run ROV (random)
    deployment = list(rng.choice(nodes, size=int(0.05 * len(nodes)), replace=False))
    print(f"  attacker={attacker}  victim={victim}  ROV adopters={len(deployment)}\n")

    print("leak_prob sweep (equal-prefix hijack, fixed seed):")
    print(f"  {'leak_prob':>9} {'direct':>8} {'indirect':>9} {'impacted%':>10}")
    for p in (0.0, 0.001, 0.005, 0.01, 0.02, 0.05, 0.1):
        r = compute_impact(G, deployment, attacker, victim,
                           mode="prefix", leak_prob=p, leak_seed=0)
        print(f"  {p:>9} {r['direct']:>8} {r['indirect']:>9} {100*r['frac_impacted']:>9.2f}%")

    print("\nMonte-Carlo over 25 leaker draws at leak_prob=0.02:")
    mc = compute_impact_mc(G, deployment, attacker, victim,
                           mode="prefix", leak_prob=0.02, runs=25, base_seed=0)
    print(f"  mean impacted = {100*mc['frac_impacted']:.2f}%  "
          f"(std {100*mc['frac_impacted_std']:.2f}%)  "
          f"direct={mc['direct']:.1f} indirect={mc['indirect']:.1f}")


if __name__ == "__main__":
    main()
