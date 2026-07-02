"""
bench_bgp.py — timing at CAIDA scale (~77k ASes) for both propagation paths.

    python bench/bench_bgp.py
"""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
from src.engine import BGPEngine, csr_from_nx
from synth import make_synth_graph


def timeit(fn, reps):
    fn()  # warm
    t = time.perf_counter()
    for _ in range(reps):
        fn()
    return (time.perf_counter() - t) / reps * 1e3   # ms


def main():
    print("building ~77k-node synthetic graph ...")
    t0 = time.perf_counter()
    G = make_synth_graph(n_tier1=15, n_mid=2500, n_edge=75000, seed=0)
    eng = BGPEngine(csr_from_nx(G))
    print(f"  nodes={eng.n}  directed-edges={G.number_of_edges()}  "
          f"build={time.perf_counter()-t0:.2f}s\n")

    nodes = list(G.nodes())
    a = nodes.index(next(n for n in nodes if n.startswith("E_")))
    v = nodes.index(next(n for n in nodes if n.startswith("M_")))
    rng = np.random.default_rng(0)
    rov = (rng.random(eng.n) < 0.2).astype(np.uint8)

    print("single-source propagation:")
    eng.set_leak(prob=0.0)
    print(f"  Dial's (no leak)         {timeit(lambda: eng.propagate(a, rov, True), 20):7.2f} ms")
    for p in (0.001, 0.01, 0.05):
        eng.set_leak(prob=p, seed=0)
        nlk = int(eng._leak.sum())
        print(f"  SPFA leak_prob={p:<5} ({nlk:>4} leakers) "
              f"{timeit(lambda: eng.propagate(a, rov, True), 20):7.2f} ms")

    print("\nfull scenario (attacker prop + cached victim prop + classify):")
    for p in (0.0, 0.01, 0.05):
        eng.set_leak(prob=p, seed=0)
        eng.clear_cache()
        eng.scenario(a, v, rov, mode="subprefix")   # warm victim cache
        dt = timeit(lambda: eng.scenario(a, v, rov, mode="subprefix"), 20)
        print(f"  leak_prob={p:<5}  {dt:7.2f} ms/scenario  (~{1000/dt:.0f}/s, victim cached)")

    print("\nattacker sweep, shared victim (throughput):")
    for p in (0.0, 0.05):
        eng.set_leak(prob=p, seed=0)
        eng.clear_cache()
        attackers = rng.integers(0, eng.n, size=200)
        eng.scenario(int(attackers[0]), v, rov)  # warm
        t = time.perf_counter()
        for at in attackers:
            eng.scenario(int(at), v, rov, mode="subprefix")
        dt = (time.perf_counter() - t) / len(attackers) * 1e3
        print(f"  leak_prob={p:<5}  {dt:7.2f} ms/scenario  (~{1000/dt:.0f}/s)")


if __name__ == "__main__":
    main()
