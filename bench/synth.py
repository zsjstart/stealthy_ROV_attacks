"""Synthetic CAIDA-like AS topology generator (no data files needed).

Produces a directed graph in graph.py's convention:
  p2c edge -> u->v relationship=-1 and v->u relationship=+1
  peer     -> both directions relationship=0
"""
import numpy as np
import networkx as nx


def make_synth_graph(n_tier1=15, n_mid=2000, n_edge=75000, seed=0):
    rng = np.random.default_rng(seed)
    G = nx.DiGraph()

    tier1 = [f"T1_{i}" for i in range(n_tier1)]
    mid   = [f"M_{i}"  for i in range(n_mid)]
    edge  = [f"E_{i}"  for i in range(n_edge)]

    def p2c(p, c):
        G.add_edge(p, c, relationship=-1)
        G.add_edge(c, p, relationship=1)

    def peer(a, b):
        G.add_edge(a, b, relationship=0)
        G.add_edge(b, a, relationship=0)

    # tier-1 full peering clique
    for i in range(n_tier1):
        for j in range(i + 1, n_tier1):
            peer(tier1[i], tier1[j])

    # mids: 1-3 tier-1 providers, occasional mid-mid peer
    for m in mid:
        for p in rng.choice(tier1, size=int(rng.integers(1, 4)), replace=False):
            p2c(p, m)
    for m in mid:
        if rng.random() < 0.3:
            other = mid[int(rng.integers(0, n_mid))]
            if other != m:
                peer(m, other)

    # edges: 1-3 providers drawn mostly from mids, sometimes tier-1
    mid_arr = np.array(mid, dtype=object)
    for e in edge:
        k = int(rng.integers(1, 4))
        provs = rng.choice(mid_arr, size=k, replace=False)
        for p in provs:
            p2c(p, e)
        if rng.random() < 0.05:
            p2c(tier1[int(rng.integers(0, n_tier1))], e)

    return G
