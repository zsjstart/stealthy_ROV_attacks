# BGP Hijack-Impact Estimator (with route leaks)

Estimate the impact of a BGP prefix hijack on an AS-level topology under partial
[ROV](https://en.wikipedia.org/wiki/Resource_Public_Key_Infrastructure) deployment,
at CAIDA scale (~77k ASes) in a few milliseconds per scenario. A small C core does
the propagation; everything else is Python/NetworkX.

Two quantities are reported per scenario:

- **Direct impact** — ASes that receive *and accept* the bogus announcement (they
  route to the attacker).
- **Indirect impact** — ASes not hit directly, but whose best path to the victim
  traverses a directly-hit AS, so their traffic is captured en route.

This repository integrates the original three-file project (`run.py`, `graph.py`,
`methods.py`) with a fast propagation engine, and adds a **route-leak** setting.

---

## Install & build

```bash
pip install -r requirements.txt
make                 # builds native/libbgp.so
make test            # runs the correctness + leak tests
make demo            # end-to-end on a synthetic graph (no data files needed)
```

`make` just runs `gcc -O3 -march=native -shared -fPIC -Wall -o native/libbgp.so native/bgp_prop.c`.

---

## Quick start

```python
from src.graph import create_graph
from src.engine import compute_impact

G = create_graph(directed=True, edge_file="network-graph-data/as-rel.txt")

r = compute_impact(
    G,
    deployment=["3356", "174"],     # ASes running ROV
    attacker="64500",               # ASN announcing the bogus route
    victim="15169",                 # ASN that owns the prefix
    mode="subprefix",               # or "prefix"
    leak_prob=0.01,                 # NEW: route-leak probability (see below)
    leak_seed=0,
)
print(r["direct"], r["indirect"], r["frac_impacted"])
```

`compute_impact` caches a compiled engine per graph object, so calling it in a loop
over many attacks is cheap. `run.py` drives the full deployment × hijack sweep.

---

## The model

Propagation follows Gao-Rexford. From a single origin, every AS selects a best route
by **(tier, AS-path length)** where tier is `customer (0) < peer (1) < provider (2)`
— customer-learned routes have the highest local-preference; ties break on hop count.
Export follows the standard rule: a customer-learned route is re-announced to everyone,
while a peer/provider-learned route is announced to customers only.

The whole computation reduces to **two single-source propagations** per scenario — one
from the attacker (ROV-filtered) and one from the victim (legitimate) — each `O(V+E)`.
No all-pairs work, no path enumeration. The victim propagation is cached and reused
across attacks.

**ROV.** ASes in the `deployment` set validate origin and drop the RPKI-invalid hijack.
ROV filters the *attacker* propagation only; the legitimate route is always valid.

**Sub-prefix vs prefix.**

- `mode="subprefix"` — the hijack is more specific, so longest-prefix-match means any AS
  that *receives* it uses it. Direct impact = reachable set. This is **exact** and matches
  the reachability model in the original `graph.py`.
- `mode="prefix"` — equal-length hijack competing with the real prefix. An AS is hit if
  its best route toward the attacker beats its best route toward the victim (ties go to
  the victim by default). This is a fast **approximation** of a full joint propagation;
  it does not model every RFC route-selection tie-break.

---

## Route leaks (the new setting)

A **route leak** is a valley-free violation: an AS re-announces a route in a direction
Gao-Rexford forbids (e.g. it takes a route learned from a provider or peer and passes it
*up* to another provider or peer). Real leaks are a common cause of large outages and
accidental hijacks.

The setting is a single probability:

```python
compute_impact(G, deployment, attacker, victim, leak_prob=0.02, leak_seed=0)
```

**Semantics.** Each AS is independently flagged a *leaker* with probability `leak_prob`
(sampled once per run; `leak_seed` fixes which ASes, for reproducibility). A leaker
re-exports **every** route it selects to **all** of its neighbours — providers, peers,
and customers — regardless of how it learned the route. Non-leakers behave normally.
Leakers affect the hijacked announcement *and* legitimate routes alike, since a leak is
a persistent misconfiguration, not something specific to one prefix.

You can also pass an explicit set of leakers instead of a probability:

```python
from src.engine import build_engine
import numpy as np
eng = build_engine(G)
mask = np.zeros(eng.n, np.uint8); mask[eng.csr.asn2id["3356"]] = 1
eng.set_leak(mask=mask)
```

**Monte-Carlo.** Because leakers are random, a single `leak_prob` run is one draw. For an
expected impact and its spread, average over draws:

```python
from src.engine import compute_impact_mc
mc = compute_impact_mc(G, deployment, attacker, victim, leak_prob=0.02, runs=50)
print(mc["frac_impacted"], mc["frac_impacted_std"])
```

**Why it needs a different solver.** Without leaks the `(tier, dist)` key strictly
increases along every export, so a single bucketed-Dijkstra (Dial's) sweep is exact and
fast. A leak can hand an AS a *better-tier* route via a longer path, which breaks that
monotonicity. When any leaker is present the engine automatically switches to a
label-correcting propagation (SPFA) that stays correct under non-monotone keys; with
`leak_prob=0` it uses the fast path. In practice both run in ~1.5–2.5 ms at 77k nodes,
so leaks are essentially free (see `make bench`).

**ROV and leaks are orthogonal.** A leaker cannot push a hijack through a ROV node — ROV
rejects the RPKI-invalid route no matter who sends it. This is intended and correct.

---

## Running the full sweep

```bash
python run.py --methods random_choice cone_size --leak-prob 0.01 --mode subprefix
```

`run.py` builds the directed graph (engine + node types) and the undirected graph
(component statistics), builds one engine, sets the leak probability once, then for each
deployment sets the ROV mask and loops over attacks, writing one JSON per scenario to
`results/`. The JSON schema matches the original plus a `leak_prob` field.

Flags: `--methods` (deployment strategies from `src/methods.py`), `--rel-file`,
`--full-graph` (keep stub/edge ASes), `--leak-prob`, `--leak-seed`, `--mode`.

---

## Data layout

```
network-graph-data/as-rel.txt               AS relationships:  P|C|-1   and   X|Y|0
network-graph-data/LLM_real_hijacks_new.csv  real hijacks (optional)
network-graph-data/caida.txt                 topology for customer-cone sizing (optional)
vrps.csv                                     ROA/VRP list for synthetic victims (optional)
deployments/<method>_<rate>.pkl              cached ROV adopter sets (auto-generated)
results/                                     per-scenario JSON output
```

`run.py` degrades gracefully when the optional files are absent. The relationship-file
convention is CAIDA's: `as1|as2|-1` means *as1 is a provider of as2*; `as1|as2|0` means
they peer. In the directed graph each link is stored both ways (`-1` down, `+1` up).

---

## Project layout

```
native/bgp_prop.c        C engine: Dial's (no-leak) + SPFA (leak) + classifier
src/engine.py            CSR builder, BGPEngine, compute_impact / _mc, leaks
src/graph.py             graph construction (+ original pure-Python impact, kept for cross-check)
src/methods.py           ROV deployment strategies (random, cone-size, degree, Louvain, KL, ...)
run.py                   deployment × hijack sweep
examples/demo.py         runnable demo, no data files
bench/bench_bgp.py       timing at ~77k nodes
tests/                   hand-verified correctness + leak tests
```

---

## Caveats

- **Verify relationship direction.** The engine prints how many ASes have no providers on
  load; only the tier-1 clique (~a dozen) should. A large number means the `-1/+1`
  direction is flipped for your data.
- **Sub-prefix is exact; prefix is an approximation.** A full joint propagation with exact
  RFC tie-breaks can be added if you need per-tie fidelity for equal-length hijacks.
- **Leak model.** Per-node Bernoulli leakers that leak *all* routes. There is no full
  AS-path loop prevention; routes longer than `MAX_DIST` (63) hops are dropped as a loop
  guard, which is far longer than any real AS path. Very large `leak_prob` values stress
  the label-correcting solver more, but realistic leak rates are small.
- **Engine caching.** `compute_impact` memoises one engine per graph object; pass
  `rebuild=True` after mutating `G` in place.
