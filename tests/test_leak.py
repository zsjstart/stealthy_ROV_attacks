"""Route-leak correctness.
Topology  provider->customer: 0->1, 1->2, 5->3, 3->4 ;  peer (2,3).
Attacker=2, victim=4, sub-prefix, no ROV.

Without leaks: AS3 only has a *peer* route to the hijack, so it does NOT re-announce
it up to its provider AS5 -> AS5 is untouched but routes to the victim via AS3, so
AS5 is *indirectly* hit.  direct={0,1,3}, indirect={5}.

With AS3 leaking: AS3 re-announces the peer-learned hijack up to AS5, so AS5 now
*receives* it directly.  direct={0,1,3,5}, indirect={}."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np, networkx as nx
from src.engine import csr_from_nx, BGPEngine

LIB = os.path.join(os.path.dirname(__file__), "..", "native", "libbgp.so")

def directed(p2c, peers):
    G = nx.DiGraph()
    for p, c in p2c:
        G.add_edge(p, c, relationship=-1); G.add_edge(c, p, relationship=1)
    for a, b in peers:
        G.add_edge(a, b, relationship=0); G.add_edge(b, a, relationship=0)
    return G

G = directed([(0,1),(1,2),(5,3),(3,4)], [(2,3)])
eng = BGPEngine(csr_from_nx(G), lib_path=LIB)
idx = eng.csr.asn2id

def run(name, res, d, i):
    got = (res["direct"], res["indirect"])
    print(f"{'PASS' if got==(d,i) else 'FAIL'} {name}: got {got} exp {(d,i)}")
    assert got == (d, i), name

# no leaks
eng.set_leak(prob=0.0)
run("no leak", eng.scenario(idx[2], idx[4], eng.zeros_rov(), mode="subprefix"), 3, 1)

# AS3 leaks (explicit mask)
mask = np.zeros(eng.n, np.uint8); mask[idx[3]] = 1
eng.set_leak(mask=mask)
run("AS3 leaks", eng.scenario(idx[2], idx[4], eng.zeros_rov(), mode="subprefix"), 4, 0)

# leak_prob monotonicity sanity: more leakers never reduces total impacted
eng2 = BGPEngine(csr_from_nx(G), lib_path=LIB)
base = None
for p in (0.0, 0.25, 0.5, 0.75, 1.0):
    eng2.set_leak(prob=p, seed=1)
    r = eng2.scenario(idx[2], idx[4], eng2.zeros_rov(), mode="subprefix")
    tot = r["direct"] + r["indirect"]
    print(f"  leak_prob={p}: direct={r['direct']} indirect={r['indirect']} impacted={tot}")
print("leak correctness OK")
