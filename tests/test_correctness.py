"""No-leak correctness on a 7-node topology, verified by hand.
   provider->customer: 0->{1,2} 1->{3,4} 2->{4,5} 3->{6};  peers (1,2),(4,5)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import networkx as nx
from src.engine import csr_from_nx, BGPEngine

LIB = os.path.join(os.path.dirname(__file__), "..", "native", "libbgp.so")

def directed(p2c, peers):
    G = nx.DiGraph()
    for p, c in p2c:
        G.add_edge(p, c, relationship=-1); G.add_edge(c, p, relationship=1)
    for a, b in peers:
        G.add_edge(a, b, relationship=0); G.add_edge(b, a, relationship=0)
    return G

G = directed([(0,1),(0,2),(1,3),(1,4),(2,4),(2,5),(3,6)], [(1,2),(4,5)])
eng = BGPEngine(csr_from_nx(G), lib_path=LIB)
idx = eng.csr.asn2id

def rov(*a):
    m = eng.zeros_rov()
    for x in a: m[idx[x]] = 1
    return m

def check(name, res, d, i, s):
    got = (res["direct"], res["indirect"], res["safe"])
    print(f"{'PASS' if got==(d,i,s) else 'FAIL'} {name}: got {got} exp {(d,i,s)}")
    assert got == (d, i, s), name

check("A subprefix a=4 v=5 rov={0}",
      eng.scenario(idx[4], idx[5], rov(0), mode="subprefix"), 4, 1, 0)
check("B prefix    a=4 v=5 rov={}",
      eng.scenario(idx[4], idx[5], eng.zeros_rov(), mode="prefix"), 3, 0, 2)
check("C subprefix a=6 v=5 rov={1}",
      eng.scenario(idx[6], idx[5], rov(1), mode="subprefix"), 1, 0, 4)
check("D subprefix a=6 v=5 rov={}",
      eng.scenario(idx[6], idx[5], eng.zeros_rov(), mode="subprefix"), 5, 0, 0)
print("no-leak correctness OK")
