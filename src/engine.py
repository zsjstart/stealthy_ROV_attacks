"""
engine.py — fast BGP-hijack impact estimation with optional route leaks.

Wraps native/libbgp.so (Gao-Rexford propagation) behind a NetworkX front-end.

Route model: single-origin propagation; each AS keeps its best route by
(tier, AS-path length) where tier = customer(0) < peer(1) < provider(2).
Direct impact = ASes that end up routing to the attacker; indirect impact =
ASes whose best path to the victim traverses a directly-hit AS (or the attacker).

Route leaks: with probability `leak_prob` each AS is flagged a "leaker" and
re-exports every route it selects to ALL neighbours, violating valley-free
export. Leakers affect the hijack and the legitimate route alike.
"""
import os
import ctypes as C
import weakref
import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_LIB = os.path.join(_HERE, "..", "native", "libbgp.so")

# relationship encoding in the (directed) NetworkX graph produced by graph.py:
#   u -> v  rel == -1  : u is a PROVIDER of v
#   u -> v  rel == +1  : u is a CUSTOMER of v   (v is provider of u)
#   u -> v  rel ==  0  : u and v are PEERS
REL_P2C = -1
REL_C2P = 1
REL_PEER = 0


# ---------------------------------------------------------------------------
# CSR construction
# ---------------------------------------------------------------------------
class CSR:
    def __init__(self, n, prov, peer, cust, id2asn, asn2id):
        self.n = n
        self.prov_off, self.prov_nbr = prov
        self.peer_off, self.peer_nbr = peer
        self.cust_off, self.cust_nbr = cust
        self.id2asn = id2asn
        self.asn2id = asn2id


def _pack(adj, n):
    off = np.zeros(n + 1, dtype=np.int32)
    for u in range(n):
        off[u + 1] = off[u] + len(adj[u])
    nbr = np.fromiter((w for u in range(n) for w in adj[u]),
                      dtype=np.int32, count=int(off[n]))
    return off, nbr


def _build_csr(n, provider_of, peers, id2asn, asn2id, quiet=False):
    prov = [sorted(provider_of[u]) for u in range(n)]
    cust = [[] for _ in range(n)]
    for u in range(n):
        for p in provider_of[u]:
            cust[p].append(u)
    cust = [sorted(set(c)) for c in cust]
    peer = [sorted(peers[u]) for u in range(n)]
    csr = CSR(n, _pack(prov, n), _pack(peer, n), _pack(cust, n), id2asn, asn2id)
    if not quiet:
        no_prov = sum(1 for u in range(n) if not prov[u])
        frac = no_prov / max(n, 1)
        if frac > 0.05:
            print(f"[WARN] {no_prov} nodes ({frac:.1%}) have no providers; only the "
                  f"tier-1 clique (~a dozen) should. Check the relationship direction.")
        else:
            print(f"[ok] CSR: {n} nodes, {no_prov} provider-less (tier-1 clique).")
    return csr


def csr_from_nx(G, rel_key="relationship"):
    """Build a CSR from a graph.py graph (directed or undirected). Works for both
    because peer edges are symmetrised and provider direction is taken from rel."""
    nodes = list(G.nodes())
    asn2id = {a: i for i, a in enumerate(nodes)}
    id2asn = np.array(nodes, dtype=object)
    n = len(nodes)
    provider_of = [set() for _ in range(n)]
    peers = [set() for _ in range(n)]
    for u, v, data in G.edges(data=True):
        iu, iv = asn2id[u], asn2id[v]
        rel = data.get(rel_key)
        if rel == REL_PEER:
            peers[iu].add(iv); peers[iv].add(iu)
        elif rel == REL_P2C:      # u provider of v
            provider_of[iv].add(iu)
        elif rel == REL_C2P:      # v provider of u
            provider_of[iu].add(iv)
        else:
            raise ValueError(f"edge {u}->{v} has {rel_key}={rel!r}; expected -1/0/1")
    return _build_csr(n, provider_of, peers, id2asn, asn2id)


def csr_from_as_rel(path):
    """Build a CSR straight from a CAIDA-style as-rel file (P|C|-1, X|Y|0).
    Unambiguous; bypasses NetworkX entirely."""
    provider_of_pairs, peer_pairs, asns = [], [], set()
    with open(path) as f:
        for line in f:
            if line.startswith("#") or "|" not in line:
                continue
            a, b, rel = line.strip().split("|")[:3]
            rel = int(rel)
            asns.add(a); asns.add(b)
            (peer_pairs if rel == 0 else provider_of_pairs).append((a, b))
    nodes = sorted(asns, key=lambda x: (len(x), x))
    asn2id = {a: i for i, a in enumerate(nodes)}
    id2asn = np.array(nodes, dtype=object)
    n = len(nodes)
    provider_of = [set() for _ in range(n)]
    peers = [set() for _ in range(n)]
    for p, c in provider_of_pairs:          # a=provider, b=customer
        provider_of[asn2id[c]].add(asn2id[p])
    for a, b in peer_pairs:
        peers[asn2id[a]].add(asn2id[b]); peers[asn2id[b]].add(asn2id[a])
    return _build_csr(n, provider_of, peers, id2asn, asn2id)


# ---------------------------------------------------------------------------
# ctypes plumbing
# ---------------------------------------------------------------------------
_i32p = C.POINTER(C.c_int)
_u8p  = C.POINTER(C.c_ubyte)
_i64p = C.POINTER(C.c_int64)

def _p(a):  return a.ctypes.data_as(_i32p)
def _pu(a): return a.ctypes.data_as(_u8p)


class BGPEngine:
    MODES = {"subprefix": 0, "prefix": 1}

    def __init__(self, csr: CSR, lib_path=_DEFAULT_LIB):
        self.csr = csr
        self.n = csr.n
        self.lib = C.CDLL(os.path.abspath(lib_path))
        self.lib.bgp_init.argtypes = [C.c_int] + [_i32p] * 6
        self.lib.bgp_propagate.argtypes = [C.c_int, _u8p, C.c_int,
                                           _i32p, _i32p, _i32p, _i32p, _i32p]
        self.lib.bgp_propagate_leak.argtypes = [C.c_int, _u8p, C.c_int, _u8p,
                                                _i32p, _i32p, _i32p]
        self.lib.bgp_classify.argtypes = [C.c_int, C.c_int, C.c_int, C.c_int,
                                          _i32p, _i32p, _i32p, _i32p, _i32p,
                                          _i32p, _i64p]
        self._arrs = [np.ascontiguousarray(x, dtype=np.int32) for x in
                      (csr.prov_off, csr.prov_nbr, csr.peer_off, csr.peer_nbr,
                       csr.cust_off, csr.cust_nbr)]
        self.lib.bgp_init(self.n, *[_p(a) for a in self._arrs])

        n = self.n
        self._a = tuple(np.empty(n, np.int32) for _ in range(3))     # attacker d,t,p
        self._status = np.empty(n, np.int32)
        self._counts = np.empty(4, np.int64)
        self._leak = np.zeros(n, np.uint8)
        self._has_leak = False
        self._leak_cfg = (0.0, None)
        self._victim_cache = {}
        self._leak_gen = 0

    # ---- leaks ----
    def set_leak(self, prob=0.0, seed=None, mask=None):
        """Flag leakers. Either give an explicit boolean `mask` (len n) or a
        probability `prob` (each AS independently leaks). Clears the victim cache."""
        if mask is not None:
            self._leak = np.ascontiguousarray(mask, dtype=np.uint8)
            self._leak_cfg = ("mask", id(mask))
        else:
            if prob <= 0:
                self._leak = np.zeros(self.n, np.uint8)
            else:
                rng = np.random.default_rng(seed)
                self._leak = (rng.random(self.n) < prob).astype(np.uint8)
            self._leak_cfg = (float(prob), seed)
        self._has_leak = bool(self._leak.any())
        self._leak_gen += 1
        self._victim_cache.clear()
        return self

    def leakers(self):
        return np.nonzero(self._leak)[0]

    # ---- propagation ----
    def zeros_rov(self):
        return np.zeros(self.n, np.uint8)

    def propagate(self, origin, rov_mask=None, rov_filter=False, out=None):
        if rov_mask is None:
            rov_mask = np.zeros(self.n, np.uint8)
        if out is None:
            out = tuple(np.empty(self.n, np.int32) for _ in range(3))
        d, t, p = out
        if self._has_leak:
            self.lib.bgp_propagate_leak(int(origin), _pu(rov_mask),
                                        1 if rov_filter else 0, _pu(self._leak),
                                        _p(d), _p(t), _p(p))
        else:
            self.lib.bgp_propagate(int(origin), _pu(rov_mask),
                                   1 if rov_filter else 0,
                                   _p(d), _p(t), _p(p), None, None)
        return d, t, p

    def _victim_prop(self, victim):
        key = (victim, self._leak_gen)
        c = self._victim_cache.get(key)
        if c is None:
            d, t, p = self.propagate(victim, rov_filter=False)   # legit: no ROV
            c = (d.copy(), t.copy(), p.copy())
            self._victim_cache[key] = c
        return c

    def clear_cache(self):
        self._victim_cache.clear()

    # ---- scenario ----
    def scenario(self, attacker, victim, rov_mask=None, mode="subprefix",
                 tie_to_victim=True, want_status=False):
        m = self.MODES[mode]
        v_d, v_t, v_p = self._victim_prop(int(victim))
        self.propagate(attacker, rov_mask=rov_mask, rov_filter=True, out=self._a)
        a_d, a_t, _ = self._a
        self.lib.bgp_classify(int(attacker), int(victim), m, 1 if tie_to_victim else 0,
                              _p(a_d), _p(a_t), _p(v_d), _p(v_t), _p(v_p),
                              _p(self._status), self._counts.ctypes.data_as(_i64p))
        safe, direct, indirect, noroute = (int(x) for x in self._counts)
        res = {"attacker": int(attacker), "victim": int(victim), "mode": mode,
               "direct": direct, "indirect": indirect, "safe": safe, "noroute": noroute}
        if want_status:
            res["status"] = self._status.copy()
        return res


# ---------------------------------------------------------------------------
# One-shot convenience API
# ---------------------------------------------------------------------------
_ENGINE_CACHE = weakref.WeakKeyDictionary()

def build_engine(G, rel_key="relationship", lib_path=_DEFAULT_LIB):
    return BGPEngine(csr_from_nx(G, rel_key=rel_key), lib_path=lib_path)


def get_engine(G, rel_key="relationship", lib_path=_DEFAULT_LIB, rebuild=False):
    eng = _ENGINE_CACHE.get(G)
    if eng is None or rebuild:
        eng = build_engine(G, rel_key=rel_key, lib_path=lib_path)
        _ENGINE_CACHE[G] = eng
    return eng


def compute_impact(G, deployment, attacker, victim, mode="subprefix",
                   leak_prob=0.0, leak_seed=None, tie_to_victim=True,
                   rel_key="relationship", lib_path=_DEFAULT_LIB,
                   rebuild=False, want_status=False):
    """Direct + indirect impact of one hijack under an ROV `deployment`.

    G          : NetworkX graph from graph.create_graph (directed recommended).
    deployment : iterable of node labels (ASNs) running ROV.
    attacker   : node label (ASN) originating the bogus route.
    victim     : node label (ASN) owning the prefix.
    mode       : "subprefix" (exact) | "prefix" (equal-length; approximate).
    leak_prob  : probability each AS violates valley-free export (route leak).
    leak_seed  : RNG seed for which ASes leak (reproducibility).

    Returns dict: direct/indirect/safe/noroute counts, their fractions of the
    N-2 classified ASes (frac_direct/frac_indirect/frac_impacted), n_considered.
    """
    eng = get_engine(G, rel_key=rel_key, lib_path=lib_path, rebuild=rebuild)
    if eng._leak_cfg != (float(leak_prob), leak_seed):
        eng.set_leak(prob=leak_prob, seed=leak_seed)

    a2i = eng.csr.asn2id
    def _id(x, what):
        if x not in a2i:
            raise KeyError(f"{what} {x!r} is not a node in G")
        return a2i[x]

    rov = eng.zeros_rov()
    for node in deployment:
        if node in a2i:
            rov[a2i[node]] = 1
    r = eng.scenario(_id(attacker, "attacker"), _id(victim, "victim"),
                     rov_mask=rov, mode=mode, tie_to_victim=tie_to_victim,
                     want_status=want_status)
    denom = max(r["direct"] + r["indirect"] + r["safe"] + r["noroute"], 1)
    r["n_considered"]  = denom
    r["frac_direct"]   = r["direct"] / denom
    r["frac_indirect"] = r["indirect"] / denom
    r["frac_impacted"] = (r["direct"] + r["indirect"]) / denom
    if want_status:
        r["id2asn"] = eng.csr.id2asn
    return r


def compute_impact_mc(G, deployment, attacker, victim, mode="subprefix",
                      leak_prob=0.0, runs=20, base_seed=0, **kw):
    """Monte-Carlo mean impact over `runs` independent leaker samplings.
    Returns the mean dict plus per-run std for the fractions."""
    accum = None
    fracs = {"frac_direct": [], "frac_indirect": [], "frac_impacted": []}
    for k in range(runs):
        r = compute_impact(G, deployment, attacker, victim, mode=mode,
                           leak_prob=leak_prob, leak_seed=base_seed + k, **kw)
        if accum is None:
            accum = {key: 0.0 for key in
                     ("direct", "indirect", "safe", "noroute",
                      "frac_direct", "frac_indirect", "frac_impacted")}
        for key in accum:
            accum[key] += r[key]
        for key in fracs:
            fracs[key].append(r[key])
    out = {k: v / runs for k, v in accum.items()}
    out.update({k + "_std": float(np.std(fracs[k])) for k in fracs})
    out["runs"] = runs
    return out
