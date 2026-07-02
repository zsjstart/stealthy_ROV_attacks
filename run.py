"""
run.py — sweep ROV deployments x hijacks and record direct/indirect impact,
using the fast C engine (src.engine) with an optional route-leak probability.

Expected data layout (paths relative to project root):
  network-graph-data/as-rel.txt              AS relationships (P|C|-1, X|Y|0)
  network-graph-data/LLM_real_hijacks_new.csv  real hijacks (optional)
  deployments/<method>_<rate>.pkl            precomputed ROV adopter sets
  results/                                    per-scenario JSON is written here

If you just want to see it work, run examples/demo.py instead — it needs no data.
"""
import os
import sys
import csv
import json
import pickle
import random

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

import numpy as np
import pandas as pd
import networkx as nx
from tqdm import tqdm

from src.graph import create_graph
from src.engine import BGPEngine, csr_from_nx
from src import methods as M


# --------------------------------------------------------------------------
# data loading
# --------------------------------------------------------------------------
def get_all_roas(csv_file_path):
    results = []
    with open(csv_file_path, newline="", encoding="utf-8") as file:
        for row in csv.DictReader(file):
            asn, prefix = row.get("ASN"), row.get("IP Prefix")
            if not asn or not prefix:
                continue
            results.append({"asn": str(asn).upper().strip().replace("AS", ""),
                            "prefix": prefix.strip()})
    return results


def get_attacks(graph):
    attacks = []
    real_csv = os.path.join(ROOT_DIR, "network-graph-data", "LLM_real_hijacks_new.csv")
    if os.path.exists(real_csv):
        for _, row in pd.read_csv(real_csv).iterrows():
            attacks.append((str(row["unexpected_origin"]).replace("AS", ""),
                            str(row["expected_origin"]).replace("AS", ""),
                            row["prefix"], "real_hijack"))

    syn_path = os.path.join(ROOT_DIR, "results", "synthetic_attacks.pkl")
    if os.path.exists(syn_path):
        with open(syn_path, "rb") as f:
            attacks += pickle.load(f)
    elif os.path.exists(os.path.join(ROOT_DIR, "vrps.csv")):
        edge_nodes = [n for n in graph.nodes if graph.nodes[n]["type"] == "edge"]
        attackers = random.sample(edge_nodes, min(1000, len(edge_nodes)))
        roas = get_all_roas(os.path.join(ROOT_DIR, "vrps.csv"))
        victims = random.sample(roas, min(1000, len(roas)))
    
        synthetic = []
        for attacker, v in zip(attackers, victims):
            ip, ml = v["prefix"].split("/")
            sub = ip + "/" + (ml if int(ml) >= 24 else str(int(ml) + 1))
            synthetic.append((attacker, v["asn"], sub, "synthetic_hijack"))
    
        with open(syn_path, "wb") as f:
            pickle.dump(synthetic, f)
        attacks += synthetic
    
    return attacks


def get_deployments(allowed_methods, analysis_graph, directed_graph):
    possible = [M.real_world, M.random_choice, M.cone_size, M.degree_centrality,
                M.louvain_communities, M.kernighan_lin_partition]
    chosen = [m for m in possible if m.__name__ in allowed_methods]
    rates = [0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
    deployments = []
    for method in chosen:
        for rate in rates:
            if method.__name__ == "real_world" and rate > 0.05:
                continue
            pkl = os.path.join(ROOT_DIR, "deployments", f"{method.__name__}_{rate}.pkl")
            if not os.path.exists(pkl):
                os.makedirs(os.path.dirname(pkl), exist_ok=True)
                pickle.dump(method(analysis_graph, rate), open(pkl, "wb"))
            deployments.append([method, rate, 0])
    return deployments


# --------------------------------------------------------------------------
# main sweep
# --------------------------------------------------------------------------
def compute_impact(methods_list, rel_file=None, full_graph=False,
                   leak_prob=0.0, leak_seed=0, mode="subprefix"):
    if rel_file is None:
        rel_file = os.path.join(ROOT_DIR, "network-graph-data", "caida.txt")

    full_undirected = create_graph(directed=False, edge_file=rel_file)
    full_directed = create_graph(directed=True, edge_file=rel_file)

    EDGE_NODES = [n for n in full_directed.nodes if full_directed.nodes[n]["type"] == "edge"]

    stripped_undirected = full_undirected.copy()
    stripped_directed = full_directed.copy()
    if not full_graph:
        stripped_undirected.remove_nodes_from(EDGE_NODES)
        stripped_directed.remove_nodes_from(EDGE_NODES)

    # ONE engine over the full directed graph; ROV set varies per deployment.
    engine = BGPEngine(csr_from_nx(full_directed))
    engine.set_leak(prob=leak_prob, seed=leak_seed)
    asn2id = engine.csr.asn2id
    num_nodes = full_directed.number_of_nodes()

    deployments = get_deployments(methods_list, stripped_undirected, stripped_directed)
    attacks = get_attacks(full_directed)
    all_results = []

    for method, adoption_rate, dropout in deployments:
        pkl = os.path.join(ROOT_DIR, "deployments", f"{method.__name__}_{adoption_rate}.pkl")
        with open(pkl, "rb") as f:
            deployment_nodes = pickle.load(f)

        # ROV mask for this deployment
        rov = engine.zeros_rov()
        for node in deployment_nodes:
            if node in asn2id:
                rov[asn2id[node]] = 1

        # connectivity stats of the graph once adopters are removed
        comp_graph = full_undirected.copy()
        comp_graph.remove_nodes_from(deployment_nodes)
        components = list(nx.connected_components(comp_graph))
        comp_len = list(map(len, components)) or [0]

        for attacker, victim, _prefix, real in tqdm(attacks, desc=f"{method.__name__}@{adoption_rate}"):
            if attacker not in asn2id or victim not in asn2id or attacker == victim:
                continue

            r = engine.scenario(asn2id[attacker], asn2id[victim], rov_mask=rov, mode=mode)
            direct, indirect = r["direct"], r["indirect"]
            res = {
                "adoption_rate": adoption_rate, "dropout": dropout,
                "impact": (direct + indirect) / num_nodes,
                "direct_impact": direct / num_nodes,
                "indirect_impact": indirect / num_nodes,
                "method": method.__name__, "attacker": attacker, "victim": victim,
                "leak_prob": leak_prob,
                "number_of_components": len(components),
                "max_component": max(comp_len),
                "average_component": float(np.mean(comp_len)),
                "mode": real,
            }
            out = os.path.join(ROOT_DIR, "results",
                               f"{method.__name__}_{adoption_rate}_{dropout}_"
                               f"{attacker}_{victim}_leak{leak_prob}"
                               f"{'_full' if full_graph else ''}.json")
            json.dump(res, open(out, "w"))
            all_results.append(res)

    return pd.DataFrame(all_results)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--methods", nargs="+", default=["random_choice"])
    ap.add_argument("--rel-file", default=None)
    ap.add_argument("--full-graph", action="store_true")
    ap.add_argument("--leak-prob", type=float, default=0.0)
    ap.add_argument("--leak-seed", type=int, default=0)
    ap.add_argument("--mode", choices=["subprefix", "prefix"], default="subprefix")
    args = ap.parse_args()
    df = compute_impact(args.methods, rel_file=args.rel_file, full_graph=args.full_graph,
                        leak_prob=args.leak_prob, leak_seed=args.leak_seed, mode=args.mode)
    print(df.groupby(["method", "adoption_rate"])[["impact", "direct_impact", "indirect_impact"]].mean())
