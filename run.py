import os
import sys

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

import csv
import pickle
import networkx as nx
import pandas as pd 
import numpy as np
import json

from tqdm import tqdm
from itertools import product
from matrix_bgpsim import RMatrix

from src.methods import *
from src.graph import create_graph, calculate_impact



def get_all_roas(csv_file_path: str) -> list[dict[str, str]]:
    """
    Reads a VRP/ROA CSV file and returns all ASN-prefix pairs.

    Example return:
    [
        {"asn": "AS64496", "prefix": "203.0.113.0/24"},
        {"asn": "AS64497", "prefix": "198.51.100.0/24"}
    ]
    """

    results = []

    with open(csv_file_path, newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            row_asn = (
                row.get("asn")
                or row.get("ASN")
                or row.get("asID")
                or row.get("origin")
            )

            prefix = (
                row.get("prefix")
                or row.get("Prefix")
            )

            if not row_asn or not prefix:
                continue

            row_asn = str(row_asn).upper().strip()

            if not row_asn.startswith("AS"):
                row_asn = f"AS{row_asn}"

            results.append({
                "asn": row_asn,
                "prefix": prefix.strip()
            })

    return results


def get_attacks(graph: nx.Graph):
    attack_df = pd.read_csv(
        os.path.join(ROOT_DIR, "network-graph-data", "LLM_real_hijacks_new.csv")
    )
    attacks = []

    for idx, row in attack_df.iterrows():
        attacks.append((
            row["unexpected_origin"].replace("AS", ""), 
            row["expected_origin"].replace("AS", ""), 
            row["prefix"], 
            True
        ))
    
    # Create synthetic attacks
    edge_nodes = [node for node in graph.nodes if graph.nodes[node]["type"] == "edge"]
    attackers = random.sample(edge_nodes, 1000)

    nodes_with_roas = get_all_roas("data/vrp.csv")
    victim_objects = random.sample(nodes_with_roas, 1000)

    for attacker, victim in zip(attackers, victim_objects):
        ip, max_length = victim["prefix"].split("/")

        attacks.append((
            attacker, 
            victim["asn"], 
            ip + "/" + max_length if max_length >= 24 else ip + "/" + str(int(max_length) + 1), 
            True
        ))

    # create all
    for attacker, victim in product(attackers, graph.nodes):
        if attacker == victim: continue

        attacks.append((
            attacker, 
            victim, 
            "", 
            False
        ))

    return attacks


def calculate_impact(
    stripped_graph: nx.Graph,
    base_r_matrix: RMatrix, 
    deployment_r_matrix: RMatrix, 
    attacker: int, 
    victim: int 
):
    directly_affected = set()

    for node in stripped_graph.nodes():
        if not deployment_r_matrix.has_asn(node): continue
        if deployment_r_matrix.get_path(attacker, node):
            directly_affected.add(node)
    
    indirectly_affected = set()

    for node in stripped_graph.nodes():
        if not base_r_matrix.has_asn(node): continue
        path = base_r_matrix.get_path(node, victim)
        if not path: continue

        for path_node in path:
            if path_node in directly_affected:
                indirectly_affected.add(node)
                break

    return len(directly_affected.union(indirectly_affected)), len(directly_affected), len(indirectly_affected)


def compute_impact(
    methods: list[str],
    rel_file: str = None,
    device: str = "cuda:0",
):
    if rel_file is None:
        rel_file = os.path.join(ROOT_DIR, "network-graph-data", "as-rel.txt")

    full_undirected_graph = create_graph(directed=False, edge_file=rel_file)
    full_directed_graph = create_graph(directed=True, edge_file=rel_file)

    TRANSIT_NODES = [
        node 
        for node in full_directed_graph.nodes 
        if full_directed_graph.nodes[node]["type"] == "transit"
    ]

    EDGE_NODES = [
        node 
        for node in full_directed_graph.nodes 
        if full_directed_graph.nodes[node]["type"] == "edge"
    ]

    stripped_undirected_graph = full_undirected_graph.copy()
    stripped_undirected_graph.remove_nodes_from(EDGE_NODES)

    stripped_directed_graph = full_directed_graph.copy()
    stripped_directed_graph.remove_nodes_from(EDGE_NODES)
    
    deployments = get_deployments(
        methods, 
        stripped_undirected_graph, 
        stripped_directed_graph
    )

    attacks = get_attacks(full_directed_graph)


    if not os.path.exists("results/base_r_matrix.lz4"):
        base_r_matrix = RMatrix(
            input_rels=rel_file,
            excluded=set(EDGE_NODES)
        )
        base_r_matrix.run(
            max_iter=32,
            save_next_hop=True,
            backend="torch",
            device=device
        )
        if not os.path.exists("results"):
            os.makedirs("results")
        base_r_matrix.dump("results/base_r_matrix.lz4")
    else:
        base_r_matrix = RMatrix.load("results/base_r_matrix.lz4")

    all_results = []
    
    for deployment in deployments:
        method, adoption_rate, dropout = deployment
        
        pkl_path = os.path.join(ROOT_DIR, "deployments", f"{method.__name__}_{adoption_rate}_{dropout}.pkl")
        with open(pkl_path, "rb") as f:
            deployment_nodes = pickle.load(f)

        component_graph = full_undirected_graph.copy()
        component_graph.remove_nodes_from(deployment_nodes)
        components = list(nx.connected_components(component_graph))
        component_lengths = list(map(len, components))
        
        matrix_file = f"results/{method.__name__}_{adoption_rate}_{dropout}.lz4"
        if not os.path.exists(matrix_file):
            deployment_r_matrix = RMatrix(
                input_rels=rel_file,
                excluded=set(EDGE_NODES).union(set(deployment_nodes))
            )
            deployment_r_matrix.run(
                max_iter=32,        
                save_next_hop=True, 
                backend="torch",    
                device=device
            )
            deployment_r_matrix.dump(matrix_file)
        else:
            deployment_r_matrix = RMatrix.load(matrix_file)

        num_nodes = len(stripped_undirected_graph.nodes)
        
        for attacker, victim, _, real in tqdm(attacks):
            if not deployment_r_matrix.has_asn(attacker) or not base_r_matrix.has_asn(victim):
                continue

            impact, direct_impact, indirect_impact = calculate_impact(
                stripped_undirected_graph,
                base_r_matrix,
                deployment_r_matrix,
                attacker,
                victim
            )

            res = {
                "adoption_rate": adoption_rate,
                "dropout": dropout,
                "impact": impact / num_nodes,
                "direct_impact": direct_impact / num_nodes,
                "indirect_impact": indirect_impact / num_nodes,
                "method": method.__name__,
                "attacker": attacker,
                "victim": victim,
                "number_of_components": len(components),
                "max_component": max(component_lengths),
                "average_component": np.mean(component_lengths),
                "mode": "real_hijack" if real else "fake_hijack"
            }
            json.dump(res, open(os.path.join(ROOT_DIR, "results", f"{method.__name__}_{adoption_rate}_{dropout}_{attacker}_{victim}.json"), "w"))
            all_results.append(res)
            
    return pd.DataFrame(all_results)


def get_deployments(allowed_methods: list[str], analysis_graph, directed_graph):
    TOP_100 = top_100(directed_graph, None)

    possible_methods = [
        random_choice, 
        cone_size,
        degree_centrality, 
        louvain_communities,
        kernighan_lin_partition
    ]
    methods = []

    for method in possible_methods:
        if method.__name__ in allowed_methods:
            methods.append(method)

    adoption_rates = [
        0.05,
        0.1,
        0.2,
        0.3,
        0.4,
        0.5,
        0.6,
        0.7,
        0.8,
        0.9
    ]

    dropouts = [
        0,
        10,
        20,
        30,
        40,
        50,
        60,
        70,
        80,
        90
    ]

    deployments = []

    for method in methods:
        for adoption_rate in adoption_rates:
            if method.__name__ == "cone_size":
                for dropout in dropouts:
                    pkl_path = os.path.join(ROOT_DIR, "deployments", f"{method.__name__}_{adoption_rate}_{dropout}.pkl")
                    if not os.path.exists(pkl_path):
                        deployment = method(directed_graph, adoption_rate)
                        stripped_deployment = set(deployment) - set(random.sample(TOP_100, dropout))
                        pickle.dump(stripped_deployment, open(pkl_path, "wb"))
                    
                    deployments.append([
                        method,
                        adoption_rate,
                        dropout
                    ])
            else:
                pkl_path = os.path.join(ROOT_DIR, "deployments", f"{method.__name__}_{adoption_rate}_0.pkl")
                if not os.path.exists(pkl_path):
                    deployment = method(analysis_graph, adoption_rate)
                    pickle.dump(deployment, open(pkl_path, "wb"))

            deployments.append([
                method,
                adoption_rate,
                0
            ])

    return deployments
