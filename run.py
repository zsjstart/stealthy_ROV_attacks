import os
import sys

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

import pickle
import networkx as nx
import pandas as pd 
import numpy as np
import torch
import json

from matrix_bgpsim import RMatrix

from src.methods import *
from src.graph import create_graph, compute_graph_metadata, calculate_impact


def get_attacks():
    attack_df = pd.read_csv(os.path.join(ROOT_DIR, "network-graph-data", "LLM_real_hijacks_new.csv"))
    attacks = []

    for idx, row in attack_df.iterrows():
        attacks.append((row["unexpected_origin"].replace("AS", ""), row["expected_origin"].replace("AS", ""), row["prefix"], True))
    
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
        if deployment_r_matrix.get_path(attacker, node):
            directly_affected.add(node)
    
    indirectly_affected = set()

    for node in stripped_graph.nodes():
        path = base_r_matrix.get_path(node, victim)
        if not path: continue

        for path_node in path:
            if path_node in directly_affected:
                indirectly_affected.add(node)
                break

    return len(directly_affected) + len(indirectly_affected), len(directly_affected), len(indirectly_affected)


def compute_impact(
    methods: list[str],
    rel_file: str = None,
    device: str = "cuda:0",
):
    if rel_file is None:
        rel_file = os.path.join(ROOT_DIR, "network-graph-data", "as-rel.txt")

    analysis_graph = create_graph(directed=False, edge_file=rel_file)
    stripped_graph = analysis_graph.copy()
    stripped_graph.remove_nodes_from([node for node in stripped_graph.nodes if stripped_graph.nodes[node]["type"] == "edge"])
    
    directed_graph = create_graph(directed=True, edge_file=rel_file)
    directed_graph.remove_nodes_from([node for node in directed_graph.nodes if directed_graph.nodes[node]["type"] == "edge"])
    
    compute_graph_metadata(stripped_graph)
    
    deployments = get_deployments(methods, stripped_graph, directed_graph)
    attacks = get_attacks()
        
    base_r_matrix = RMatrix(
        input_rels=os.path.join(ROOT_DIR, "network-graph-data", "as-rel.txt"),
        excluded=set(analysis_graph.nodes()) - set(stripped_graph.nodes())
    )
    base_r_matrix.run(
        max_iter=32,
        save_next_hop=True,
        backend="torch",
        device=device
    )
    base_r_matrix.dump("results/base_r_matrix.lz4")

    all_results = []
    
    for deployment in deployments:
        method, adoption_rate, dropout = deployment
        
        pkl_path = os.path.join(ROOT_DIR, "deployments", f"{method.__name__}_{adoption_rate}_{dropout}.pkl")
        with open(pkl_path, "rb") as f:
            deployment_nodes = pickle.load(f)

        component_graph = analysis_graph.copy()
        component_graph.remove_nodes_from(deployment_nodes)

        components = list(nx.connected_components(component_graph))
        component_lengths = list(map(len, components))

        deployment_r_matrix = RMatrix(
            input_rels=os.path.join(ROOT_DIR, "network-graph-data", "as-rel.txt"), 
            excluded=set(analysis_graph.nodes()) - set(stripped_graph.nodes()) - set(deployment_nodes)
        )
        deployment_r_matrix.run(
            max_iter=32,        
            save_next_hop=True, 
            backend="torch",    
            device=device
        )
        deployment_r_matrix.dump("results/{method.__name__}_{adoption_rate}_{dropout}.lz4")

        num_nodes = len(stripped_graph.nodes)
        
        for attacker, victim, _, real in attacks:
            impact, direct_impact, indirect_impact = calculate_impact(
                stripped_graph,
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


def get_deployments(methods: list[str], analysis_graph, directed_graph):
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
        if method.__name__ in methods:
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
