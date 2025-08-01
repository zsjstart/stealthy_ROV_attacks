import pickle
import multiprocessing
import pandas as pd 
import numpy as np

from src.simulation import sim
from src.methods import *
from src.graph import create_graph, compute_graph_metadata, calculate_impact, TRANSIT


def compute_impact(args):
    analysis_graph, directed_graph, method, adoption_rate, attacker, victim, dropout = args

    stripped_graph = analysis_graph.copy()
    stripped_graph.remove_nodes_from([node for node in analysis_graph.nodes if analysis_graph.nodes[node]["type"] == "edge"])

    deployment = method(stripped_graph, adoption_rate)
    stripped_deployment = set(deployment) - set(random.sample(TOP_100, dropout))
            
    pickle.dump(stripped_deployment, open(f"deployments/{method.__name__}_{adoption_rate}_{dropout}.pkl", "wb"))
    component_graph = analysis_graph.copy()
    component_graph.remove_nodes_from(stripped_deployment)

    components = list(nx.connected_components(component_graph))
    component_lengths = list(map(len, components))

    deployed_graph = directed_graph.copy()
    for node in stripped_deployment:
        deployed_graph.nodes[node]["ROV"] = 1
        
    impact, direct_impact, indirect_impact = calculate_impact(deployed_graph, attacker, victim)
    impact_vf, direct_impact_vf, indirect_impact_vf = calculate_impact(deployed_graph, attacker, victim, valley_free_routing=False)

    sim_infos = sim(adoption_rate=adoption_rate, deployment=stripped_deployment, attacker=attacker, victim=victim)
    return {
        "sim_infos": sim_infos,
        "adoption_rate": adoption_rate,
        "dropout": dropout,
        "impact": impact / len(deployed_graph.nodes),
        "direct_impact": direct_impact / len(deployed_graph.nodes),
        "indirect_impact": indirect_impact / len(deployed_graph.nodes),
        "impact_vf": impact_vf / len(deployed_graph.nodes),
        "direct_impact_vf": direct_impact_vf / len(deployed_graph.nodes),
        "indirect_impact_vf": indirect_impact_vf / len(deployed_graph.nodes),
        "method": method.__name__,
        "attacker": attacker,
        "number_of_components": len(components),
        "max_component": max(component_lengths),
        "average_component": np.mean(component_lengths),
        "victim": victim,
        "mode": "random_transit_attacker_victim"
    }



if __name__ == "__main__":
    analysis_graph = create_graph(directed=False)
    directed_graph = create_graph(directed=True)
    compute_graph_metadata(analysis_graph)

    TOP_100 = set(top_100(analysis_graph, None))

    methods = [
        random_choice, 
        cone_size,
        node_betweenness,
        degree_centrality, 
        louvain_communities,
        kernighan_lin_partition
    ]

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

    transit = [node for node in graph.nodes if graph.nodes[node]["type"] == "transit"]
    attackers_victims = zip(random.sample(TRANSIT, 1000), random.sample(TRANSIT, 1000))

    dropouts = [
        0.0,
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

    args = []

    for method in methods:
        for adoption_rate in adoption_rates:
            for attacker, victim in attackers_victims:
                if method.__name__ == "cone_size":
                    for dropout in dropouts:
                        args.append([
                            analysis_graph,
                            directed_graph,
                            method,
                            adoption_rate,
                            attacker,
                            victim,
                            dropout
                        ])
                else:
                    args.append([
                        analysis_graph,
                        directed_graph,
                        method,
                        adoption_rate,
                        attacker,
                        victim,
                        0
                    ])

    print("Lets go!s")
    with multiprocessing.Pool() as pool:
        impacts = pool.map(compute_impact, args)

    df = pd.DataFrame(impacts)
    df.to_csv("results/impacts.csv", index=False)