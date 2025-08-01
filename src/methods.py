import json
import random
import numpy as np
import pandas as pd
import networkx as nx
from .graph import create_graph


def compute_cone(node, cones):
    neighbors = graph.successors(node)
    neighbors = [n for n in neighbors if graph.get_edge_data(node, n).get("relationship") == -1]
    

    if node in cones:
        return cones[node]
    
    cone = {node}

    for neighbor in neighbors:
        if neighbor in cones:
            cone |= cones[neighbor]
        else:
            cone |= compute_cone(neighbor, cones)

    cones[node] = cone
    return cone


graph = create_graph(directed=True)
graph.remove_nodes_from([node for node in graph.nodes if graph.nodes[node] == "edge"])

cones = {}

for node in graph.nodes:
    compute_cone(node, cones)


CONE_SIZES = {}

for key in cones:
    CONE_SIZES[key] = len(cones[key])


import requests


def top_100(graph, rate):
    return sorted(graph.nodes, key=lambda x: CONE_SIZES[x], reverse=True)[:100]


def real_world(graph, rate):
    link_template = 'https://api.rovista.netsecurelab.org/rovista/api/overview?offset={offset}&count={count}&sortBy=rank&sortOrder=asc&searchBy=ASN'

    offset = 0
    count = 50000

    data = []

    while True:
        try:
            response = requests.get(link_template.format(offset=offset, count=count))
            data += response.json()["data"]

            if len(response.json()["data"]) < count:
                break
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            break
        offset += count

    return list(map(lambda x: x["asn"], filter(lambda x: x["ratio"] > 0.1 and x["asn"] in graph.nodes, data)))


def cone_size(graph, adoption_rate):
    n = round(adoption_rate * len(graph.nodes))

    sorted_nodes = sorted(list(graph.nodes), key=lambda x: CONE_SIZES[x], reverse=True)
    
    return sorted_nodes[0:n]


def special_deployment(graph, n):
    return nx.node_boundary(graph, [node for node in graph.nodes if graph.nodes[node]["type"] == "tier-1"])


def random_choice(
        graph: nx.Graph, 
        adoption_rate: float,
        transit_only: bool = True
    ):
    tier1 = [node for node in graph.nodes if graph.nodes[node]["type"] == "tier-1"]
    transit = [node for node in graph.nodes if graph.nodes[node]["type"] == "transit"]
    edge = [node for node in graph.nodes if graph.nodes[node]["type"] == "edge"]

    if transit_only:
        n = round(adoption_rate * len(transit))
        return tier1 + random.sample(transit, n)
    else:
        n = round(adoption_rate * len(graph.nodes))
        if len(tier1) >= n:
            return random.sample(tier1, n)
        
        deployment = tier1
        n -= len(tier1)

        if len(transit) >= n:
            return deployment + random.sample(transit, n)

        n -= len(transit)

        if len(edge) >= n:
            return deployment + transit + random.sample(edge, n)
    
        return tier1 + transit + edge


def level_heuristic(graph, adoption_rate):
    n = round(adoption_rate * len(graph.nodes))
    nodes = sorted(graph.nodes(data=True), key=lambda x: abs(5 - x[1]["level"]), reverse=True)
    
    return set([x[0] for x in nodes[:n]])


def degree_centrality(graph, adoption_rate):
    n = round(adoption_rate * len(graph.nodes))
    deployment = set()
    
    while len(deployment) < n:
        degrees = nx.degree_centrality(graph.subgraph(graph.nodes - deployment))
        deployment.add(max(degrees, key=lambda x: degrees[x]))
    
    return deployment


def eigenvector_centrality(graph, adoption_rate):
    n = round(adoption_rate * len(graph.nodes))
    nodes = sorted(graph.nodes(data=True), key=lambda x: x[1]["eigenvector"], reverse=True)
    
    return set([x[0] for x in nodes[:n]])


def kernighan_lin_partition(graph, adoption_rate):
    if adoption_rate == 0:
        return []
    
    last = None
    parts = 2
    n = round(adoption_rate * len(graph.nodes))
    
    partition = [graph.nodes]

    while True:
        if len(partition) > parts:
            partition = [graph.nodes]
        
        while len(partition) < parts:
            new_partition = []
            for part in partition:
                new_partition.extend(list(nx.community.kernighan_lin.kernighan_lin_bisection(graph.subgraph(part))))
            partition = new_partition

        if last is None and parts > 2:
            for part in partition:
                boundary1 = nx.node_boundary(graph, part)
                boundary2 = nx.node_boundary(graph, graph.nodes - part)

                boundary = boundary1 if len(boundary1) < len(boundary2) else boundary2
                if len(boundary) < n:
                    return boundary | set(np.random.choice(list(graph.nodes - boundary), abs(n - len(boundary)), replace=False))
                
            parts *= 2
        elif parts == 2:
            boundary1 = nx.node_boundary(graph, partition[0])
            boundary2 = nx.node_boundary(graph, partition[1])

            boundary = boundary1 if len(boundary1) < len(boundary2) else boundary2
            if len(boundary) < n:
                last = boundary
            parts *= 2
        else:
            boundary = set()
            for part in partition:
                b1 = nx.node_boundary(graph, part) | boundary
                b2 = nx.node_boundary(graph, graph.nodes - part) | boundary

                boundary = b1 if len(b1) < len(b2) else b2
            if len(boundary) < n and parts < len(graph.nodes) / 4:
                last = boundary
                parts *= 2
            else:
                return last | set(np.random.choice(list(graph.nodes - last), abs(n - len(last)), replace=False))


# def metis_partition(graph, adoption_rate):
#     if adoption_rate == 0:
#         return []
    
#     last = None
#     parts = 2
#     n = round(adoption_rate * len(graph.nodes))
    
#     while True:
#         cuts, partition = metis.part_graph(graph, parts)
#         partitions = [set(np.where(np.array(partition) == i)[0]) for i in range(parts)]

#         if last is None and parts > 2:
#             for part in partitions:
#                 boundary1 = nx.node_boundary(graph, graph.nodes - part)
#                 boundary2 = nx.node_boundary(graph, part)

#                 boundary = boundary1 if len(boundary1) < len(boundary2) else boundary2
#                 if len(boundary) < n:
#                     return boundary
                
#             parts *= 2
#         elif parts == 2:
#             boundary1 = nx.node_boundary(graph, graph.nodes - partitions[0])
#             boundary2 = nx.node_boundary(graph, partitions[0])

#             boundary = boundary1 if len(boundary1) < len(boundary2) else boundary2

            
#             if len(boundary) < n:
#                 last = boundary
#             parts *= 2
#         else:
#             boundary = set()
#             for part in partitions:
#                 b1 = nx.node_boundary(graph, graph.nodes - part) | boundary
#                 b2 = nx.node_boundary(graph, part) | boundary

#                 boundary = b1 if len(b1) < len(b2) else b2
#             if len(boundary) < n and parts < len(graph.nodes) / 4:
#                 last = boundary
#                 parts *= 2
#             else:
#                 return last
            

def compute_subsets(graph):
    possible_subsets = []

    for partition in nx.community.louvain_partitions(graph):
        for community in partition:
            inner_boundary = nx.node_boundary(graph, graph.nodes - community, community)
            outer_boundary = nx.node_boundary(graph, community)
            possible_subsets.append({
                "subset": community,
                "number_of_members": len(community),
                "inner_boundary": inner_boundary,
                "inner_boundary_length": len(inner_boundary),
                "outer_boundary": outer_boundary,
                "outer_boundary_length": len(outer_boundary) 
            })

    subset_df = pd.DataFrame(possible_subsets)
    subset_df = subset_df.sort_values(by="number_of_members", ascending=False)

    return subset_df

def louvain_communities(graph, adoption_rate):
    if adoption_rate == 0:
        return []
    
    n = round(adoption_rate * len(graph.nodes))
    subset_df = compute_subsets(graph)
    current_partition = [set(graph.nodes)]
    current_boundary = set()

    final = []

    while current_partition:
        subset_df = subset_df[(subset_df.inner_boundary_length < (n - len(current_boundary))) | (subset_df.outer_boundary_length < (n - len(current_boundary)))]
        for idx, row in subset_df[(subset_df.inner_boundary == 0) | (subset_df.outer_boundary == 0)].iterrows():
            current_partition.append(row["subset"])
            current_partition[[row["subset"] <= x for x in current_partition].index(True)] -= row["subset"]
            subset_df.drop(idx, axis=0, inplace=True)
        
        biggest_partition = max(current_partition, key=len)

        candidates = subset_df[subset_df.subset < biggest_partition]
        if len(candidates) == 1:
            try:
                new_subset_df = compute_subsets(graph.subgraph(biggest_partition))
            except Exception:
                new_subset_df = None

            if new_subset_df is None or len(new_subset_df) < 2:
                final.append(biggest_partition)
                idx = current_partition.index(biggest_partition)
                del current_partition[idx]
                continue
            else:
                subset_df = pd.concat([subset_df, new_subset_df], ignore_index=True)
                subset_df = subset_df.sort_values(by=["number_of_members"], ascending=False).reset_index(drop=True)
                candidates = subset_df

        new_subset = None
        for idx, subset in candidates[candidates.number_of_members < (len(biggest_partition) / 2)].iterrows():
            boundary = subset["inner_boundary"] if subset["inner_boundary_length"] < subset["outer_boundary_length"] else subset["outer_boundary"]

            if len(boundary) < (n - len(current_boundary)):
                new_subset = subset
                subset_df.drop(idx, axis=0, inplace=True)
                break

        if new_subset is None:
            idx = current_partition.index(biggest_partition)
            final.append(biggest_partition)
            del current_partition[idx]
            continue

            
        idx = current_partition.index(biggest_partition)
        current_partition[idx] -= new_subset["subset"]
        current_partition.append(new_subset["subset"])
        current_boundary |= boundary

        subset_df["inner_boundary"] = subset_df.inner_boundary.apply(lambda x: x - boundary)
        subset_df["inner_boundary_length"] = subset_df.inner_boundary.apply(len)
        subset_df["outer_boundary"] = subset_df.outer_boundary.apply(lambda x: x - boundary)
        subset_df["outer_boundary_length"] = subset_df.outer_boundary.apply(len)

    return current_boundary | set(random.sample(list(set(graph.nodes) - current_boundary), n - len(current_boundary)))


def node_betweenness(graph, adoption_rate):
    n = round(adoption_rate * len(graph.nodes))

    counts = json.load(open("results/reachable_nodes_count.json", "r"))
    sorted_nodes = sorted(graph.nodes, key=lambda x: counts[str(x)] if str(x) in counts else 0, reverse=True)

    return sorted_nodes[:n]