import os
import json
import random

import numpy as np
import pandas as pd
import networkx as nx

from .graph import create_graph

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Customer-cone sizes are computed lazily on first use so importing this module
# does not require a caida.txt on disk.
_CONE_SIZES = None


def compute_cone(node, cones, graph):
    if node in cones:
        return cones[node]
    neighbors = [n for n in graph.successors(node)
                 if graph.get_edge_data(node, n).get("relationship") == 1]
    cone = {node}
    for neighbor in neighbors:
        cone |= cones.get(neighbor) or compute_cone(neighbor, cones, graph)
    cones[node] = cone
    return cone


def compute_cone_sizes(edge_file="caida.txt"):
    cones = {}
    graph = create_graph(directed=True, special=True, edge_file=edge_file)
    import sys
    sys.setrecursionlimit(1_000_000)
    for node in graph.nodes:
        compute_cone(node, cones, graph)
    return {k: len(v) for k, v in cones.items()}


def get_cone_sizes(edge_file="caida.txt"):
    global _CONE_SIZES
    if _CONE_SIZES is None:
        _CONE_SIZES = compute_cone_sizes(edge_file)
    return _CONE_SIZES


def top_100(graph, rate):
    cs = get_cone_sizes()
    return sorted(graph.nodes, key=lambda x: cs.get(x, 0), reverse=True)[:100]


def real_world(graph, rate):
    import requests
    link = ('https://api.rovista.netsecurelab.org/rovista/api/overview'
            '?offset={offset}&count={count}&sortBy=rank&sortOrder=asc&searchBy=ASN')
    offset, count, data = 0, 50000, []
    while True:
        try:
            resp = requests.get(link.format(offset=offset, count=count))
            page = resp.json()["data"]
            data += page
            if len(page) < count:
                break
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            break
        offset += count
    return [x["asn"] for x in data if x["ratio"] > 0]


def cone_size(graph, adoption_rate):
    cs = get_cone_sizes()
    n = round(adoption_rate * len(graph.nodes))
    return sorted(list(graph.nodes), key=lambda x: cs.get(x, 0), reverse=True)[:n]


def random_choice(graph, adoption_rate):
    n = round(adoption_rate * len(graph.nodes))
    return random.sample(list(graph.nodes), n)


def degree_centrality(graph, adoption_rate):
    n = round(adoption_rate * len(graph.nodes))
    deployment = set()
    while len(deployment) < n:
        degrees = nx.degree_centrality(graph.subgraph(graph.nodes - deployment))
        deployment.add(max(degrees, key=lambda x: degrees[x]))
    return deployment


def kernighan_lin_partition(graph, adoption_rate):
    if adoption_rate == 0:
        return []
    last, parts = None, 2
    n = round(adoption_rate * len(graph.nodes))
    partition = [graph.nodes]
    while True:
        if len(partition) > parts:
            partition = [graph.nodes]
        while len(partition) < parts:
            new_partition = []
            for part in partition:
                new_partition.extend(list(nx.community.kernighan_lin_bisection(graph.subgraph(part))))
            partition = new_partition
        if last is None and parts > 2:
            for part in partition:
                b1 = nx.node_boundary(graph, part)
                b2 = nx.node_boundary(graph, graph.nodes - part)
                boundary = b1 if len(b1) < len(b2) else b2
                if len(boundary) < n:
                    return boundary | set(np.random.choice(list(graph.nodes - boundary),
                                          abs(n - len(boundary)), replace=False))
            parts *= 2
        elif parts == 2:
            b1 = nx.node_boundary(graph, partition[0])
            b2 = nx.node_boundary(graph, partition[1])
            boundary = b1 if len(b1) < len(b2) else b2
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
                return last | set(np.random.choice(list(graph.nodes - last),
                                  abs(n - len(last)), replace=False))


def compute_subsets(graph):
    rows = []
    for partition in nx.community.louvain_partitions(graph):
        for community in partition:
            inner = nx.node_boundary(graph, graph.nodes - community, community)
            outer = nx.node_boundary(graph, community)
            rows.append({"subset": community, "number_of_members": len(community),
                         "inner_boundary": inner, "inner_boundary_length": len(inner),
                         "outer_boundary": outer, "outer_boundary_length": len(outer)})
    return pd.DataFrame(rows).sort_values(by="number_of_members", ascending=False)


def louvain_communities(graph, adoption_rate):
    if adoption_rate == 0:
        return []
    n = round(adoption_rate * len(graph.nodes))
    subset_df = compute_subsets(graph)
    current_partition = [set(graph.nodes)]
    current_boundary = set()
    while current_partition:
        subset_df = subset_df[(subset_df.inner_boundary_length < (n - len(current_boundary))) |
                              (subset_df.outer_boundary_length < (n - len(current_boundary)))]
        for idx, row in subset_df[(subset_df.inner_boundary_length == 0) |
                                  (subset_df.outer_boundary_length == 0)].iterrows():
            current_partition.append(row["subset"])
            current_partition[[row["subset"] <= x for x in current_partition].index(True)] -= row["subset"]
            subset_df.drop(idx, axis=0, inplace=True)
        biggest = max(current_partition, key=len)
        candidates = subset_df[subset_df.subset < biggest]
        if len(candidates) == 1:
            try:
                new_df = compute_subsets(graph.subgraph(biggest))
            except Exception:
                new_df = None
            if new_df is None or len(new_df) < 2:
                final_big = biggest
                del current_partition[current_partition.index(final_big)]
                continue
            subset_df = pd.concat([subset_df, new_df], ignore_index=True)
            subset_df = subset_df.sort_values(by=["number_of_members"], ascending=False).reset_index(drop=True)
            candidates = subset_df
        new_subset, boundary = None, set()
        for idx, subset in candidates[candidates.number_of_members < (len(biggest) / 2)].iterrows():
            boundary = subset["inner_boundary"] if subset["inner_boundary_length"] < subset["outer_boundary_length"] else subset["outer_boundary"]
            if len(boundary) < (n - len(current_boundary)):
                new_subset = subset
                subset_df.drop(idx, axis=0, inplace=True)
                break
        if new_subset is None:
            del current_partition[current_partition.index(biggest)]
            continue
        idx = current_partition.index(biggest)
        current_partition[idx] -= new_subset["subset"]
        current_partition.append(new_subset["subset"])
        current_boundary |= boundary
        for col, bl in (("inner_boundary", "inner_boundary_length"),
                        ("outer_boundary", "outer_boundary_length")):
            subset_df[col] = subset_df[col].apply(lambda x: x - boundary)
            subset_df[bl] = subset_df[col].apply(len)
    return current_boundary | set(random.sample(list(set(graph.nodes) - current_boundary),
                                  n - len(current_boundary)))
