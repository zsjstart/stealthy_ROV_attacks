import networkx as nx

from collections import deque
import os

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Step 1: Read AS relationships data
def parse_as_relationships(file_path):
    """Parse AS relationship dataset."""
    edges = []
    relas = dict()
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith("#"):  # Skip comments
                continue
            parts = line.strip().split('|')
            if len(parts) < 3:
                continue
            as1, as2, rel = parts[0], parts[1], int(parts[2])
            edges.append((as1, as2, rel))
            relas[(as1, as2)] = rel
    return edges, relas


def compute_graph_metadata(graph):
    has_customers = set()
    for u, v, data in graph.edges(data=True):
        if data.get("relationship") == -1:
            has_customers.add(u)

    for node in graph.nodes:
        graph.nodes[node]["ROV"] = 0
        if node in has_customers:
            graph.nodes[node]["type"] = "transit"
        else:
            graph.nodes[node]["type"] = "edge"

    nx.set_node_attributes(graph, nx.degree_centrality(graph), "degree")
    nx.set_node_attributes(graph, nx.eigenvector_centrality(graph), "eigenvector")


def create_graph(
        edge_file: str = None, 
        infos: object = {}, 
        directed: bool = False, 
        special: bool = False,
    ):
    
    if edge_file is None:
        edge_file = os.path.join(ROOT_DIR, "network-graph-data", "cached.txt")
        
    edges, _ = parse_as_relationships(edge_file)
    """Create a filtered graph based on specific AS paths."""
    if directed or special:
        graph = nx.DiGraph()
    else:
        graph = nx.Graph()
    
    for as1, as2, rel in edges:
        # -1 for provider-to-customer, 0 for peer-to-peer
        if special:
            rel = abs(rel)
        graph.add_edge(as1, as2, relationship=rel)
        if directed and not special:
            graph.add_edge(as2, as1, relationship=-rel)
        
    if infos:
        # Convert lists to sets for faster lookup
        rov_asns_set = set(infos['Adopting_asns'])
        directly_affected_set = set(infos['Directly_affected'])
        indirectly_affected_set = set(infos['Indirectly_affected'])
        
        for asn in graph.nodes:
            graph.nodes[asn]["ROV"] = 1 if asn in rov_asns_set else 0
            graph.nodes[asn]["Attacker"] = 1 if asn == infos['Attacker_asn'] else 0
            graph.nodes[asn]["Victim"] = 1 if asn == infos['Victim_asn'] else 0
            
            label = 0

            if asn in indirectly_affected_set:
                label = 1
            if asn in directly_affected_set:
                label = 2

            graph.nodes[asn]["y"] = label
    compute_graph_metadata(graph)

    return graph


def find_reachable_nodes_bfs(graph, start_node, filter_rov=True, valley_free=True):
    queue = deque([(start_node, [], [])])
    visited = {start_node: ([], [])}

    while queue:
        current_node, used_peer_to_peer, path = queue.popleft()

        for neighbor in graph.neighbors(current_node):
            if neighbor in visited:
                continue

            relation = graph.get_edge_data(current_node, neighbor).get("relationship", None)

            # Skip nodes with ROV = 1
            if filter_rov and graph.nodes[neighbor].get('ROV', 0) == 1:
                continue

            # Valley-free routing checks
            if valley_free:
                has_peer_to_peer = 0 in used_peer_to_peer
                has_downstream = -1 in used_peer_to_peer

                if has_peer_to_peer and relation in {0, 1}:
                    continue
                if has_downstream and relation in {0, 1}:
                    continue

            # Update path and peer-to-peer usage efficiently
            new_path = path + [current_node]
            new_used_peer_to_peer = used_peer_to_peer + [relation]

            visited[neighbor] = (tuple(new_path), tuple(new_used_peer_to_peer))
            queue.append((neighbor, new_used_peer_to_peer, new_path))

    return visited


def calculate_impact(graph, attacker, victim, valley_free_routing: bool = True):
    directly_impacted = find_reachable_nodes_bfs(graph, attacker, valley_free=valley_free_routing)
    reachable_from_victim = find_reachable_nodes_bfs(graph, victim, filter_rov=False, valley_free=valley_free_routing)

    indirectly_impacted = set()

    for node in graph.nodes:
        if node in directly_impacted: continue

        path, _ = reachable_from_victim.get(node, ([], []))
        
        if len(path) > 0 and (any([n in directly_impacted for n in path])):
            indirectly_impacted.add(node)


    return len(directly_impacted) + len(indirectly_impacted), len(directly_impacted), len(indirectly_impacted)