import os
from collections import deque
import networkx as nx

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def parse_as_relationships(file_path):
    """Parse an as-rel dataset: lines `as1|as2|rel`, rel = -1 (as1 provider of as2)
    or 0 (peers). '#' comments skipped."""
    edges, relas = [], {}
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith("#"):
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
        graph.nodes[node]["type"] = "transit" if node in has_customers else "edge"

    nx.set_node_attributes(graph, nx.degree_centrality(graph), "degree")
    try:
        nx.set_node_attributes(graph, nx.eigenvector_centrality(graph, max_iter=1000),
                               "eigenvector")
    except nx.PowerIterationFailedConvergence:
        pass


def create_graph(edge_file=None, infos=None, directed=False, special=False):
    """Create the AS graph. directed=True stores each relationship both ways
    (p2c -> -1 one way, +1 the other; peer -> 0 both). special=True keeps a single
    directed edge with abs(rel) (used only for customer-cone computation)."""
    if infos is None:
        infos = {}
    if edge_file is None:
        edge_file = os.path.join(ROOT_DIR, "network-graph-data", "as-rel.txt")

    edges, _ = parse_as_relationships(edge_file)
    graph = nx.DiGraph() if (directed or special) else nx.Graph()

    for as1, as2, rel in edges:
        if special:
            rel = abs(rel)
        graph.add_edge(as1, as2, relationship=rel)
        if directed and not special:
            graph.add_edge(as2, as1, relationship=-rel)

    if infos:
        rov_set = set(infos['Adopting_asns'])
        direct_set = set(infos['Directly_affected'])
        indirect_set = set(infos['Indirectly_affected'])
        for asn in graph.nodes:
            graph.nodes[asn]["ROV"] = 1 if asn in rov_set else 0
            graph.nodes[asn]["Attacker"] = 1 if asn == infos['Attacker_asn'] else 0
            graph.nodes[asn]["Victim"] = 1 if asn == infos['Victim_asn'] else 0
            label = 0
            if asn in indirect_set:
                label = 1
            if asn in direct_set:
                label = 2
            graph.nodes[asn]["y"] = label

    compute_graph_metadata(graph)
    return graph


# --------------------------------------------------------------------------
# Reference pure-Python impact (slow). Kept for cross-checking the fast engine.
# NOTE: run.py uses src.engine (C) instead — orders of magnitude faster and it
# resolves the up/down direction correctly on the *directed* graph.
# --------------------------------------------------------------------------
def find_reachable_nodes_bfs(graph, start_node, filter_rov=True, valley_free=True):
    queue = deque([(start_node, [], [])])
    visited = {start_node: ([], [])}
    while queue:
        current_node, used, path = queue.popleft()
        for neighbor in graph.neighbors(current_node):
            if neighbor in visited:
                continue
            relation = graph.get_edge_data(current_node, neighbor).get("relationship", None)
            if filter_rov and graph.nodes[neighbor].get('ROV', 0) == 1:
                continue
            if valley_free:
                if (0 in used or -1 in used) and relation in {0, 1}:
                    continue
            new_path = path + [current_node]
            new_used = used + [relation]
            visited[neighbor] = (tuple(new_path), tuple(new_used))
            queue.append((neighbor, new_used, new_path))
    return visited


def calculate_impact(graph, attacker, victim, valley_free_routing=True):
    directly = find_reachable_nodes_bfs(graph, attacker, valley_free=valley_free_routing)
    from_victim = find_reachable_nodes_bfs(graph, victim, filter_rov=False,
                                           valley_free=valley_free_routing)
    indirectly = set()
    for node in graph.nodes:
        if node in directly:
            continue
        path, _ = from_victim.get(node, ([], []))
        if len(path) > 0 and any(n in directly for n in path):
            indirectly.add(node)
    return len(directly) + len(indirectly), len(directly), len(indirectly)
