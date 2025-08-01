# Step 1: Read AS relationships data
import torch
import numpy as np
from torch_geometric.data import Data

def setup_base_graph(file_path):
    """Parse AS relationship dataset."""
    edge_index = []
    edge_values = []
    as_set = set()

    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith("#"): continue
            if len(parts := line.strip().split("|")) < 3: continue

            as1, as2 = parts[0], parts[1]
            as_set.add(int(as1))
            as_set.add(int(as2))

    as_list = sorted(list(as_set))
            
    asn_to_index_mapping = {asn: index for index, asn in enumerate(as_list)}
    index_to_asn_mapping = {index: asn for index, asn in enumerate(as_list)}
    
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith("#"): continue
            if len(parts := line.strip().split("|")) < 3: continue

            as1, as2, rel = asn_to_index_mapping[int(parts[0])], asn_to_index_mapping[int(parts[1])], parts[2]
            edge_index.append([as1, as2])
            edge_values.append(int(rel))

    
    edge_index = np.array(edge_index, dtype=np.int64).T
    edge_values = np.array(edge_values, dtype=np.float32)
    
    return {
        "edge_index": edge_index,
        "edge_attr": edge_values,
        "x": np.zeros((len(asn_to_index_mapping), 1), dtype=np.float32)
    }, asn_to_index_mapping, index_to_asn_mapping


def set_node_data(base_data, as_mapping, infos):
    base_data = Data(**base_data)
    node_values = torch.zeros((len(as_mapping), 3), dtype=torch.float)
    
    for asn in map(int, infos["Adopting_asns"]):
        if asn not in as_mapping: continue
        node_values[as_mapping[asn], 0] = 1

    attacker_asn = int(infos["Attacker_asn"])
    victim_asn = int(infos["Victim_asn"])
    
    if attacker_asn in as_mapping: node_values[as_mapping[attacker_asn], 1] = 1
    if victim_asn in as_mapping: node_values[as_mapping[victim_asn], 2] = 1

    label = torch.zeros((len(as_mapping)), dtype=torch.long)

    for asn in map(int, infos["Indirectly_affected"]):
        if asn not in as_mapping: continue
        label[as_mapping[asn]] = 1   
    
    for asn in map(int, infos["Directly_affected"]):
        if asn not in as_mapping: continue
        label[as_mapping[asn]] = 2

    base_data.x = node_values
    base_data.y = label
    
    return base_data