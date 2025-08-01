import os
import pickle
import torch
import re
import bz2
import requests

from src.helper import set_node_data, setup_base_graph
from bs4 import BeautifulSoup
from pathlib import Path
from typing import List
from tqdm import tqdm
from bgp_simulator_pkg.simulation_framework import Simulation
from bgp_simulator_pkg.simulation_framework.scenarios.hijack_scenarios import SubprefixHijack
from torch_geometric.data import Data, Dataset, InMemoryDataset


class NetworkGraphDataset(Dataset):
    def __init__(
            self, 
            root, 
            steps: int = 5,
            num_of_deployments: int = 100,
            attacks_per_deployment: int = 20,
            transform=None, 
            pre_transform=None):
        
        super().__init__(root, transform, pre_transform)
        self.steps = steps
        self.num_of_deployments = num_of_deployments
        self.attacks_per_deployment = attacks_per_deployment

    @property
    def raw_file_names(self):
        return os.listdir(self.raw_dir)

    @property
    def processed_file_names(self):
        return list(map(lambda x: x.replace(".pkl", ".pt"), self.raw_file_names))

    def download(self):
        html = requests.get("https://publicdata.caida.org/datasets/as-relationships/serial-2/").text
        soup = BeautifulSoup(html, "html.parser")
        
        most_recent_link = soup.findAll("a", string=re.compile(r".*rel2.txt.bz2"))[-1]
        response = requests.get("https://publicdata.caida.org/datasets/as-relationships/serial-2/" + most_recent_link["href"])
        text = bz2.decompress(response.content)
        
        with open(self.root + "as-rel.txt", "w") as f:
            f.write(text.decode("utf-8"))

        adoption_rates = range(0, 100, self.steps)

        for adoption_rate in map(lambda x: x / 100, adoption_rates):
            adoption_rate = adoption_rate / 100

            simulation = Simulation(
                    scenario=SubprefixHijack(), 
                    percent_adoption=0, 
                    num_trials=self.attacks_per_deployment, 
                    propagation_rounds=1, 
                    env=False
            )

            for deploy in self.num_of_deployments:
                if Path(self.raw_dir + f"ROV_{adoption_rate}_{deploy}_{idx}.pkl").is_file(): continue

                info_list = simulation.run() 

                for idx, info in enumerate(info_list):
                    pickle.dump(info, open(self.raw_dir + f"ROV_{adoption_rate}_{deploy}_{idx}.pkl", "wb"))

    def process(self):
        if Path(self.processed_paths[0]).is_file(): return

        edge_index, edge_values, as_mapping, _ = setup_base_graph(self.root + "/as-rel.txt")
        
        for idx, file_path in tqdm(enumerate(self.raw_paths)):
            if not Path(file_path).is_file(): continue

            with open(file_path, 'rb') as ifile:
                infos = pickle.load(ifile)

            torch.save(set_node_data(edge_index, edge_values, as_mapping, infos), self.processed_paths[idx])

    def get(self, idx):
        return torch.load(self.processed_paths[idx])

    def len(self):
        return len(self.processed_file_names)