import gymnasium as gym
import json
import pickle
import multiprocessing
import pandas as pd
import numpy as np

from tqdm import tqdm
from src.helper import setup_base_graph
from bgp_simulator_pkg.enums import Prefixes
from .scenarios import Scenario
from .scenarios import SubprefixHijack
from .subgraphs import Subgraph
from bgp_simulator_pkg.simulation_engine import ROVAS, SimulationEngine, BGPSimpleAS

from copy import deepcopy
from itertools import product
from multiprocessing import Pool
from pathlib import Path
from shutil import make_archive
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Tuple
from collections import defaultdict
from caida_collector_pkg.caida_collector import CaidaCollector


class Simulation(gym.Env):
    """Runs simulations for BGP attack/defend scenarios"""

    def __init__(self,
                 percent_adoption: float = 0.05,  
                 scenario: Scenario = SubprefixHijack(AdoptASCls=ROVAS, attacker_asns=None, victim_asns=None), 
                 subgraphs: Tuple[Subgraph, ...] = tuple([Cls() for Cls in Subgraph.subclasses if Cls.name]),
                 num_trials: int = 100,
                 propagation_rounds: int = 1,
                 env: bool = True,
                 path: str = ""
                 ):
        super(Simulation, self).__init__()
        
        self.percent_adoption: float = percent_adoption

        self.subgraphs: Tuple[Subgraph, ...] = subgraphs

        self.propagation_rounds: int = propagation_rounds

        self.scenario = scenario

        self.save_path: Path = None

        # Done here so that the caida files are cached
        # So that multiprocessing doesn't interfere with one another
        # CaidaCollector().run()
        self.num_trials: int = num_trials
        self.env = env

        if env:
            assert path, "If env is true, path has to be set."

            self.base_observation, self.asn_to_index, self.index_to_asn = setup_base_graph(path)
            self.base_observation["x"][:, 0] = percent_adoption

            self.observation_space = gym.spaces.Dict({
                "x": gym.spaces.Box(low=-np.inf, high=np.inf, shape=self.base_observation["x"].shape, dtype=np.float32),
                "edge_index": gym.spaces.Box(low=-np.inf, high=np.inf, shape=self.base_observation["edge_index"].shape, dtype=np.int),
                "edge_attr": gym.spaces.Box(low=-np.inf, high=np.inf, shape=self.base_observation["edge_attr"].shape, dtype=np.float32)
            })

            self.action_space = gym.spaces.MultiBinary(self.base_observation["x"].shape[0])

    def reset(self, seed: int = 0):
        observation = self.get_observation()
        info = {}

        return observation, info

    def get_observation(self):
        if self.env:
            return self.base_observation
        else:
            return None

    def render(self):
        pass

    def close(self):
        pass

    def step(self, action = None):
        """Runs a chunk of trial inputs"""

        # Engine is not picklable or dillable AT ALL, so do it here
        # (after the multiprocess process has started)
        # Changing recursion depth does nothing
        # Making nothing a reference does nothing
        engine = CaidaCollector(BaseASCls=BGPSimpleAS,
                                GraphCls=SimulationEngine,
                                ).run(tsv_path=None)

        subgraphs = deepcopy(self.subgraphs)

        prev_scenario = None
        info_list = []

        if action is not None:
            action = np.where(np.array(action) > 0)[0]
            action = list(map(lambda x: self.index_to_asn[x], action))
        
        for trial in tqdm(range(0, self.num_trials)):
            # Deep copy scenario to ensure it's fresh
            # Since certain things like announcements change round to round
            scenario = deepcopy(self.scenario)

            # Change AS Classes, seed announcements before propagation
            
            if action is not None:
                scenario.set_adopting_asns(action)
            
            scenario.setup_engine(engine, self.percent_adoption, prev_scenario)
            impact_score = 0

            for propagation_round in range(0, 1):
                print("HI")
                engine.run(propagation_round=propagation_round, scenario=scenario)
                print("SDF")
                kwargs = {
                    "engine": engine,
                    "percent_adopt": self.percent_adoption,
                    "trial": trial,
                    "scenario": scenario,
                    "propagation_round": propagation_round
                }
                # Save all engine run info
                # The reason we aggregate info right now, instead of saving
                # the engine and doing it later, is because doing it all
                # in RAM is MUCH faster, and speed is important

                self._aggregate_engine_run_data(subgraphs, **kwargs)
                # By default, this is a no op
                scenario.post_propagation_hook(**kwargs)

            if self.env:
                directly_affected = list(scenario.affected_prefixes[Prefixes.SUBPREFIX.value])
                indirectly_affected = list(scenario.affected_prefixes[Prefixes.PREFIX.value])

                affected_paths = list(scenario.affected_paths)

                impact_score += len(directly_affected) + len(indirectly_affected) + len(affected_paths)
            else:
                infos = {}
                infos['adopting_asns'] = scenario.adopting_asns
                infos['attacker_asn'] = list(scenario.attacker_asns)[0]
                infos['victim_asn'] = list(scenario.victim_asns)[0]
                infos['directly_affected'] = list(scenario.affected_prefixes[Prefixes.SUBPREFIX.value])
                infos['indirectly_affected'] = list(scenario.affected_prefixes[Prefixes.PREFIX.value])
                infos['vulnerable_paths'] = list(scenario.affected_paths)

                info_list.append(infos)

            prev_scenario = scenario


        if self.env:
            terminated = True
            reward = -(impact_score / self.num_trials)
            observation = self.get_observation()
            info = {}

            return observation, reward, terminated, False, info
        else:
            return info_list

    def _aggregate_engine_run_data(self,
                                   subgraphs: Tuple[Subgraph, ...],
                                   **kwargs):
        """For each subgraph, aggregate data

        Some data aggregation is shared to speed up runs
        For example, traceback might be useful across
        Multiple subgraphs
        """

        shared_data: Dict[Any, Any] = dict()
        for subgraph in subgraphs:
            subgraph.aggregate_engine_run_data(shared_data, **kwargs)
