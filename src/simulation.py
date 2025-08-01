from typing import List
from bgp_simulator_pkg.simulation_framework import Simulation
from bgp_simulator_pkg.simulation_framework.scenarios.hijack_scenarios import SubprefixHijack
from bgp_simulator_pkg.simulation_engine.as_classes.rov import ROVAS, ROVSimpleAS


def sim(
        adoption_rate: float, 
        deployment: List[int], 
        attacker: int, 
        victim: int, 
        trials: int = 10
    ):
    scenario = SubprefixHijack(AdoptASCls=ROVSimpleAS, attacker_asns=[attacker], victim_asns=[victim])
    scenario.set_adopting_asns(deployment)

    return Simulation(
        scenario=scenario, 
        percent_adoption=adoption_rate, 
        num_trials=trials, 
        propagation_rounds=1, 
        env=False
    ).step()