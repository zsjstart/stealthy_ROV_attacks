import time
from caida_collector_pkg.graph import AS
from bgp_simulator_pkg.simulation_engine.announcement import Announcement as Ann
from bgp_simulator_pkg.simulation_engine import SimulationEngine
from bgp_simulator_pkg.enums import Outcomes, ASTypes, Prefixes
from abc import ABC
from collections import defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict, List, Optional, Type
from copy import deepcopy

import matplotlib  # type: ignore
import matplotlib.pyplot as plt  # type: ignore

from .line import Line

from ..scenarios import Scenario

import sys
sys.path.append(
    '/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/bgp_simulator_pkg/bgp_simulator_pkg')

# ofile = open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/hi_max_len.res', 'w')

# ofile = open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/uRPF_attacks_assess.res', 'w')

# Must be module level in order to be picklable
# https://stackoverflow.com/a/16439720/8903959


def default_dict_inner_func():
    return defaultdict(list)


def default_dict_func():
    return defaultdict(default_dict_inner_func)


class Subgraph(ABC):
    """A subgraph for data display"""

    __slots__ = ("data",)  # type: ignore

    name: Optional[str] = None

    subclasses: List[Type["Subgraph"]] = []

    def __init_subclass__(cls, *args, **kwargs):
        """This method essentially creates a list of all subclasses
        This is allows us to know all attackers that have been created
        """

        super().__init_subclass__(*args, **kwargs)
        cls.subclasses.append(cls)
        names = [x.name for x in cls.subclasses if x.name]
        assert len(set(names)) == len(names), "Duplicate subgraph class names"

    def __init__(self):
        """Inits data"""

        # This is a list of all the trial info
        # You must save info trial by trial, so that you can join
        # After a return from multiprocessing
        # {propagation_round: {scenario_label: {percent_adopt: [percentages]}}}
        self.data: DefaultDict[int,
                               DefaultDict[str,
                                           DefaultDict[float,
                                                       List[float]]]] =\
            defaultdict(default_dict_func)

    ###############
    # Graph funcs #
    ###############

    def write_graphs(self, graph_dir: Path):
        """Writes all graphs into the graph dir"""

        for prop_round in self.data:
            self.write_graph(prop_round, graph_dir)

    def write_graph(self, prop_round: int, graph_dir: Path):
        """Writes graph into the graph directory"""

        lines: List[Line] = self._get_lines(prop_round)

        matplotlib.use("Agg")
        fig, ax = plt.subplots()
        # Set X and Y axis size
        plt.xlim(0, 100)
        plt.ylim(0, 100)
        # Add the data from the lines
        for line in lines:
            ax.errorbar(line.xs,
                        line.ys,
                        yerr=line.yerrs,
                        label=line.label)
        # Set labels
        ax.set_ylabel(self.y_axis_label)
        ax.set_xlabel(self.x_axis_label)

        # This is to avoid warnings
        handles, labels = ax.get_legend_handles_labels()
        ax.legend(handles, labels)
        plt.tight_layout()
        plt.rcParams.update({"font.size": 14, "lines.markersize": 10})
        plt.savefig(graph_dir / f"{self.name}.png")
        # https://stackoverflow.com/a/33343289/8903959
        plt.close(fig)

    def _get_lines(self, prop_round: int) -> List[Line]:
        """Returns lines for matplotlib graph"""

        return [Line(k, v) for k, v in self.data[prop_round].items()]

    @property
    def y_axis_label(self) -> str:
        """returns y axis label"""

        raise NotImplementedError

    @property
    def x_axis_label(self) -> str:
        """Returns X axis label"""

        return "Percent adoption of the adopted class"

    ##############
    # Data funcs #
    ##############

    def add_trial_info(self, other_subgraph: "Subgraph"):
        """Merges other subgraph into this one and combines the data

        This gets called when we need to merge all the subgraphs
        from the various processes that were spawned
        """

        for prop_round, scenario_dict in other_subgraph.data.items():
            for scenario_label, percent_dict in scenario_dict.items():
                for percent_adopt, trial_results in percent_dict.items():
                    self.data[prop_round][scenario_label][percent_adopt
                        ].extend(trial_results)  # noqa

    def aggregate_engine_run_data(self,
                                  shared_data: Dict[Any, Any],
                                  *,
                                  engine: SimulationEngine,
                                  percent_adopt: float,
                                  trial: int,
                                  scenario: Scenario,
                                  propagation_round: int):
        """Aggregates data after a single engine run

        Shared data is passed between subgraph classes and is
        mutable. This is done to speed up data aggregation, even
        though it is at the cost of immutability

        shared data is reset after every run

        shared_data ex:
        {stubs_hijacked: int,
         stubs_hijacked_total: int,
         stubs_hijacked_percentage: float,
         stubs_hijacked_adopting: int
         stubs_hijacked_adopting_total: int,
         stubs_hijacked_adopting_percentage: float,
         stubs_hijacked_non_adopting: int,
         stubs_hijacked_non_adopting_total: int
         stubs_hijacked_non_adopting_percentage: float,
         ...
         }

        self.data ex:
        {scenario_label: {percent_adopt: [percents]}}
        """

        if not shared_data.get("set"):
            # {as_obj: outcome}
            outcomes = self._get_engine_outcomes(engine, scenario)

            self._add_traceback_to_shared_data(shared_data,
                                               engine,
                                               scenario,
                                               outcomes)
        key = self._get_subgraph_key(scenario)
        self.data[propagation_round][scenario.graph_label][percent_adopt
            ].append(shared_data.get(key, 0))  # noqa

    def _get_subgraph_key(self, scenario: Scenario, *args: Any) -> str:
        """Returns the key to be used in shared_data on the subgraph"""

        raise NotImplementedError

    #####################
    # Shared data funcs #
    #####################

    def _add_traceback_to_shared_data(self,
                                      shared: Dict[Any, Any],
                                      engine: SimulationEngine,
                                      scenario: Scenario,
                                      outcomes: Dict[AS, Outcomes]):
        """Adds traceback info to shared data"""

        for as_obj, outcome in outcomes.items():
            as_type = self._get_as_type(as_obj)

            # TODO: refactor this ridiculousness into a class
            # Add to the AS type and policy, as well as the outcome

            # THESE ARE JUST KEYS, JUST GETTING KEYS/Strings HERE
            ##################################################################
            as_type_pol_k = self._get_as_type_pol_k(as_type, as_obj.__class__)
            # print('as_type_pol_k: ', as_type_pol_k)
            as_type_pol_outcome_k = self._get_as_type_pol_outcome_k(
                as_type, as_obj.__class__, outcome)
            # print('as_type_pol_outcome_k: ', as_type_pol_outcome_k)
            # as type + policy + outcome as a percentage
            as_type_pol_outcome_perc_k = self._get_as_type_pol_outcome_perc_k(
                as_type, as_obj.__class__, outcome)
            # print('as_type_pol_outcome_perc_k: ', as_type_pol_outcome_perc_k)
            ##################################################################

            # Add to the totals:
            for k in [as_type_pol_k, as_type_pol_outcome_k]:
                shared[k] = shared.get(k, 0) + 1
            # Set the new percent
            shared[as_type_pol_outcome_perc_k] = (
                shared[as_type_pol_outcome_k] *
                100 / shared[as_type_pol_k]
            )

            ############################
            # Track stats for all ASes #
            ############################

            # Keep track of totals for all ASes
            name = outcome.name
            total = shared.get(f"all_{name}", 0) + 1
            shared[f"all_{name}"] = total

            # Keep track of percentages for all ASes
            shared[f"all_{name}_perc"] = total * 100 / len(outcomes)

        shared["set"] = True

    def _get_as_type(self, as_obj: AS) -> ASTypes:
        """Returns the type of AS (stub_or_mh, input_clique, or etc)"""

        if as_obj.stub or as_obj.multihomed:
            return ASTypes.STUBS_OR_MH
        elif as_obj.input_clique:
            return ASTypes.INPUT_CLIQUE
        else:
            return ASTypes.ETC

    def _get_as_type_pol_k(self,
                           as_type: ASTypes,
                           ASCls: Type[AS]
                           ) -> str:
        """Returns AS type+policy key"""

        return f"{as_type.value}_{ASCls.name}"

    def _get_as_type_pol_outcome_k(self,
                                   as_type: ASTypes,
                                   ASCls: Type[AS],
                                   outcome: Outcomes) -> str:
        """returns as type+policy+outcome key"""

        return f"{self._get_as_type_pol_k(as_type, ASCls)}_{outcome.name}"

    def _get_as_type_pol_outcome_perc_k(self,
                                        as_type: ASTypes,
                                        ASCls: Type[AS],
                                        outcome: Outcomes) -> str:
        """returns as type+policy+outcome key as a percent"""

        x = self._get_as_type_pol_outcome_k(as_type, ASCls, outcome)
        return f"{x}_percent"

    ###################
    # Traceback funcs #
    ###################

    def _check_vulnerable_asn(self, urpf_asn, info, checked_asn, scenario: Scenario):
        found = False
        for provider in info[checked_asn]['providers']:
            if len(info[provider]['customers']) > 0 and (len(info[provider]['providers']) > 0 or len(info[provider]['peers']) > 0):

                for provider_provider in info[provider]['providers']:
                    most_specific_anns = self._get_most_specific_ann(
                        info[provider_provider]['obj'], scenario.ordered_prefix_subprefix_dict)

                    for ann in most_specific_anns:
                        if urpf_asn != ann.as_path[-1]:
                            continue
                        if provider not in ann.as_path:
                            continue
                        found = True
                        return found
                        # scenario.as2_set[urpf_asn].add(provider)
                        # scenario.as3_set[urpf_asn].add(provider_provider)

                for provider_peer in info[provider]['peers']:
                    most_specific_anns = self._get_most_specific_ann(
                        info[provider_peer]['obj'], scenario.ordered_prefix_subprefix_dict)
                    for ann in most_specific_anns:
                        if urpf_asn != ann.as_path[-1]:
                            continue
                        if provider not in ann.as_path:
                            continue
                        found = True
                        return found
                        # scenario.as2_set[urpf_asn].add(provider)
                        # scenario.as3_set[urpf_asn].add(provider_peer)

        return found

    def iterate_checking(self, checked_asn, urpf_asn, info, scenario: Scenario):
        providers = info[checked_asn]['providers']
        if len(providers) == 0:
            return
        if checked_asn != urpf_asn and self._check_vulnerable_asn(urpf_asn, info, checked_asn, scenario):
            scenario.indirect_vulnerable_urpf[urpf_asn] = True
            return

        for provider in providers:
            iterate_checking(provider, urpf_asn, info, scenario)

    def first_checking(self, urpf_asn, info, scenario: Scenario):
        providers = info[urpf_asn]['providers']
        if len(providers) == 0:
            return
        if self._check_vulnerable_asn(urpf_asn, info, urpf_asn, scenario):
            scenario.direct_vulnerable_urpf[urpf_asn] = True
            return

    def _get_customer_set(self, asn, info, customer_zone):
    	for customer in info[asn]['customers']:
    		customer_zone.add(customer)
    		self._get_customer_set(customer, info, customer_zone)

    def _get_engine_outcomes(self,
                             engine: SimulationEngine,
                             scenario: Scenario
                             ) -> Dict[AS, Outcomes]:
        """Gets the outcomes of all ASes"""

        # {ASN: outcome}
        
        '''
        # For uRPF
        outcomes: Dict[AS, Outcomes] = dict()

        info = defaultdict(dict)

        # f = open('./targeted_uRPF_attacks.dat', 'w')

        for i, as_obj in enumerate(engine.as_dict.values()):
            obj = as_obj.__to_yaml_dict__()
            info[as_obj.asn]['providers'] = obj['providers']
            info[as_obj.asn]['customers'] = obj['customers']
            info[as_obj.asn]['peers'] = obj['peers']
            info[as_obj.asn]['obj'] = as_obj

        urpf_asns = list(scenario.attacker_asns)
        customer_zone = set()

        for urpf_asn in urpf_asns:

            if urpf_asn not in info:  # Necessary code
                continue

            self.first_checking(urpf_asn, info, scenario)

            if scenario.direct_vulnerable_urpf.get(urpf_asn):
                for as2 in scenario.as2_set[urpf_asn]: scenario.as666_set[urpf_asn].update(
                    info[as2]['customers'])

                
                self._get_customer_set(urpf_asn, info, customer_zone)
                scenario.affected_customer_set[urpf_asn] = customer_zone

                continue

            self.iterate_checking(urpf_asn, urpf_asn, info, scenario)

            if scenario.indirect_vulnerable_urpf.get(urpf_asn):
                for as2 in scenario.as2_set[urpf_asn]:
                    scenario.as666_set[urpf_asn].update(info[as2]['customers'])
		 
		 
		 #self._get_customer_set(urpf_asn, info, customer_zone)
		 #scenario.affected_customer_set[urpf_asn] = customer_zone 
            
            
        return outcomes
        '''
        

        
        # For ROV
        outcomes: Dict[AS, Outcomes] = dict()
        for as_obj in engine.as_dict.values():
            # Gets AS outcome and stores it in the outcomes dict
            # self._get_as_outcome(as_obj, outcomes, engine, scenario)	
            self._get_as_outcome_v2(as_obj, engine, scenario)
            
        return outcomes
        
        

    def convert_to_as_obj(self, asn, engine: SimulationEngine):
        for as_obj in engine.as_dict.values():
            if as_obj.asn == asn:
                return as_obj
        return None

    def _get_as_outcome_v2(self, as_obj: AS, engine: SimulationEngine, scenario: Scenario):

        affected = False

        if as_obj.asn in scenario.output:
            affected = scenario.output[as_obj.asn]
            return affected

        # Get the most specific announcement in the rib
        most_specific_anns = self._get_most_specific_ann(
            as_obj, scenario.ordered_prefix_subprefix_dict)
        if len(most_specific_anns) == 0:
            scenario.num_no_anns = scenario.num_no_anns + 1

        # HERE NEED TO BE REMOVED; just used for stealth BGP hijacks
        # if have multiple prefixes, the most specific pprefix is chosen
        if len(most_specific_anns) == 2:
            new_anns = deepcopy(most_specific_anns)
            for most_specific_ann in new_anns:
                if most_specific_ann.prefix == Prefixes.PREFIX.value:
                    most_specific_anns.remove(most_specific_ann)

        # This has to be done in the scenario
        # Because only the scenario knows attacker/victim
        # And it's possible for scenario's to have multiple attackers
        # or multiple victims or different ways of determining outcomes

        if len(most_specific_anns) > 0 and (as_obj.asn not in scenario.attacker_asns) and (as_obj.asn not in scenario.victim_asns):
            
            for most_specific_ann in most_specific_anns:

                prefix = most_specific_ann.prefix
                
                if prefix == Prefixes.SUBPREFIX.value:
                    scenario.affected_prefixes[prefix].add(as_obj.asn)
                    
                    affected = True
                elif prefix == Prefixes.PREFIX.value:

                    as_path = most_specific_ann.as_path

                    for node in as_path[1:-1]:

                        if node in scenario.affected_asns:
                            affected = True
                            scenario.affected_prefixes[prefix].add(
                                as_obj.asn)
                            
                            scenario.affected_paths.add(as_path)
                            break
                        else:
                            node_as_obj = self.convert_to_as_obj(node, engine)
                            if node_as_obj != None:
                                if self._get_as_outcome_v2(node_as_obj, engine, scenario):
                                    affected = True
                                    scenario.affected_prefixes[prefix].add(
                                        as_obj.asn)
                                    scenario.affected_paths.add(as_path)
                                    break

        if affected:
            scenario.affected_asns.add(as_obj.asn)

        scenario.output[as_obj.asn] = affected

        return affected
        

    def _get_as_outcome_v3(self,
                        as_obj: AS,
                   
                        engine: SimulationEngine,
                        scenario: Scenario
                        ) -> Outcomes:
        """Recursively returns the as outcome"""
        
        most_specific_anns = self._get_most_specific_ann(
                as_obj, scenario.ordered_prefix_subprefix_dict)  # show the announcements seen in a given as obj
        
        if len(most_specific_anns) == 0:
        	scenario.output[as_obj.asn] = 'indirect'
        	return
        if len(most_specific_anns) == 2: print('Two announcements!!')
        for most_specific_ann in most_specific_anns:
        	asID = int(most_specific_ann.origin)
        	vrpID = int(most_specific_ann.roa_origin)
        	if asID != vrpID: scenario.output[as_obj.asn] = 'direct'
        	else: scenario.output[as_obj.asn] = 'no'
        		
        	
   
    def _get_as_outcome(self,
                        as_obj: AS,
                        outcomes: Dict[AS, Outcomes],
                        engine: SimulationEngine,
                        scenario: Scenario
                        ) -> Outcomes:
        """Recursively returns the as outcome"""

        if as_obj in outcomes:

            return outcomes[as_obj]
        else:
            # Get the most specific announcement in the rib
            most_specific_anns = self._get_most_specific_ann(
                as_obj, scenario.ordered_prefix_subprefix_dict)  # show the announcements seen in a given as obj

            # This has to be done in the scenario
            # Because only the scenario knows attacker/victim
            # And it's possible for scenario's to have multiple attackers
            # or multiple victims or different ways of determining outcomes
            n = 0  # Number of announcements

            if len(most_specific_anns) > 0:
                lens = list()

                asns = set()
                for most_specific_ann in most_specific_anns:
                    origin_as = engine.as_dict[
                        most_specific_ann.as_path[-1]  # type: ignore
                    ]  # type: ignore
                    # if as_obj.asn == origin_as.asn: continue
                    L = len(most_specific_ann.as_path)
                    lens.append(L)
                    asID = int(most_specific_ann.origin)
                    vrpID = int(most_specific_ann.roa_origin)
                    n = n + 1
                    prefix = most_specific_ann.prefix

                    # scenario.affected_asns[as_obj.asn].add(asID)

                # ofile.write(str(as_obj.asn)+','+str(max(lens))+'\n')
                scenario.output[as_obj.asn] = n
                outcome = scenario.my_determine_as_outcome(
                    origin_as, most_specific_ann)

            else:
                outcome = Outcomes.DISCONNECTED

            '''
            # We haven't traced back all the way on the AS path
            if outcome == Outcomes.UNDETERMINED:
                # next as in the AS path to traceback to
                # Ignore type because only way for this to be here
                # Is if the most specific Ann was NOT None.
                next_as = engine.as_dict[
                    most_specific_ann.as_path[1]  # type: ignore
                ]  # type: ignore
                
                outcome = self._get_as_outcome(next_as,
                                               outcomes,
                                               engine,
                                               scenario)
            assert outcome != Outcomes.UNDETERMINED, "Shouldn't be possible"
            '''

            outcomes[as_obj] = outcome
            return outcome

    def _get_most_specific_ann(self,
                               as_obj: AS,
                               ordered_prefixes: Dict[str, List[str]]
                               ) -> Optional[Ann]:
        """Returns the most specific announcement that exists in a rib

        as_obj is the as
        ordered prefixes are prefixes ordered from most specific to least
        """
        anns = set()

        for prefix in ordered_prefixes:
            most_specific_ann = as_obj._local_rib.get_ann(prefix)

            if most_specific_ann:
                # Mypy doesn't recognize that this is always an annoucnement
                anns.add(most_specific_ann)  # type: ignore

        return anns
