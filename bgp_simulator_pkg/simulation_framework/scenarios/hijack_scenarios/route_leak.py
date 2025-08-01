import sys
sys.path.append(
    '/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/bgp_simulator_pkg/bgp_simulator_pkg')

from bgp_simulator_pkg.enums import Timestamps, Relationships, Prefixes
from typing import Tuple, TYPE_CHECKING

from ..scenario import Scenario
from copy import deepcopy

if TYPE_CHECKING:
    from ....simulation_engine import Announcement

Info = {
    199599: (1622715055, '87.238.138.0/24', 51776, 51776, [8447]),
    265038: (1629390037, '2001:470:30::/48', 2033, 2033, [61832, 19151]),
    42313: (1657201320, '185.204.32.0/22', 205832, 205832, [6762, 1273, 50973, 21183]),
    42910: (1598268024, '37.75.9.0/24', 199484, 199484, [9121]),
    269601: (1657201320, '5.187.114.0/24', 21351, 21351, [16735, 21351]), #1659612328
    #7473: (1657133374, '110.224.240.0/20', 45609, 24560, [3491, 9498]),
    #13101: (1656310535, '5.160.125.0/24', 42337, 202616, [3356, 20940, 6762, 5511, 49666, 12880]),
    #4775: (1657469626, '112.198.30.0/24', 4797, 4797, [1299, 3491, 9299]),
    
}

'''
Info = {
    199599: (1622715055, '87.238.138.0/24', 51776, 51776, [8447]),
    132215: (1640334124, '103.86.40.0/24', 133275, 133275, [9583, 24029]),
    42910: (1598268024, '37.75.9.0/24', 199484, 199484, [9121]),
    13101: (1659378048, '5.160.125.0/24', 42337, 202616, [3356, 20940, 6762, 5511, 49666, 12880]),
    265766: (1656310535, '190.93.169.0/24', 262171, 28110, [395880]),
    7633: (1640364384, '164.100.54.0/23', 4758, 4758, [55836, 24029, 9885]),
}
'''


class RouteLeak(Scenario):

    __slots__ = ()

    def _get_announcements(self) -> Tuple["Announcement", ...]:
        """ victim asn is a provider asn of the attacker asn which exposes the anoucement from the victim to other provider
        """
        anns = list()
        attacker_asns = deepcopy(self.attacker_asns)
        for attacker_asn in attacker_asns:
            timestamp = Info[attacker_asn][0]
            prefix = Info[attacker_asn][1]
            victim_asn = Info[attacker_asn][2]
            roa_origin = Info[attacker_asn][3]
            transit_asns = Info[attacker_asn][4]
            self.victim_asns = {roa_origin}
            
            '''
            anns.append(self.AnnCls(prefix=prefix,
                                    as_path=(roa_origin,),
                                    timestamp=timestamp,
                                    seed_asn=roa_origin,
                                    roa_valid_length=True,
                                    roa_origin=roa_origin,
                                    recv_relationship=Relationships.ORIGIN))
            '''
            
            as_path = (victim_asn,)
            for transit_asn in reversed(transit_asns):
                as_path = (transit_asn,) + as_path
            anns.append(self.AnnCls(prefix=prefix,
                                    as_path=(attacker_asn,) + as_path,
                                    timestamp=timestamp,
                                    seed_asn=attacker_asn,
                                    roa_valid_length=True,
                                    roa_origin=roa_origin,
                                    recv_relationship=Relationships.LEAKER))
            
            
        return tuple(anns)
