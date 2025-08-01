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
    #7473: (1657133374, '110.224.240.0/20', 45609, 24560, [3491, 9498]),
    13101: (1656310535, '5.160.125.0/24', 42337, 202616, [3356, 20940, 6762, 5511, 49666, 12880]), #1659378048
    265766: (1656310535, '190.93.169.0/24', 262171, 28110, [395880]),
    60299: (1657133374, '45.146.43.0/24', 47726, 0, [35168, 28910, 34250]), # 1658237217, 0: unknown
    270771: (1657133374, '24.181.189.10/32', 271380, 0, []), # 1658396242 0: unknown
    21277: (1657133374,'24.154.91.141/32', 212338, 0, [207701, 208293, 42705]), # 1658405711
    
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


class HybridLeak(Scenario):

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
