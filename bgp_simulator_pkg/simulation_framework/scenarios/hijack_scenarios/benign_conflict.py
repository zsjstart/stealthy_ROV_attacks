from ..scenario import Scenario
from collections import defaultdict
from typing import Tuple, TYPE_CHECKING, Optional
from bgp_simulator_pkg.enums import Prefixes, Relationships, Timestamps


if TYPE_CHECKING:
    from ....simulation_engine import Announcement


class BenignConflict(Scenario):
    """benign conflict"""

    #__slots__ = ("Info")

    def __init__(self, AdoptASCls, attacker_asns, victim_asns, output, Info: defaultdict(set) = None):

        super().__init__(AdoptASCls=AdoptASCls, attacker_asns=attacker_asns,
                         victim_asns=victim_asns, output=output)
        self.Info: defaultdict(set) = Info

    def _get_announcements(self) -> Tuple["Announcement", ...]:
        """
        for subclasses of this EngineInput, you can set AnnCls equal to
        something other than Announcement
        """

        anns = list()
        #for attacker_asn in self.attacker_asns:
        for pfx in self.pfxs:
            for timestamp, prefix, attacker_asn, roa_origin in self.Info[pfx]:
                '''
                timestamp = self.Info[attacker_asn][0]
                prefix = self.Info[attacker_asn][1]
                roa_origin = self.Info[attacker_asn][2]
                '''
                #roa_valid_length = self.Info[attacker_asn][3]
                roa_valid_length = False
                self.victim_asns = {roa_origin}
                anns.append(self.AnnCls(prefix=prefix,
                                        as_path=(attacker_asn,),
                                        timestamp=timestamp,
                                        seed_asn=attacker_asn,
                                        roa_valid_length=roa_valid_length,
                                        roa_origin=roa_origin,
                                        recv_relationship=Relationships.ORIGIN))
        print('The number of anns sent:', len(anns))
        return tuple(anns)
