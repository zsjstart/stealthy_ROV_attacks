from ..scenario import Scenario
from typing import Tuple, TYPE_CHECKING
from collections import defaultdict
from bgp_simulator_pkg.enums import Prefixes, Relationships, Timestamps


if TYPE_CHECKING:
    from ....simulation_engine import Announcement


class PrefixHijack(Scenario):
    """Prefix hijack where both attacker and victim compete for a prefix, this calss can be used for valid"""

    #__slots__ = ()

    def __init__(self, AdoptASCls, attacker_asns, victim_asns, output, Info: defaultdict(set) = None):

        super().__init__(AdoptASCls=AdoptASCls, attacker_asns=attacker_asns,
                         victim_asns=victim_asns, output=output)
        self.Info: defaultdict(set) = Info

    def _get_announcements(self) -> Tuple["Announcement", ...]:
        """Returns the two announcements seeded for this engine input

        This engine input is for a prefix hijack,
        consisting of a valid prefix and invalid prefix

        for subclasses of this EngineInput, you can set AnnCls equal to
        something other than Announcement
        """

        anns = list()
        
        for attacker_asn in self.attacker_asns:
            
            for timestamp, prefix, roa_origin in self.Info[attacker_asn]:
                roa_valid_length = True
                self.victim_asns = {roa_origin}
                anns.append(self.AnnCls(prefix=prefix,
                                        as_path=(attacker_asn,),
                                        timestamp=timestamp,
                                        seed_asn=attacker_asn,
                                        roa_valid_length=roa_valid_length,
                                        roa_origin=roa_origin,
                                        recv_relationship=Relationships.ORIGIN))
        
        return tuple(anns)
