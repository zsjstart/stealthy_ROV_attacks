import sys
sys.path.append(
    '/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/bgp_simulator_pkg/bgp_simulator_pkg')
from typing import Tuple, TYPE_CHECKING

from .scenario import Scenario
from bgp_simulator_pkg.enums import Prefixes, Relationships, Timestamps



if TYPE_CHECKING:
    from ...simulation_engine import Announcement


class OldValidPrefix(Scenario):
    """A valid prefix engine input, mainly for testing"""

    __slots__ = ()

    def _get_announcements(self) -> Tuple["Announcement", ...]:
        """Returns a valid prefix announcement
        for subclasses of this EngineInput, you can set AnnCls equal to
        something other than Announcement
        """

        anns = list()
        for victim_asn in self.victim_asns:
            anns.append(self.AnnCls(prefix=Prefixes.PREFIX.value,
                                    as_path=(victim_asn,),
                                    timestamp=Timestamps.VICTIM.value,
                                    seed_asn=victim_asn,
                                    roa_valid_length=True,
                                    roa_origin=victim_asn,
                                    recv_relationship=Relationships.ORIGIN))
        return tuple(anns)

    def _get_attacker_asns(self, *args, **kwargs):
        return None

