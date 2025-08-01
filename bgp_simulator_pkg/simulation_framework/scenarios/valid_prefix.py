from typing import Tuple, TYPE_CHECKING

from .scenario import Scenario

from bgp_simulator_pkg.enums import Prefixes, Relationships, Timestamps


if TYPE_CHECKING:
    from ...simulation_engine import Announcement

Info = {
    7922: (1640839441, '96.96.0.0/12', 7922),
    21928: (1640397286, '172.32.0.0/11', 21928),
    149555: (1655524398, '103.184.207.0/24', 149555),
    14618: (1654642769, '18.194.0.0/15', 14618),
    12389: (1640085874, '188.17.224.0/19', 12389),
}

class ValidPrefix(Scenario):
    """A valid prefix engine input, mainly for testing"""

    __slots__ = ()

    def _get_announcements(self) -> Tuple["Announcement", ...]:
        """Returns a valid prefix announcement

        for subclasses of this EngineInput, you can set AnnCls equal to
        something other than Announcement
        """

        anns = list()
        for attacker_asn in self.attacker_asns:
            timestamp = Info[attacker_asn][0]
            prefix = Info[attacker_asn][1]
            roa_origin = Info[attacker_asn][2]
            self.victim_asns = {roa_origin}
            
            anns.append(self.AnnCls(prefix=prefix,
                                    as_path=(roa_origin,),
                                    timestamp=timestamp,
                                    seed_asn=roa_origin,
                                    roa_valid_length=True,
                                    roa_origin=roa_origin,
                                    recv_relationship=Relationships.ORIGIN))
            
        return tuple(anns)

    def _get_attacker_asns(self, *args, **kwargs):
        return None
