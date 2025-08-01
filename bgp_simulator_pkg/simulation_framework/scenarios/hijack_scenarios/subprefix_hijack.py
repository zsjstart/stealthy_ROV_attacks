import random
from bgp_simulator_pkg.enums import Prefixes, Relationships, Timestamps

from ..scenario import Scenario


class SubprefixHijack(Scenario):
    """Subprefix Hijack Engine input

    Subprefix hijack consists of a valid prefix by the victim with a roa
    then a subprefix from an attacker
    invalid by roa by length and origin
    """

    __slots__ = ()
    
    #for ROV
    def _get_announcements(self):
        """Returns victim and attacker anns for subprefix hijack

        for subclasses of this EngineInput, you can set AnnCls equal to
        something other than Announcement
        """

        anns = list()
        
        for victim_asn in self.victim_asns:
            
            anns.append(self.AnnCls(prefix=Prefixes.PREFIX.value,  #PREFIX
                                    as_path=(victim_asn,),
                                    timestamp=Timestamps.VICTIM.value,
                                    seed_asn=victim_asn,
                                    roa_valid_length=True,
                                    roa_origin=victim_asn,
                                    recv_relationship=Relationships.ORIGIN))

        err: str = "Fix the roa_origins of the " \
                   "announcements for multiple victims"
        assert len(self.victim_asns) == 1, err
        
        roa_origin: int = next(iter(self.victim_asns))
        #print('roa_origin: ', roa_origin)
        for attacker_asn in self.attacker_asns:
            #print('attacker_asn: ', attacker_asn)
            anns.append(self.AnnCls(prefix=Prefixes.SUBPREFIX.value, #PREFIX HIJACK
                                    as_path=(attacker_asn,),
                                    timestamp=Timestamps.ATTACKER.value,
                                    seed_asn=attacker_asn,
                                    roa_valid_length=False,
                                    roa_origin=roa_origin,
                                    recv_relationship=Relationships.ORIGIN))

        return tuple(anns)
    
    # Adopting asns is a dict of category to asns
    def set_adopting_asns(self, adopting_asns):
        self.adopting_asns = adopting_asns

    def get_possible_adopters(self, engine):
        possible_adopters = []

        for subcategory in ("stub_or_mh_asns", "etc_asns", "input_clique_asns"):
            asns = getattr(engine, subcategory)
            possible_adopters.extend(asns.difference(self._preset_asns))
        
        return possible_adopters

    def _get_adopting_asns_dict(self, engine, percent_adopt):
        """Get adopting ASNs

        By default, to get even adoption, adopt in each of the three
        subcategories
        """
        adopting_asns = list()
        subcategories = ("stub_or_mh_asns", "etc_asns", "input_clique_asns")
        
        if self.adopting_asns:
            adopting_asns = self.adopting_asns
        else:
            for subcategory in subcategories:
                asns = getattr(engine, subcategory)
                possible_adopters = asns.difference(self._preset_asns)

                # https://stackoverflow.com/a/15837796/8903959
                possible_adopters = tuple(possible_adopters)
                #random.seed(1)
                if subcategory == "stub_or_mh_asns":
                    pass
                elif subcategory == "etc_asns":
                    print(len(possible_adopters))
                    adopters = random.sample(possible_adopters, round(len(possible_adopters) * percent_adopt))
                    print(len(adopters))
                    adopting_asns.extend(adopters)
                else:
                    print(len(possible_adopters))
                    adopting_asns.extend(possible_adopters)

        # adopting_asns += self._default_adopters
        assert len(adopting_asns) == len(set(adopting_asns))
        
        self.adopting_asns = adopting_asns
        print('Networks adopting asns: ', len(self.adopting_asns))
        return {asn: self.AdoptASCls for asn in adopting_asns}