"""announce/sr_policy.py

SR Policy route announcement handler (RFC 9830).

Registers handlers for:
  ipv4 sr-policy
  ipv6 sr-policy

Created by Manoharan Sundaramoorthy 2026-05-01.
"""

from __future__ import annotations

from exabgp.bgp.message.update.attribute import AttributeCollection
from exabgp.protocol.family import AFI, SAFI
from exabgp.rib.route import Route

from exabgp.configuration.announce import ParseAnnounce
from exabgp.configuration.core import Tokeniser
from exabgp.configuration.schema import ActionKey, ActionOperation, ActionTarget
from exabgp.configuration.static.sr_policy import sr_policy_route


def _build_sr_policy_route(tokeniser: Tokeniser, afi: AFI) -> list[Route]:
    nlri, nexthop, tunnel_encap = sr_policy_route(tokeniser, afi)
    attributes = AttributeCollection()
    if tunnel_encap is not None:
        attributes.add(tunnel_encap)
    return [Route(nlri, attributes, nexthop=nexthop)]


@ParseAnnounce.register_family(AFI.ipv4, SAFI.sr_policy, ActionTarget.SCOPE, ActionOperation.EXTEND, ActionKey.NAME)
def sr_policy_ipv4(tokeniser: Tokeniser) -> list[Route]:
    return _build_sr_policy_route(tokeniser, AFI.ipv4)


@ParseAnnounce.register_family(AFI.ipv6, SAFI.sr_policy, ActionTarget.SCOPE, ActionOperation.EXTEND, ActionKey.NAME)
def sr_policy_ipv6(tokeniser: Tokeniser) -> list[Route]:
    return _build_sr_policy_route(tokeniser, AFI.ipv6)
