"""announce/sr_policy.py

SR Policy route announcement handler (RFC 9830).

Registers handlers for:
  ipv4 sr-policy
  ipv6 sr-policy

Created by Manoharan Sundaramoorthy 2026-05-01.
"""

from __future__ import annotations

from exabgp.bgp.message.update.attribute import Attributes
from exabgp.protocol.family import AFI, SAFI
from exabgp.rib.change import Change

from exabgp.configuration.announce import ParseAnnounce
from exabgp.configuration.static.sr_policy import sr_policy_route


def _build_sr_policy_route(tokeniser, afi: AFI) -> list[Change]:
    nlri, nexthop, tunnel_encap = sr_policy_route(tokeniser, afi)
    nlri.nexthop = nexthop
    attributes = Attributes()
    if tunnel_encap is not None:
        attributes.add(tunnel_encap)
    return [Change(nlri, attributes)]


@ParseAnnounce.register('sr-policy', 'extend-name', 'ipv4')
def sr_policy_ipv4(tokeniser):
    return _build_sr_policy_route(tokeniser, AFI.ipv4)


@ParseAnnounce.register('sr-policy', 'extend-name', 'ipv6')
def sr_policy_ipv6(tokeniser):
    return _build_sr_policy_route(tokeniser, AFI.ipv6)
