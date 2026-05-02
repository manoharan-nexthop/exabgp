"""configuration/static/sr_policy.py

Parser functions for SR Policy NLRI and Tunnel Encapsulation attributes.

Inline command syntax:
  announce ipv4 sr-policy distinguisher 0 color 100 endpoint 1.2.3.4 \\
      next-hop 5.6.7.8 \\
      preference 100 \\
      binding-sid mpls 24000 \\
      srv6-binding-sid fc00::1 \\
      segment-list weight 1 segment type-a mpls 16001 segment type-a mpls 16002 \\
      segment-list weight 2 segment type-b srv6 fc00::1 endpoint-behavior 65 32 0 16 0 \\
      priority 10 \\
      policy-name "my-policy" \\
      candidate-path-name "primary"

Created by Manoharan Sundaramoorthy 2026-05-01.
"""

from __future__ import annotations

from typing import Any

from exabgp.bgp.message.update.attribute.tunnel_encap import TunnelEncap
from exabgp.bgp.message.update.attribute.tunnel_encap.sr_policy import (
    BindingSIDSubTLV,
    CandidatePathNameSubTLV,
    PolicyNameSubTLV,
    PreferenceSubTLV,
    PrioritySubTLV,
    SRPolicyTunnel,
    SRv6BindingSIDSubTLV,
    SegmentListSubTLV,
)
from exabgp.bgp.message.update.attribute.tunnel_encap.sr_policy.segment_list import (
    SegmentTypeA,
    SegmentTypeB,
    SRv6EndpointBehavior,
    WeightSubSubTLV,
)
from exabgp.bgp.message.update.nlri.sr_policy import SRPolicyNLRI
from exabgp.protocol.family import AFI
from exabgp.protocol.ip import IP

_MPLS_LABEL_MAX = 1048575  # 2^20 - 1


def _parse_segment_list(tokeniser: Any) -> SegmentListSubTLV:
    """Parse: weight <N> [segment type-a mpls <label> ...] [segment type-b srv6 <sid> ...]"""
    tokeniser.consume('weight')
    weight_val = int(tokeniser())
    weight = WeightSubSubTLV(weight=weight_val)

    segments: list[SegmentTypeA | SegmentTypeB] = []

    while tokeniser.peek() == 'segment':
        tokeniser()  # consume 'segment'
        seg_type = tokeniser()
        if seg_type == 'type-a':
            tokeniser.consume('mpls')
            label = int(tokeniser())
            if label < 0 or label > _MPLS_LABEL_MAX:
                raise ValueError(f'MPLS label {label} out of range (0-{_MPLS_LABEL_MAX})')
            segments.append(SegmentTypeA(label=label))
        elif seg_type == 'type-b':
            tokeniser.consume('srv6')
            sid = tokeniser()
            # Check for optional endpoint-behavior
            eb: SRv6EndpointBehavior | None = None
            if tokeniser.peek() == 'endpoint-behavior':
                tokeniser()  # consume 'endpoint-behavior'
                behavior = int(tokeniser(), 0)  # allow 0x prefix
                lb = int(tokeniser())
                ln = int(tokeniser())
                fun = int(tokeniser())
                arg = int(tokeniser())
                eb = SRv6EndpointBehavior(
                    endpoint_behavior=behavior,
                    lb_length=lb,
                    ln_length=ln,
                    fun_length=fun,
                    arg_length=arg,
                )
            segments.append(SegmentTypeB(sid=sid, endpoint_behavior=eb))
        else:
            raise ValueError(f"Unknown segment type '{seg_type}'. Expected: type-a, type-b")

    return SegmentListSubTLV(weight=weight, segments=segments)


def _parse_sr_policy_subtlvs(tokeniser: Any) -> list[Any]:
    """Parse SR Policy sub-TLVs from inline token stream.

    Reads: preference, binding-sid, srv6-binding-sid, priority, policy-name,
           candidate-path-name, segment-list (repeatable).
    Stops when no known keyword is next.
    """
    subtlvs: list[Any] = []
    _SR_KEYS = {
        'preference',
        'priority',
        'binding-sid',
        'srv6-binding-sid',
        'policy-name',
        'candidate-path-name',
        'segment-list',
    }

    while tokeniser.peek() in _SR_KEYS:
        key = tokeniser()
        if key == 'preference':
            subtlvs.append(PreferenceSubTLV(preference=int(tokeniser())))
        elif key == 'priority':
            subtlvs.append(PrioritySubTLV(priority=int(tokeniser())))
        elif key == 'binding-sid':
            bsid_type = tokeniser()
            if bsid_type == 'mpls':
                label = int(tokeniser())
                subtlvs.append(BindingSIDSubTLV(label=label))
            elif bsid_type == 'null':
                subtlvs.append(BindingSIDSubTLV(label=None))
            else:
                raise ValueError(f"Unknown binding-sid type '{bsid_type}'. Expected: mpls, null")
        elif key == 'srv6-binding-sid':
            sid = tokeniser()
            subtlvs.append(SRv6BindingSIDSubTLV(sid=sid))
        elif key == 'policy-name':
            name = tokeniser().strip('"').strip("'")
            subtlvs.append(PolicyNameSubTLV(name=name))
        elif key == 'candidate-path-name':
            name = tokeniser().strip('"').strip("'")
            subtlvs.append(CandidatePathNameSubTLV(name=name))
        elif key == 'segment-list':
            subtlvs.append(_parse_segment_list(tokeniser))

    return subtlvs


def sr_policy_route(tokeniser: Any, afi: AFI) -> tuple[SRPolicyNLRI, IP, TunnelEncap | None]:
    """Parse SR Policy route from inline token stream.

    Reads:
      distinguisher <N> color <N> endpoint <IP>
      next-hop <IP>
      [preference <N>] [priority <N>] [binding-sid mpls <N>] [srv6-binding-sid <SID>]
      [segment-list weight <N> segment type-a mpls <N> ...] (repeatable)
      [policy-name <str>] [candidate-path-name <str>]

    Returns:
      (nlri, nexthop, tunnel_encap_or_None)
    """
    tokeniser.consume('distinguisher')
    distinguisher = int(tokeniser())
    tokeniser.consume('color')
    color = int(tokeniser())
    tokeniser.consume('endpoint')
    endpoint = tokeniser()

    nlri = SRPolicyNLRI.create(afi=afi, distinguisher=distinguisher, color=color, endpoint=endpoint)

    tokeniser.consume('next-hop')
    nexthop = IP.from_string(tokeniser())

    subtlvs = _parse_sr_policy_subtlvs(tokeniser)

    tunnel_encap: TunnelEncap | None = None
    if subtlvs:
        tunnel_encap = TunnelEncap(tunnel_tlvs=[SRPolicyTunnel(subtlvs=subtlvs)])

    return nlri, nexthop, tunnel_encap
