"""tests/unit/test_sr_policy.py

Unit tests for SR Policy NLRI and Tunnel Encap attribute (RFC 9830 / RFC 9012).
"""

from __future__ import annotations


from exabgp.bgp.message.update.attribute.tunnel_encap import TunnelEncap
from exabgp.bgp.message.update.attribute.tunnel_encap.sr_policy import (
    BindingSIDSubTLV,
    CandidatePathNameSubTLV,
    PolicyNameSubTLV,
    PreferenceSubTLV,
    PrioritySubTLV,
    SegmentListSubTLV,
    SRPolicyTunnel,
    SRv6BindingSIDSubTLV,
)
from exabgp.bgp.message.update.attribute.tunnel_encap.sr_policy.segment_list import (
    SegmentTypeA,
    SegmentTypeB,
    SRv6EndpointBehavior,
    WeightSubSubTLV,
)
from exabgp.bgp.message.update.nlri.sr_policy import SRPolicyNLRI
from exabgp.protocol.family import AFI, SAFI


# ============================================================= SAFI


def test_safi_sr_policy_value():
    assert int(SAFI.sr_policy) == 73


def test_safi_sr_policy_name():
    assert SAFI.sr_policy.name() == 'sr-policy'


def test_afi_implemented_safi_includes_sr_policy():
    assert 'sr-policy' in AFI.implemented_safi('ipv4')
    assert 'sr-policy' in AFI.implemented_safi('ipv6')


# ============================================================= SRPolicyNLRI


def test_sr_policy_nlri_ipv4_create():
    nlri = SRPolicyNLRI.create(AFI.ipv4, distinguisher=0, color=100, endpoint='1.2.3.4')
    assert nlri.distinguisher == 0
    assert nlri.color == 100
    assert nlri.endpoint == '1.2.3.4'
    assert nlri.afi == AFI.ipv4
    assert nlri.safi == SAFI.sr_policy


def test_sr_policy_nlri_ipv6_create():
    nlri = SRPolicyNLRI.create(AFI.ipv6, distinguisher=1, color=200, endpoint='2001:db8::1')
    assert nlri.distinguisher == 1
    assert nlri.color == 200
    assert nlri.endpoint == '2001:db8::1'
    assert nlri.afi == AFI.ipv6


def test_sr_policy_nlri_ipv4_pack_unpack():
    nlri = SRPolicyNLRI.create(AFI.ipv4, distinguisher=42, color=999, endpoint='10.0.0.1')
    packed = nlri.pack_nlri(None)
    assert len(packed) == 12  # 4 + 4 + 4

    nlri2, remaining = SRPolicyNLRI.unpack_nlri(AFI.ipv4, SAFI.sr_policy, packed, None, None, None)
    assert remaining == b''
    assert isinstance(nlri2, SRPolicyNLRI)
    assert nlri2.distinguisher == 42
    assert nlri2.color == 999
    assert nlri2.endpoint == '10.0.0.1'


def test_sr_policy_nlri_ipv6_pack_unpack():
    nlri = SRPolicyNLRI.create(AFI.ipv6, distinguisher=0, color=500, endpoint='fc00::1')
    packed = nlri.pack_nlri(None)
    assert len(packed) == 24  # 4 + 4 + 16

    nlri2, remaining = SRPolicyNLRI.unpack_nlri(AFI.ipv6, SAFI.sr_policy, packed, None, None, None)
    assert remaining == b''
    assert nlri2.distinguisher == 0
    assert nlri2.color == 500
    assert nlri2.endpoint == 'fc00::1'


def test_sr_policy_nlri_str():
    nlri = SRPolicyNLRI.create(AFI.ipv4, 0, 100, '1.2.3.4')
    assert 'distinguisher 0' in str(nlri)
    assert 'color 100' in str(nlri)
    assert 'endpoint 1.2.3.4' in str(nlri)


def test_sr_policy_nlri_eq():
    n1 = SRPolicyNLRI.create(AFI.ipv4, 0, 100, '1.2.3.4')
    n2 = SRPolicyNLRI.create(AFI.ipv4, 0, 100, '1.2.3.4')
    n3 = SRPolicyNLRI.create(AFI.ipv4, 0, 200, '1.2.3.4')
    assert n1 == n2
    assert n1 != n3


# ============================================================= Preference


def test_preference_subtlv_pack_unpack():
    tlv = PreferenceSubTLV(preference=100)
    packed = tlv.pack()
    # type(1) + length(2) + flags(4) + preference(4) = 11 bytes
    assert len(packed) == 11
    assert packed[0] == 12  # SUBTYPE

    tlv2 = PreferenceSubTLV.unpack(packed[3:])  # skip header
    assert tlv2.preference == 100


def test_preference_subtlv_json():
    tlv = PreferenceSubTLV(preference=200)
    assert '"preference": 200' in tlv.json()


# ============================================================= Priority


def test_priority_subtlv_pack_unpack():
    tlv = PrioritySubTLV(priority=10)
    packed = tlv.pack()
    assert len(packed) == 5  # type(1) + length(2) + priority(1) + reserved(1)
    assert packed[0] == 15

    tlv2 = PrioritySubTLV.unpack(packed[3:])
    assert tlv2.priority == 10


# ============================================================= Policy Name


def test_policy_name_subtlv_pack_unpack():
    tlv = PolicyNameSubTLV(name='test-policy')
    packed = tlv.pack()
    # type(1) + length(2) + flags(1) + name_bytes
    assert packed[0] == 129

    tlv2 = PolicyNameSubTLV.unpack(packed[3:])
    assert tlv2.name == 'test-policy'


# ============================================================= Candidate Path Name


def test_candidate_path_name_subtlv_pack_unpack():
    tlv = CandidatePathNameSubTLV(name='primary')
    packed = tlv.pack()
    assert packed[0] == 130

    tlv2 = CandidatePathNameSubTLV.unpack(packed[3:])
    assert tlv2.name == 'primary'


# ============================================================= Binding SID


def test_binding_sid_mpls_pack_unpack():
    tlv = BindingSIDSubTLV(label=24000)
    packed = tlv.pack()
    # type(1) + length(2) + flags(1) + reserved(1) + label_entry(4) = 9 bytes
    assert len(packed) == 9
    assert packed[0] == 13

    tlv2 = BindingSIDSubTLV.unpack(packed[3:])
    assert tlv2.label == 24000


def test_binding_sid_null_pack_unpack():
    tlv = BindingSIDSubTLV(label=None)
    packed = tlv.pack()
    # type(1) + length(2) + flags(1) + reserved(1) = 5 bytes
    assert len(packed) == 5

    tlv2 = BindingSIDSubTLV.unpack(packed[3:])
    assert tlv2.label is None


# ============================================================= SRv6 Binding SID


def test_srv6_binding_sid_pack_unpack():
    tlv = SRv6BindingSIDSubTLV(sid='fc00::1')
    packed = tlv.pack()
    # type(1) + length(2) + flags(1) + reserved(1) + sid(16) = 21 bytes
    assert len(packed) == 21
    assert packed[0] == 20

    tlv2 = SRv6BindingSIDSubTLV.unpack(packed[3:])
    assert tlv2.sid == 'fc00::1'


# ============================================================= Segment List


def test_weight_subsubtlv_pack_unpack():
    w = WeightSubSubTLV(weight=5)
    packed = w.pack()
    # type(1) + length(2) + flags(1) + reserved(3) + weight(4) = 11 bytes
    assert len(packed) == 11
    assert packed[0] == 9

    w2 = WeightSubSubTLV.unpack(packed[3:])
    assert w2.weight == 5


def test_segment_type_a_pack_unpack():
    seg = SegmentTypeA(label=16001)
    packed = seg.pack()
    # type(1) + length(2) + flags(1) + reserved(1) + label_entry(4) = 9 bytes
    assert len(packed) == 9
    assert packed[0] == 1

    seg2 = SegmentTypeA.unpack(packed[3:])
    assert seg2.label == 16001


def test_segment_type_b_pack_unpack():
    seg = SegmentTypeB(sid='fc00::2')
    packed = seg.pack()
    # type(1) + length(2) + flags(1) + reserved(1) + sid(16) = 21 bytes
    assert len(packed) == 21
    assert packed[0] == 13

    seg2 = SegmentTypeB.unpack(packed[3:])
    assert seg2.sid == 'fc00::2'
    assert seg2.endpoint_behavior is None


def test_segment_type_b_with_endpoint_behavior():
    eb = SRv6EndpointBehavior(endpoint_behavior=0x0041, lb_length=32, ln_length=0, fun_length=16, arg_length=0)
    seg = SegmentTypeB(sid='fc00::3', endpoint_behavior=eb)
    packed = seg.pack()

    seg2 = SegmentTypeB.unpack(packed[3:])
    assert seg2.sid == 'fc00::3'
    assert seg2.endpoint_behavior is not None
    assert seg2.endpoint_behavior.endpoint_behavior == 0x0041
    assert seg2.endpoint_behavior.lb_length == 32
    assert seg2.endpoint_behavior.fun_length == 16


def test_segment_list_pack_unpack():
    weight = WeightSubSubTLV(weight=1)
    segments = [
        SegmentTypeA(label=16001),
        SegmentTypeA(label=16002),
    ]
    tlv = SegmentListSubTLV(weight=weight, segments=segments)
    packed = tlv.pack()
    assert packed[0] == 128

    tlv2 = SegmentListSubTLV.unpack(packed[3:])
    assert tlv2.weight.weight == 1
    assert len(tlv2.segments) == 2
    assert isinstance(tlv2.segments[0], SegmentTypeA)
    assert tlv2.segments[0].label == 16001
    assert tlv2.segments[1].label == 16002


def test_segment_list_mixed_segments():
    weight = WeightSubSubTLV(weight=2)
    segments = [SegmentTypeA(label=16003), SegmentTypeB(sid='fc00::5')]
    tlv = SegmentListSubTLV(weight=weight, segments=segments)
    packed = tlv.pack()

    tlv2 = SegmentListSubTLV.unpack(packed[3:])
    assert tlv2.weight.weight == 2
    assert len(tlv2.segments) == 2
    assert isinstance(tlv2.segments[0], SegmentTypeA)
    assert isinstance(tlv2.segments[1], SegmentTypeB)
    assert tlv2.segments[0].label == 16003
    assert tlv2.segments[1].sid == 'fc00::5'


# ============================================================= SRPolicyTunnel


def test_sr_policy_tunnel_pack_unpack():
    tunnel = SRPolicyTunnel(
        subtlvs=[
            PreferenceSubTLV(100),
            PrioritySubTLV(10),
            PolicyNameSubTLV('my-policy'),
            SegmentListSubTLV(
                weight=WeightSubSubTLV(1),
                segments=[SegmentTypeA(16001), SegmentTypeA(16002)],
            ),
        ]
    )
    packed_value = tunnel.pack_value()
    tunnel2 = SRPolicyTunnel.unpack(packed_value)

    subtlv_types = [type(t) for t in tunnel2.subtlvs]
    assert PreferenceSubTLV in subtlv_types
    assert PrioritySubTLV in subtlv_types
    assert PolicyNameSubTLV in subtlv_types
    assert SegmentListSubTLV in subtlv_types

    seg_list = next(t for t in tunnel2.subtlvs if isinstance(t, SegmentListSubTLV))
    assert seg_list.weight.weight == 1
    assert len(seg_list.segments) == 2


def test_sr_policy_tunnel_multiple_segment_lists():
    tunnel = SRPolicyTunnel(
        subtlvs=[
            PreferenceSubTLV(100),
            SegmentListSubTLV(WeightSubSubTLV(1), [SegmentTypeA(16001)]),
            SegmentListSubTLV(WeightSubSubTLV(2), [SegmentTypeA(16002), SegmentTypeA(16003)]),
        ]
    )
    packed_value = tunnel.pack_value()
    tunnel2 = SRPolicyTunnel.unpack(packed_value)

    seg_lists = [t for t in tunnel2.subtlvs if isinstance(t, SegmentListSubTLV)]
    assert len(seg_lists) == 2
    assert seg_lists[0].weight.weight == 1
    assert seg_lists[1].weight.weight == 2
    assert len(seg_lists[1].segments) == 2


# ============================================================= TunnelEncap


def test_tunnel_encap_attribute_pack_unpack():
    tunnel = SRPolicyTunnel(
        subtlvs=[
            PreferenceSubTLV(100),
            SegmentListSubTLV(WeightSubSubTLV(1), [SegmentTypeA(16001)]),
        ]
    )
    attr = TunnelEncap(tunnel_tlvs=[tunnel])
    packed = attr.pack_attribute(None)

    # packed includes the BGP attribute header (flags + type + length)
    # strip it to get the raw value for unpack_attribute
    # Attribute._attribute() adds: flags(1) + type(1) + length(1 or 2)
    # The value starts after the header
    # Read past flags(1) + type(1) + length bytes
    raw_value = _strip_attr_header(packed)
    attr2 = TunnelEncap.unpack_attribute(raw_value, None)

    assert len(attr2.tunnel_tlvs) == 1
    assert isinstance(attr2.tunnel_tlvs[0], SRPolicyTunnel)
    sr = attr2.tunnel_tlvs[0]
    prefs = [t for t in sr.subtlvs if isinstance(t, PreferenceSubTLV)]
    assert prefs[0].preference == 100


def _strip_attr_header(data: bytes) -> bytes:
    """Strip BGP attribute header (flags + type + length) from packed attribute."""
    flags = data[0]
    # bit 4 (0x10) = extended length
    if flags & 0x10:
        # flags(1) + type(1) + length(2) = 4 bytes header
        return data[4:]
    else:
        # flags(1) + type(1) + length(1) = 3 bytes header
        return data[3:]


def test_tunnel_encap_json():
    tunnel = SRPolicyTunnel(subtlvs=[PreferenceSubTLV(50)])
    attr = TunnelEncap(tunnel_tlvs=[tunnel])
    j = attr.json()
    assert 'sr-policy' in j
    assert '"preference": 50' in j
