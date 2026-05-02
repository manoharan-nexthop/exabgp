"""sr_policy/segment_list.py

SR Policy Segment List Sub-TLV (type 128, RFC 9256 Section 2.4.4).

The Segment List sub-TLV contains its own set of sub-sub-TLVs using the
same 1-byte type + 2-byte length format.

Segment List sub-sub-TLV types:
  9   Weight
  1   Segment Type A (MPLS label only)
  13  Segment Type B (SRv6 SID, optionally with Endpoint Behavior sub-sub-TLV)

Weight sub-sub-TLV (type 9):
 +-+-+-+-+-+-+-+-+
 | Flags (1 octet)|
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | Reserved (3 octets)                            |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | Weight (4 octets, unsigned)                    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Total value: 8 bytes.

Segment Type A sub-sub-TLV (type 1):
 +-+-+-+-+-+-+-+-+
 | Flags (1 octet)|
 +-+-+-+-+-+-+-+-+
 | Reserved (1 octet) |
 +-+-+-+-+-+-+-+-+-- ... --+
 | MPLS Label Stack Entry (4 octets) |
 +-+-+-+-+-+-+-+-+-- ... --+
Total value: 6 bytes.

Segment Type B sub-sub-TLV (type 13):
 +-+-+-+-+-+-+-+-+
 | Flags (1 octet)|
 +-+-+-+-+-+-+-+-+
 | Reserved (1 octet) |
 +-+-+-+-+-+-+-+-+-- ... --+
 | SRv6 SID (16 octets)  |
 +-+-+-+-+-+-+-+-+-- ... --+
 | [SRv6 Endpoint Behavior sub-sub-TLV (type 20, optional)] |
Total value: 18+ bytes.

SRv6 Endpoint Behavior sub-sub-TLV (type 20, within Segment Type B):
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | Endpoint Behavior (2 octets)  |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | LB length (1 octet)           |
 +-+-+-+-+-+-+-+-+
 | LN length (1 octet)           |
 +-+-+-+-+-+-+-+-+
 | Fun length (1 octet)          |
 +-+-+-+-+-+-+-+-+
 | Arg length (1 octet)          |
 +-+-+-+-+-+-+-+-+
Total: 6 bytes.
"""

from __future__ import annotations

import socket
from struct import pack, unpack
from typing import ClassVar

from exabgp.bgp.message.notification import Notify
from exabgp.bgp.message.update.attribute.tunnel_encap.tlv import SubTLV
# Type alias for buffer (bytes or bytearray)
Buffer = bytes | bytearray

_SUBTLV_HEADER = 3  # type(1) + length(2)

# Segment type B flag: indicates SRv6 Endpoint Behavior sub-sub-TLV follows
_SEG_B_FLAG_ENDPOINT_BEHAVIOR = 0x80


class SRv6EndpointBehavior:
    """SRv6 Endpoint Behavior and Structure (sub-sub-TLV type 20 within Segment Type B)."""

    SIZE = 6  # endpoint_behavior(2) + lb(1) + ln(1) + fun(1) + arg(1)

    def __init__(
        self,
        endpoint_behavior: int,
        lb_length: int = 0,
        ln_length: int = 0,
        fun_length: int = 0,
        arg_length: int = 0,
    ) -> None:
        self.endpoint_behavior = endpoint_behavior
        self.lb_length = lb_length
        self.ln_length = ln_length
        self.fun_length = fun_length
        self.arg_length = arg_length

    def pack(self) -> bytes:
        return pack('!HBBBB', self.endpoint_behavior, self.lb_length, self.ln_length, self.fun_length, self.arg_length)

    def json(self) -> str:
        return (
            '"endpoint-behavior": {'
            f'"behavior": {self.endpoint_behavior}, '
            f'"lb-length": {self.lb_length}, '
            f'"ln-length": {self.ln_length}, '
            f'"fun-length": {self.fun_length}, '
            f'"arg-length": {self.arg_length}'
            '}'
        )

    @classmethod
    def unpack(cls, data: Buffer) -> SRv6EndpointBehavior:
        if len(data) < cls.SIZE:
            return cls(0)
        eb, lb, ln, fun, arg = unpack('!HBBBB', data[: cls.SIZE])
        return cls(endpoint_behavior=eb, lb_length=lb, ln_length=ln, fun_length=fun, arg_length=arg)


class WeightSubSubTLV:
    """Segment List Weight sub-sub-TLV (type 9)."""

    SUBTYPE: ClassVar[int] = 9
    VALUE_SIZE: ClassVar[int] = 8  # flags(1) + reserved(3) + weight(4)

    def __init__(self, weight: int, flags: int = 0) -> None:
        self.weight = weight
        self.flags = flags

    def pack(self) -> bytes:
        value = pack('!B3sI', self.flags, b'\x00\x00\x00', self.weight)
        return pack('!BH', self.SUBTYPE, len(value)) + value

    def json(self) -> str:
        return f'"weight": {self.weight}'

    @classmethod
    def unpack(cls, data: Buffer) -> WeightSubSubTLV:
        if len(data) < cls.VALUE_SIZE:
            return cls(1)
        flags = data[0]
        weight: int = unpack('!I', data[4:8])[0]
        return cls(weight=weight, flags=flags)


class SegmentTypeA:
    """Segment Type A: MPLS label only (sub-sub-TLV type 1)."""

    SUBTYPE: ClassVar[int] = 1
    VALUE_SIZE: ClassVar[int] = 6  # flags(1) + reserved(1) + label_entry(4)

    def __init__(self, label: int, flags: int = 0, tc: int = 0, s: bool = True, ttl: int = 0) -> None:
        self.label = label
        self.flags = flags
        self.tc = tc
        self.s = s
        self.ttl = ttl

    def pack(self) -> bytes:
        label_entry = (self.label << 12) | (self.tc << 9) | (0x100 if self.s else 0) | self.ttl
        value = pack('!BBL', self.flags, 0, label_entry)
        return pack('!BH', self.SUBTYPE, len(value)) + value

    def json(self) -> str:
        return f'{{"type": "A", "label": {self.label}, "tc": {self.tc}, "s": {str(self.s).lower()}, "ttl": {self.ttl}}}'

    @classmethod
    def unpack(cls, data: Buffer) -> SegmentTypeA:
        if len(data) < cls.VALUE_SIZE:
            return cls(0)
        flags = data[0]
        label_entry: int = unpack('!L', data[2:6])[0]
        label = label_entry >> 12
        tc = (label_entry >> 9) & 0x7
        s = bool(label_entry & 0x100)
        ttl = label_entry & 0xFF
        return cls(label=label, flags=flags, tc=tc, s=s, ttl=ttl)


class SegmentTypeB:
    """Segment Type B: SRv6 SID (sub-sub-TLV type 13), optionally with endpoint behavior."""

    SUBTYPE: ClassVar[int] = 13
    VALUE_BASE_SIZE: ClassVar[int] = 18  # flags(1) + reserved(1) + sid(16)

    def __init__(
        self,
        sid: str,
        flags: int = 0,
        endpoint_behavior: SRv6EndpointBehavior | None = None,
    ) -> None:
        self.sid = sid
        self.flags = flags
        self.endpoint_behavior = endpoint_behavior

    def pack(self) -> bytes:
        sid_bytes = socket.inet_pton(socket.AF_INET6, self.sid)
        effective_flags = self.flags
        if self.endpoint_behavior is not None:
            effective_flags |= _SEG_B_FLAG_ENDPOINT_BEHAVIOR
        value = pack('!BB', effective_flags, 0) + sid_bytes
        if self.endpoint_behavior is not None:
            eb_value = self.endpoint_behavior.pack()
            value += pack('!BH', 20, len(eb_value)) + eb_value
        return pack('!BH', self.SUBTYPE, len(value)) + value

    def json(self) -> str:
        parts = ['"type": "B"', f'"sid": "{self.sid}"']
        if self.endpoint_behavior is not None:
            parts.append(self.endpoint_behavior.json())
        return '{' + ', '.join(parts) + '}'

    @classmethod
    def unpack(cls, data: Buffer) -> SegmentTypeB:
        if len(data) < cls.VALUE_BASE_SIZE:
            return cls('::')
        flags = data[0]
        sid = socket.inet_ntop(socket.AF_INET6, bytes(data[2:18]))
        endpoint_behavior: SRv6EndpointBehavior | None = None
        # Parse optional sub-sub-TLVs after the SID
        remainder = data[18:]
        while remainder:
            if len(remainder) < _SUBTLV_HEADER:
                break
            sub_type = remainder[0]
            sub_len: int = unpack('!H', remainder[1:3])[0]
            if len(remainder) < _SUBTLV_HEADER + sub_len:
                break
            sub_value = remainder[_SUBTLV_HEADER : _SUBTLV_HEADER + sub_len]
            if sub_type == 20:
                endpoint_behavior = SRv6EndpointBehavior.unpack(sub_value)
            remainder = remainder[_SUBTLV_HEADER + sub_len :]
        return cls(sid=sid, flags=flags, endpoint_behavior=endpoint_behavior)


def _unpack_segment_subsubtlvs(data: Buffer) -> tuple[WeightSubSubTLV | None, list[SegmentTypeA | SegmentTypeB]]:
    """Parse segment list body: weight + segments."""
    weight: WeightSubSubTLV | None = None
    segments: list[SegmentTypeA | SegmentTypeB] = []

    while data:
        if len(data) < _SUBTLV_HEADER:
            raise Notify(3, 1, f'Segment List sub-sub-TLV header truncated: got {len(data)}')
        sub_type = data[0]
        sub_len: int = unpack('!H', data[1:3])[0]
        if len(data) < _SUBTLV_HEADER + sub_len:
            raise Notify(3, 1, f'Segment List sub-sub-TLV truncated: need {_SUBTLV_HEADER + sub_len}')
        value = data[_SUBTLV_HEADER : _SUBTLV_HEADER + sub_len]
        if sub_type == WeightSubSubTLV.SUBTYPE:
            weight = WeightSubSubTLV.unpack(value)
        elif sub_type == SegmentTypeA.SUBTYPE:
            segments.append(SegmentTypeA.unpack(value))
        elif sub_type == SegmentTypeB.SUBTYPE:
            segments.append(SegmentTypeB.unpack(value))
        data = data[_SUBTLV_HEADER + sub_len :]

    return weight, segments


@SubTLV.register(128)
class SegmentListSubTLV(SubTLV):
    """SR Policy Segment List Sub-TLV (type 128).

    Contains Weight sub-sub-TLV and one or more Segment sub-sub-TLVs.
    """

    SUBTYPE: ClassVar[int] = 128

    def __init__(
        self,
        weight: WeightSubSubTLV,
        segments: list[SegmentTypeA | SegmentTypeB],
    ) -> None:
        self.weight = weight
        self.segments = segments

    def pack_value(self) -> bytes:
        data = self.weight.pack()
        for seg in self.segments:
            data += seg.pack()
        return data

    def json(self) -> str:
        segs_json = ', '.join(seg.json() for seg in self.segments)
        return f'{{"weight": {self.weight.weight}, "segments": [{segs_json}]}}'

    def __str__(self) -> str:
        segs = ' '.join(str(s.label) if isinstance(s, SegmentTypeA) else str(s.sid) for s in self.segments)
        return f'segment-list weight {self.weight.weight} [{segs}]'

    @classmethod
    def unpack(cls, data: Buffer) -> SegmentListSubTLV:
        weight, segments = _unpack_segment_subsubtlvs(data)
        if weight is None:
            weight = WeightSubSubTLV(1)
        return cls(weight=weight, segments=segments)
