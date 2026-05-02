"""sr_policy/preference.py

SR Policy Preference Sub-TLV (type 12, RFC 9256 Section 2.4.1).

Wire format:
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Reserved/Flags (4 octets)                   |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Preference (4 octets)                       |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Total value length: 8 bytes.
"""

from __future__ import annotations

from struct import pack, unpack
from typing import ClassVar

from exabgp.bgp.message.update.attribute.tunnel_encap.tlv import SubTLV
from exabgp.util.types import Buffer

_PREFERENCE_VALUE_SIZE = 8  # flags(4) + preference(4)


@SubTLV.register(12)
class PreferenceSubTLV(SubTLV):
    """SR Policy Preference Sub-TLV."""

    SUBTYPE: ClassVar[int] = 12

    def __init__(self, preference: int, flags: int = 0) -> None:
        self.preference = preference
        self.flags = flags

    def pack_value(self) -> bytes:
        return pack('!II', self.flags, self.preference)

    def json(self) -> str:
        return f'"preference": {self.preference}'

    def __str__(self) -> str:
        return f'preference {self.preference}'

    @classmethod
    def unpack(cls, data: Buffer) -> PreferenceSubTLV:
        if len(data) < _PREFERENCE_VALUE_SIZE:
            return cls(0)
        flags, preference = unpack('!II', data[:8])
        return cls(preference=preference, flags=flags)
