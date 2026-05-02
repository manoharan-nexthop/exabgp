"""sr_policy/srv6_binding_sid.py

SR Policy SRv6 Binding SID Sub-TLV (type 20, RFC 9256 Section 2.4.3).

Wire format:
 +-+-+-+-+-+-+-+-+
 | Flags (1 octet)|
 +-+-+-+-+-+-+-+-+
 | Reserved (1 octet) |
 +-+-+-+-+-+-+-+-+-- ... --+
 | SRv6 SID (16 octets)   |
 +-+-+-+-+-+-+-+-+-- ... --+
Total value length: 18 bytes.
"""

from __future__ import annotations

import socket
from struct import pack
from typing import ClassVar

from exabgp.bgp.message.update.attribute.tunnel_encap.tlv import SubTLV
from exabgp.util.types import Buffer

_SRV6_BSID_VALUE_SIZE = 18  # flags(1) + reserved(1) + sid(16)


@SubTLV.register(20)
class SRv6BindingSIDSubTLV(SubTLV):
    """SR Policy SRv6 Binding SID Sub-TLV."""

    SUBTYPE: ClassVar[int] = 20

    def __init__(self, sid: str, flags: int = 0) -> None:
        """Args:
        sid: SRv6 SID as IPv6 address string.
        flags: Sub-TLV flags byte.
        """
        self.sid = sid
        self.flags = flags

    def pack_value(self) -> bytes:
        return pack('!BB', self.flags, 0) + socket.inet_pton(socket.AF_INET6, self.sid)

    def json(self) -> str:
        return f'"srv6-binding-sid": "{self.sid}"'

    def __str__(self) -> str:
        return f'srv6-binding-sid {self.sid}'

    @classmethod
    def unpack(cls, data: Buffer) -> SRv6BindingSIDSubTLV:
        if len(data) < _SRV6_BSID_VALUE_SIZE:
            return cls('::')
        flags = data[0]
        sid = socket.inet_ntop(socket.AF_INET6, bytes(data[2:18]))
        return cls(sid=sid, flags=flags)
