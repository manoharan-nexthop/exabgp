# Plan: SR Policy Support (RFC 9830)

**Status:** 📋 Planning
**Created:** 2026-05-01
**Last Updated:** 2026-05-01

---

## Objective

Add full SR Policy support per RFC 9830 (BGP SR Policy SAFI), RFC 9012 (Tunnel Encapsulation Attribute), and RFC 9256 (SR Policy Architecture). This includes:
- SR Policy NLRI (SAFI 73): encode/decode/announce/withdraw
- Tunnel Encapsulation Attribute (type 23): encode/decode
- SR Policy Sub-TLVs: 7 types requested

---

## RFCs

| RFC | Title | Relevance |
|-----|-------|-----------|
| RFC 9830 | BGP SR Policy SAFI | SAFI 73 + NLRI format |
| RFC 9012 | Tunnel Encapsulations Attribute | Attribute type 23 + TLV format |
| RFC 9256 | SR Policy Architecture | Sub-TLV semantics, segment types |
| RFC 8402 | SR Architecture | SR-MPLS label stack |

---

## Wire Formats

### SR Policy NLRI (RFC 9830, IPv4)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Distinguisher (4 octets)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Policy Color (4 octets)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Endpoint (4 octets IPv4 or 16 IPv6)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
Total: 12 bytes (IPv4) or 24 bytes (IPv6).  
AFI: IPv4 (1) or IPv6 (2). SAFI: 73.

### Tunnel Encap Attribute (RFC 9012, type 23)
Flag: OPTIONAL | TRANSITIVE
```
 +------------------------+
 | Tunnel Type (2 octets) |
 +------------------------+
 | Length (2 octets)      |
 +------------------------+
 | Value (variable)       |
 +------------------------+
 ... (repeated per tunnel type)
```
Tunnel Type 15 = SR Policy.

### SR Policy Sub-TLVs (within Tunnel Type 15 Value)
Each sub-TLV:
```
 +---------------+
 | Type (1 octet)|
 +---------------+---------------+
 | Length (2 octets)             |  ← length of Value only
 +---------------+---------------+--...
 | Value (variable)              |
 +-------------------------------+
```

| Type | Name | Value Format |
|------|------|--------------|
| 12   | Preference | Flags(4) + Preference(4) = 8 bytes |
| 13   | Binding SID | Flags(1) + Reserved(1) + BSID(variable, 0 or 4 bytes) |
| 20   | SRv6 Binding SID | Flags(1) + Reserved(1) + SID(16 bytes) |
| 128  | Segment List | Weight sub-TLV + Segment sub-TLVs |
| 15   | Priority | Priority(1) + Reserved(1) = 2 bytes |
| 129  | Policy Name | Flags(1) + Name(variable UTF-8) |
| 130  | Candidate Path Name | Flags(1) + Name(variable UTF-8) |

### Segment List Sub-TLV (type 128) Internal Sub-Sub-TLVs
Same 1-byte type + 2-byte length + value format.

| Type | Name | Value Format |
|------|------|--------------|
| 9    | Weight | Flags(1) + Reserved(3) + Weight(4) = 8 bytes |
| 1    | Segment Type A (MPLS) | Flags(1) + Reserved(1) + Label Stack Entry(4) = 6 bytes |
| 13   | Segment Type B (SRv6) | Flags(1) + Reserved(1) + SID(16) [+ opt SRv6 Endpoint Behavior] |

**MPLS Label Stack Entry (4 bytes):**
- Label: bits [31:12] (top 20 bits)
- TC: bits [11:9] (3 bits)
- S: bit [8] (bottom-of-stack)
- TTL: bits [7:0] (8 bits)

**SRv6 Endpoint Behavior Sub-Sub-TLV (type 20, within Segment Type B):**
- Endpoint Behavior (2 bytes)
- LB length (1 byte)
- LN length (1 byte)
- Fun length (1 byte)
- Arg length (1 byte)

---

## File Structure

```
src/exabgp/
├── protocol/family.py                         [MODIFY] Add SAFI 73 sr-policy
├── bgp/message/update/
│   ├── nlri/
│   │   ├── __init__.py                        [MODIFY] Import sr_policy
│   │   └── sr_policy.py                       [NEW] SRPolicyNLRI class
│   └── attribute/
│       ├── attribute.py                        [MODIFY] Add TUNNEL_ENCAP to registered
│       ├── __init__.py                         [MODIFY] Import tunnel_encap
│       └── tunnel_encap/
│           ├── __init__.py                     [NEW] TunnelEncap attribute (code 23)
│           ├── tlv.py                          [NEW] Base TunnelTLV + SubTLV classes
│           └── sr_policy/
│               ├── __init__.py                 [NEW] SRPolicyTunnel (type 15)
│               ├── preference.py               [NEW] Preference Sub-TLV (type 12)
│               ├── binding_sid.py              [NEW] Binding SID Sub-TLV (type 13)
│               ├── srv6_binding_sid.py          [NEW] SRv6 Binding SID Sub-TLV (type 20)
│               ├── segment_list.py             [NEW] Segment List Sub-TLV (type 128)
│               ├── priority.py                 [NEW] Priority Sub-TLV (type 15)
│               ├── policy_name.py              [NEW] Policy Name Sub-TLV (type 129)
│               └── candidate_path_name.py      [NEW] Candidate Path Name Sub-TLV (type 130)
└── configuration/
    ├── neighbor/family.py                      [MODIFY] sr-policy family support
    ├── announce/
    │   └── sr_policy.py                        [NEW] ParseAnnounce for SR Policy
    └── static/
        └── sr_policy.py                        [NEW] Parser functions

tests/
└── unit/
    ├── test_sr_policy_nlri.py                  [NEW]
    ├── test_tunnel_encap.py                    [NEW]
    └── test_sr_policy_subtlvs.py              [NEW]

qa/
├── encoding/
│   └── sr-policy-*.ci                         [NEW] Functional encode tests
└── decoding/
    └── sr-policy-*.json                        [NEW] Functional decode tests
```

---

## Configuration Syntax

### ExaBGP Config File
```
neighbor 1.2.3.4 {
    family {
        ipv4 sr-policy;
        ipv6 sr-policy;
    }
    static {
        sr-policy {
            route distinguisher 0 color 100 endpoint 1.2.3.4 {
                next-hop 5.6.7.8;
                tunnel-encap sr-policy {
                    preference 100;
                    binding-sid mpls 24000;
                    srv6-binding-sid fc00::1;
                    segment-list weight 1 {
                        segment type-a mpls 16001;
                        segment type-a mpls 16002;
                        segment type-b srv6 fc00::2;
                    }
                    priority 10;
                    policy-name "test-policy";
                    candidate-path-name "primary-path";
                }
            }
        }
    }
}
```

### ExaBGP API Command (inline)
```
announce sr-policy distinguisher 0 color 100 endpoint 1.2.3.4 next-hop 5.6.7.8 tunnel-encap sr-policy preference 100 segment-list weight 1 segment type-a mpls 16001 segment type-a mpls 16002 policy-name test-policy
```

---

## Implementation Phases

### Phase 1: Core NLRI + SAFI (Foundation)

**Tasks:**
1. Add SAFI 73 (`SR_POLICY = 73`, `sr_policy`) to `family.py`
2. Add `sr-policy` to `AFI.implemented_safi()` for ipv4/ipv6
3. Create `nlri/sr_policy.py`:
   - `SRPolicyNLRI(NLRI)` registered for (ipv4, sr_policy) and (ipv6, sr_policy)
   - `__init__(distinguisher, color, endpoint, packed)` → packed-bytes-first
   - `pack_nlri()` / `unpack_nlri()`
   - `json()`, `__str__()`, `__hash__()`, `__eq__()`
4. Register in `nlri/__init__.py`
5. Add Family.size entry for SR Policy
6. Unit tests: construct, pack, unpack round-trip

### Phase 2: Tunnel Encap Attribute (Code 23)

**Tasks:**
1. Create `attribute/tunnel_encap/tlv.py`:
   - `TunnelTLV`: base class for Tunnel Type TLVs (type:2, length:2, value:variable)
   - `SubTLV`: base class for sub-TLVs (type:1, length:2, value:variable)
   - Registry pattern: `TunnelTLV.register(tunnel_type)`
2. Create `attribute/tunnel_encap/__init__.py`:
   - `TunnelEncap(Attribute)` with ID = 23
   - FLAG = OPTIONAL | TRANSITIVE
   - `unpack_attribute()`: parse outer TLVs, dispatch to registered tunnel types
   - `pack_attribute()`: serialize all tunnel TLVs
   - `json()`, `__str__()`
3. Register in `attribute/__init__.py`
4. Unit tests

### Phase 3: SR Policy Sub-TLVs

**Tasks (in order of simplicity):**
1. `sr_policy/preference.py` - Preference (type 12): Flags(4) + Value(4)
2. `sr_policy/priority.py` - Priority (type 15): Priority(1) + Reserved(1)
3. `sr_policy/policy_name.py` - Policy Name (type 129): Flags(1) + Name(str)
4. `sr_policy/candidate_path_name.py` - Candidate Path Name (type 130): Flags(1) + Name(str)
5. `sr_policy/binding_sid.py` - Binding SID (type 13): Flags(1) + Reserved(1) + BSID(0 or 4 bytes)
6. `sr_policy/srv6_binding_sid.py` - SRv6 Binding SID (type 20): Flags(1) + Reserved(1) + SID(16)
7. `sr_policy/segment_list.py` - Segment List (type 128):
   - Weight sub-TLV (type 9)
   - Segment Type A - MPLS label (type 1)
   - Segment Type B - SRv6 SID (type 13) with optional SRv6 endpoint behavior
8. `sr_policy/__init__.py` - SRPolicyTunnel container (type 15)
9. Unit tests for each

### Phase 4: Configuration

**Tasks:**
1. Modify `configuration/neighbor/family.py` to recognize `sr-policy` SAFI
2. Create `configuration/static/sr_policy.py`:
   - `sr_policy_nlri(tokeniser, afi)` → SRPolicyNLRI
   - `tunnel_encap_sr_policy(tokeniser)` → TunnelEncap attribute
3. Create `configuration/announce/sr_policy.py`:
   - `AnnouncePolicy(ParseAnnounce)` class
   - Register for (ipv4, sr_policy) and (ipv6, sr_policy)
4. Wire into `configuration/announce/__init__.py`

### Phase 5: Tests + CI

**Tasks:**
1. Functional encoding test (`.ci` file): encode SR Policy route, verify hex
2. Functional decoding test (`.json` file): decode hex, verify JSON output
3. Run `./qa/bin/test_everything` and confirm all pass

---

## Key Design Decisions

### D1: Tunnel Encap Sub-TLV length encoding
RFC 9012 uses 1-byte type + 2-byte length for sub-TLVs (not 1-byte type + 1-byte length like some other TLVs). Must be consistent.

### D2: Packed-bytes-first for NLRI
SRPolicyNLRI follows the packed-bytes-first pattern (like EVPN, VPLS). The `_packed` stores the raw wire bytes for the NLRI body (distinguisher + color + endpoint).

### D3: Attribute packing
TunnelEncap stores `_packed` for the full attribute body (all tunnel TLVs). Sub-TLVs pack independently via `pack_tlv()` → joined in TunnelEncap.

### D4: No AFI encoding in NLRI body
SR Policy NLRI body does NOT include AFI/SAFI. The AFI determines endpoint size (4 bytes IPv4, 16 bytes IPv6). The `unpack_nlri()` classmethod receives AFI to know endpoint size.

### D5: Segment Type A vs B naming
In the config, use `type-a` for MPLS segments and `type-b` for SRv6 segments (matching RFC 9256 naming convention).

### D6: SRv6 Endpoint Behavior (confirmed 2026-05-01)
Include SRv6 Endpoint Behavior sub-sub-TLV within Segment Type B: `endpoint_behavior(2) + lb_len(1) + ln_len(1) + fun_len(1) + arg_len(1)`. Optional (only present if flags indicate).

### D7: ENLP Sub-TLV (confirmed 2026-05-01)
Skip ENLP (type 14) — not in scope for this pass.

### D8: Segment Types C–H (confirmed 2026-05-01)
Only Type A (MPLS label, type 1) and Type B (SRv6 SID, type 13). Types C–H deferred.

### D9: Multiple Segment Lists (confirmed 2026-05-01)
Multiple `segment-list` blocks per SR Policy route are supported. Each has its own `weight`. Config and wire format must handle N Segment List Sub-TLVs in the SR Policy Tunnel.

---

## Progress Table

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | SAFI 73 in family.py | ⬜ | |
| 2 | SRPolicyNLRI | ⬜ | |
| 3 | TunnelEncap attribute (code 23) | ⬜ | |
| 4 | Preference Sub-TLV | ⬜ | |
| 5 | Priority Sub-TLV | ⬜ | |
| 6 | Policy Name Sub-TLV | ⬜ | |
| 7 | Candidate Path Name Sub-TLV | ⬜ | |
| 8 | Binding SID Sub-TLV | ⬜ | |
| 9 | SRv6 Binding SID Sub-TLV | ⬜ | |
| 10 | Segment List + Weight + Type A/B | ⬜ | |
| 11 | SRPolicyTunnel (type 15) container | ⬜ | |
| 12 | Config parser: NLRI | ⬜ | |
| 13 | Config parser: Tunnel Encap sub-TLVs | ⬜ | |
| 14 | Announce registration | ⬜ | |
| 15 | Unit tests | ⬜ | |
| 16 | Functional tests | ⬜ | |
| 17 | test_everything passes | ⬜ | |

---

## Recent Failures

*(none yet)*

---

## Blockers

*(none yet)*

---

## Resume Point

Not started. Begin with Phase 1: SAFI 73 + SRPolicyNLRI.
