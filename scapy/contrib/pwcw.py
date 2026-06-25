# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = PseudoWire Control Word (PWE3, RFC 4385)
# scapy.contrib.status = loads

"""
PWCW - PseudoWire Control Word.

The 4-byte control word carried between the MPLS label stack and the
emulated payload of a PWE3 pseudowire, in the "preferred" generic format of
RFC 4385 section 3:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 0 0 0| Flags |FRG|  Length   |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The leading four bits are zero so the control word cannot be mistaken for the
first nibble of an IPv4 (0x4) or IPv6 (0x6) packet.  ``length`` carries the
payload length only when the packet has been padded to a minimum size; it is
left as a plain settable field here rather than computed automatically.

Scapy already ships the minimal Ethernet-PW control word as ``EoMCW`` in
``scapy.contrib.mpls``; ``PWCW`` exposes the individual Flags/FRG/Length
subfields of the generic form.
"""

from scapy.packet import Packet, Padding
from scapy.fields import BitField, ShortField

from scapy.layers.l2 import Ether


class PWCW(Packet):
    name = "PWCW"
    fields_desc = [BitField("zero", 0, 4),
                   BitField("flags", 0, 4),
                   BitField("frg", 0, 2),
                   BitField("length", 0, 6),
                   ShortField("seq", 0)]

    def guess_payload_class(self, payload):
        if len(payload) >= 1:
            return Ether
        return Padding
