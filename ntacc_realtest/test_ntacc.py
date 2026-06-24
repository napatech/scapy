#!/usr/bin/env python3
"""Real-hardware test for scapy.contrib.ntacc.NtaccSocket.

Transmits a known set of packets through the Napatech SmartNIC via NTAPI
(NT_NetTxAddPacket) and verifies the adapter's TX packet counter increments
by exactly the number sent. TX counters are read with the trusted C helper
nt_txstat (compiled against the real NTAPI headers).

Run:  LD_LIBRARY_PATH=/opt/napatech3/lib python3 test_ntacc.py [port]
"""
import os
import subprocess
import sys
import time

from scapy.all import Ether, IP, ICMP, Raw
from scapy.contrib.ntacc import NtaccSocket

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 0
HERE = os.path.dirname(os.path.abspath(__file__))
TXSTAT = os.path.join(HERE, "nt_txstat")


def read_tx(port):
    """Return (pkts, octets) for the port via the C stats helper."""
    out = subprocess.check_output([TXSTAT, str(port)]).decode().split()
    return int(out[0]), int(out[1])


def main():
    # Build a deterministic set of frames. Mix of normal-sized and short
    # frames (the short ones exercise NtaccSocket's zero-padding path).
    pkts = []
    for i in range(250):
        pkts.append(Ether(dst="00:11:22:33:44:55", src="00:0d:e9:08:96:79") /
                    IP(dst="10.0.0.%d" % (i + 1), src="10.0.0.254") /
                    ICMP() / Raw(b"NtaccSocket-test-%02d" % i))
    # 2 deliberately short frames (< 60B) to test padding
    pkts.append(Ether(dst="ff:ff:ff:ff:ff:ff", src="00:0d:e9:08:96:79", type=0x0801))
    pkts.append(Ether(dst="ff:ff:ff:ff:ff:ff", src="00:0d:e9:08:96:79", type=0x0802))
    n = len(pkts)

    expected_octets = sum(max(len(bytes(p)), 60) + 4 for p in pkts)  # +4 FCS

    print("Port %d: sending %d packets via NtaccSocket (expected +%d octets)"
          % (PORT, n, expected_octets))

    before = read_tx(PORT)
    print("TX before:  pkts=%d octets=%d" % before)

    s = NtaccSocket(port=PORT)
    sent = 0
    t0 = time.time()
    for p in pkts:
        sent += 1 if s.send(p) else 0
    dt = time.time() - t0
    s.close()
    print("NtaccSocket.send() accepted %d/%d packets in %.3f ms"
          % (sent, n, dt * 1e3))

    # Stats refresh is periodic; poll for the delta to appear.
    after = before
    for _ in range(20):
        time.sleep(0.1)
        after = read_tx(PORT)
        if after[0] - before[0] >= n:
            break
    dpkts = after[0] - before[0]
    docts = after[1] - before[1]
    print("TX after:   pkts=%d octets=%d" % after)
    print("Delta:      pkts=+%d octets=+%d" % (dpkts, docts))

    ok = (dpkts == n)
    print("\nRESULT: %s — adapter TX packet counter changed by %+d (expected +%d)"
          % ("PASS" if ok else "FAIL", dpkts, n))
    if docts:
        print("        octets +%d (expected ~%d incl. FCS)" % (docts, expected_octets))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
