#!/usr/bin/env python3
"""Extended real-hardware tests for scapy.contrib.ntacc.NtaccSocket.

(b) transmit on each available port and verify the TX counter delta
(a) throughput: blast a batch and measure packets/s and Mbps from Python
(c) drive it through scapy's high-level sendp(..., socket=...) path

Run:  LD_LIBRARY_PATH=/opt/napatech3/lib python3 test_ntacc_extended.py
"""
import os
import subprocess
import sys
import time

from scapy.all import Ether, IP, UDP, Raw, sendp
from scapy.compat import raw
from scapy.contrib.ntacc import NtaccSocket

HERE = os.path.dirname(os.path.abspath(__file__))
TXSTAT = os.path.join(HERE, "nt_txstat")
PORTS = [0, 1]


def read_tx(port):
    out = subprocess.check_output([TXSTAT, str(port)]).decode().split()
    return int(out[0]), int(out[1])


def wait_delta(port, before, want, tries=30):
    after = before
    for _ in range(tries):
        time.sleep(0.1)
        after = read_tx(port)
        if after[0] - before[0] >= want:
            break
    return after


def banner(t):
    print("\n" + "=" * 64 + "\n" + t + "\n" + "=" * 64)


# ---------------------------------------------------------------------------
# (b) Per-port transmit
# ---------------------------------------------------------------------------
def test_ports():
    banner("(b) Transmit on each port")
    results = {}
    for port in PORTS:
        pkt = (Ether(dst="00:11:22:33:44:55", src="00:0d:e9:08:96:79") /
               IP(dst="10.0.0.1") / UDP() / Raw(b"port-%d" % port))
        n = 5
        before = read_tx(port)
        s = NtaccSocket(port=port)
        for _ in range(n):
            s.send(pkt)
        s.close()
        after = wait_delta(port, before, n)
        d = after[0] - before[0]
        ok = d == n
        results[port] = ok
        print("  port %d: sent %d, TX delta +%d  -> %s"
              % (port, n, d, "PASS" if ok else "FAIL"))
    return all(results.values())


# ---------------------------------------------------------------------------
# (a) Throughput
# ---------------------------------------------------------------------------
def test_throughput(port=0, count=50000, payload=46):
    banner("(a) Throughput (port %d, %d packets)" % (port, count))
    # 64-byte frame on the wire: 14 Ether + 20 IP + 8 UDP + payload, +4 FCS.
    pkt = (Ether(dst="00:11:22:33:44:55", src="00:0d:e9:08:96:79") /
           IP(dst="10.0.0.1") / UDP() / Raw(b"\x00" * payload))
    frame = raw(pkt)
    wire = len(frame) + 4  # adapter adds FCS
    # timeout>0 so NT_NetTxAddPacket blocks for buffer space instead of erroring
    s = NtaccSocket(port=port, timeout=1000)

    before = read_tx(port)

    # Realistic path: send Packet objects (includes scapy re-serialization).
    t0 = time.perf_counter()
    for _ in range(count):
        s.send(pkt)
    t_pkt = time.perf_counter() - t0

    # NTAPI ceiling: send pre-serialized bytes (skips scapy serialization).
    t0 = time.perf_counter()
    for _ in range(count):
        s.send(frame)
    t_raw = time.perf_counter() - t0

    s.close()
    after = wait_delta(port, before, 2 * count)
    d = after[0] - before[0]

    def rate(t):
        pps = count / t
        return pps, pps * wire * 8 / 1e6  # Mbps (wire bytes incl FCS)

    pps1, mbps1 = rate(t_pkt)
    pps2, mbps2 = rate(t_raw)
    print("  frame=%dB wire=%dB" % (len(frame), wire))
    print("  Packet objects : %.3f s  -> %8.0f pps  %7.1f Mbps" % (t_pkt, pps1, mbps1))
    print("  pre-serialized : %.3f s  -> %8.0f pps  %7.1f Mbps" % (t_raw, pps2, mbps2))
    ok = d == 2 * count
    print("  TX delta +%d (expected +%d) -> %s"
          % (d, 2 * count, "PASS" if ok else "FAIL"))
    return ok


# ---------------------------------------------------------------------------
# (c) High-level sendp() integration
# ---------------------------------------------------------------------------
def test_sendp(port=0):
    banner("(c) scapy sendp(..., socket=NtaccSocket)")
    pkts = [Ether(dst="00:11:22:33:44:55", src="00:0d:e9:08:96:79") /
            IP(dst="10.0.0.%d" % i) / UDP() / Raw(b"sendp-%d" % i)
            for i in range(1, 8)]
    n = len(pkts)
    before = read_tx(port)
    s = NtaccSocket(port=port)
    # sendp drives __gen_send over our socket; return_packets gives a count.
    res = sendp(pkts, socket=s, verbose=True, return_packets=True)
    s.close()
    after = wait_delta(port, before, n)
    d = after[0] - before[0]
    nret = len(res) if res is not None else 0
    ok = d == n and nret == n
    print("  sendp returned %d packets; TX delta +%d (expected +%d) -> %s"
          % (nret, d, n, "PASS" if ok else "FAIL"))
    return ok


def main():
    results = {
        "ports": test_ports(),
        "throughput": test_throughput(),
        "sendp": test_sendp(),
    }
    banner("SUMMARY")
    for k, v in results.items():
        print("  %-12s %s" % (k, "PASS" if v else "FAIL"))
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
