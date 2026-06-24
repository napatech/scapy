# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Napatech SmartNIC transmit socket (NTAPI / ntacc)
# scapy.contrib.status = loads

"""
NtaccSocket: transmit packets through a Napatech SmartNIC using the Napatech
API (NTAPI, ``libntapi``), bypassing the OS kernel network stack.

This is the same hardware path used by the DPDK ``net_ntacc`` PMD in its
"mode 2" transmit function (``eth_ntacc_tx_mode2``), which calls
``NT_NetTxAddPacket()`` once per packet with a scatter-gather fragment list.
Here we drive ``NT_NetTxAddPacket()`` directly from Python via ctypes, so no
DPDK/EAL is required.

Requirements (runtime, not bundled with Scapy):
  - A Napatech SmartNIC with the Napatech driver installed and ``ntservice``
    running.
  - ``libntapi.so`` reachable by the loader (e.g. ``/opt/napatech3/lib``).
  - The target TX port enabled for transmit in the adapter configuration.

Notes:
  - The adapter appends the 4-byte Ethernet FCS itself. Pass the L2 frame
    WITHOUT FCS (a normal Scapy ``Ether(...)/...`` frame).
  - This is a transmit-only socket; ``recv`` is not implemented.

Usage::

    from scapy.contrib.ntacc import NtaccSocket
    s = NtaccSocket(port=0)
    s.send(Ether()/IP(dst="10.0.0.1")/ICMP())
    sendp(Ether()/IP()/ICMP(), socket=s)   # or drive it via sendp()
    s.close()
"""

import ctypes
import time

from scapy.supersocket import SuperSocket
from scapy.compat import raw
from scapy.error import Scapy_Exception, log_runtime
from scapy.data import MTU

# NTAPI constants (from /opt/napatech3/include/ntapi/*.h)
NTAPI_VERSION = 2
NT_SUCCESS = 0
NT_ERRBUF_SIZE = 128
# NUMA option passed to NT_NetTxOpen: -1 lets the adapter pick the host buffer.
NT_NETTX_NUMA_ADAPTER_HB = -1

# Minimum on-wire frame size excluding the FCS the adapter adds (64 - 4).
# Short frames are zero-padded so the NIC does not reject them as runts.
MIN_TX_FRAME_NO_FCS = 60


# NtNetStreamTx_t is an opaque "struct NtNetStreamTx_s *" handle.
NtNetStreamTx_t = ctypes.c_void_p


class NtNetTxFragment_t(ctypes.Structure):
    """Mirror of NtNetTxFragment_s in ntapi/stream_net.h"""
    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("size", ctypes.c_uint16),
    ]


def _load_libntapi():
    # type: () -> ctypes.CDLL
    last_err = None
    for name in ("libntapi.so", "/opt/napatech3/lib/libntapi.so"):
        try:
            return ctypes.CDLL(name)
        except OSError as e:
            last_err = e
    raise OSError(
        "Could not load libntapi.so (is the Napatech driver installed and on "
        "the loader path?): %s" % last_err
    )


_lib = None  # type: ctypes.CDLL | None
_initialized = False


def _ntapi():
    # type: () -> ctypes.CDLL
    """Load libntapi (once) and declare the prototypes we use."""
    global _lib, _initialized
    if _lib is not None:
        return _lib
    lib = _load_libntapi()

    lib.NT_Init.restype = ctypes.c_int
    lib.NT_Init.argtypes = [ctypes.c_uint32]

    lib.NT_ExplainError.restype = ctypes.c_char_p
    lib.NT_ExplainError.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32
    ]

    lib.NT_NetTxOpen.restype = ctypes.c_int
    lib.NT_NetTxOpen.argtypes = [
        ctypes.POINTER(NtNetStreamTx_t),  # hStream (out)
        ctypes.c_char_p,                  # name
        ctypes.c_uint64,                  # portMask
        ctypes.c_uint32,                  # NUMA
        ctypes.c_uint32,                  # minHostBufferSize
    ]

    lib.NT_NetTxAddPacket.restype = ctypes.c_int
    lib.NT_NetTxAddPacket.argtypes = [
        NtNetStreamTx_t,                       # hStream
        ctypes.c_uint32,                       # port
        ctypes.POINTER(NtNetTxFragment_t),     # fragments
        ctypes.c_uint32,                        # fragmentCount
        ctypes.c_int,                           # timeout (ms)
    ]

    lib.NT_NetTxClose.restype = ctypes.c_int
    lib.NT_NetTxClose.argtypes = [NtNetStreamTx_t]

    if not _initialized:
        _check(lib, lib.NT_Init(NTAPI_VERSION), "NT_Init")
        _initialized = True

    _lib = lib
    return lib


def _check(lib, status, where):
    # type: (ctypes.CDLL, int, str) -> None
    """Raise a Scapy_Exception with the NTAPI error text on failure."""
    if status == NT_SUCCESS:
        return
    buf = ctypes.create_string_buffer(NT_ERRBUF_SIZE)
    lib.NT_ExplainError(status, buf, NT_ERRBUF_SIZE)
    raise Scapy_Exception(
        "%s failed (status=%d): %s" % (where, status, buf.value.decode(errors="replace"))
    )


class NtaccSocket(SuperSocket):
    desc = "transmit via Napatech SmartNIC (NTAPI NT_NetTxAddPacket)"
    nonblocking_socket = True

    def __init__(self, port=0, timeout=0, name="scapy", cache=True):
        # type: (int, int, str, bool) -> None
        """
        :param port: Napatech TX port number to transmit on.
        :param timeout: per-packet NT_NetTxAddPacket timeout in ms
            (0 = non-blocking, return immediately if the TX buffer is full).
        :param name: stream name shown in Napatech tooling.
        :param cache: reuse the serialized bytes when the *same* object is sent
            repeatedly (the loop/flood pattern), skipping raw() and buffer
            setup. Caveat: if you mutate a Packet in place between sends, pass
            cache=False so each send re-serializes.
        """
        self.lib = _ntapi()
        self.port = port
        self.timeout = timeout
        self.cache = cache
        self._cache_key = None     # last object sent (held to pin its id)
        self._cache_prep = None    # cached (frags, nfrags, length, *buffers)
        self.hStream = NtNetStreamTx_t()
        # One host buffer is allocated per port set in portMask.
        _check(
            self.lib,
            self.lib.NT_NetTxOpen(
                ctypes.byref(self.hStream),
                name.encode(),
                1 << port,
                NT_NETTX_NUMA_ADAPTER_HB & 0xFFFFFFFF,
                0,
            ),
            "NT_NetTxOpen",
        )
        self.closed = False

    def _prepare(self, x):
        # type: (Packet) -> tuple
        """Serialize x and build the NTAPI fragment list (+ kept-alive buffers).

        Fragment 0 is the packet bytes; fragment 1 (optional) is zero padding so
        short frames meet the NIC's minimum on-wire length -- same approach as
        the ntacc PMD's eth_ntacc_tx_mode2().
        """
        sx = raw(x)
        n = len(sx)
        frags = (NtNetTxFragment_t * 2)()
        databuf = (ctypes.c_uint8 * n).from_buffer_copy(sx)
        frags[0].data = ctypes.cast(databuf, ctypes.POINTER(ctypes.c_uint8))
        frags[0].size = n
        nfrags = 1
        padbuf = None
        if n < MIN_TX_FRAME_NO_FCS:
            padlen = MIN_TX_FRAME_NO_FCS - n
            padbuf = (ctypes.c_uint8 * padlen)()  # zero-initialised
            frags[1].data = ctypes.cast(padbuf, ctypes.POINTER(ctypes.c_uint8))
            frags[1].size = padlen
            nfrags = 2
        # databuf/padbuf are returned so the caller keeps them referenced for
        # the lifetime of the cached entry (NTAPI copies them synchronously).
        return (frags, nfrags, n, databuf, padbuf)

    def send(self, x):
        # type: (Packet) -> int
        if self.cache and x is self._cache_key:
            prep = self._cache_prep
        else:
            prep = self._prepare(x)
            if self.cache:
                self._cache_key = x
                self._cache_prep = prep
        frags, nfrags, n = prep[0], prep[1], prep[2]

        try:
            x.sent_time = time.time()
        except AttributeError:
            pass

        status = self.lib.NT_NetTxAddPacket(
            self.hStream, self.port, frags, nfrags, self.timeout
        )
        _check(self.lib, status, "NT_NetTxAddPacket")
        return n

    def recv(self, x=MTU, **kwargs):
        # type: (int, **object) -> object
        raise Scapy_Exception("NtaccSocket is transmit-only")

    def recv_raw(self, x=MTU):
        # type: (int) -> object
        raise Scapy_Exception("NtaccSocket is transmit-only")

    def fileno(self):
        # type: () -> int
        return -1

    def close(self):
        # type: () -> None
        if self.closed:
            return
        self.closed = True
        if getattr(self, "hStream", None):
            status = self.lib.NT_NetTxClose(self.hStream)
            if status != NT_SUCCESS:
                log_runtime.warning("NT_NetTxClose failed (status=%d)", status)
            self.hStream = NtNetStreamTx_t()
