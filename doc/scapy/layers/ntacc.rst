**********************************
Napatech SmartNIC transmit socket
**********************************

.. note::

    This module requires a Napatech SmartNIC with the Napatech driver
    installed. It is not bundled with, nor exercised by, Scapy's own tests
    against real hardware.

:py:class:`~scapy.contrib.ntacc.NtaccSocket` transmits packets through a
Napatech SmartNIC using the Napatech API (NTAPI, ``libntapi``), bypassing the
OS kernel network stack. It drives ``NT_NetTxAddPacket()`` directly from Python
via ``ctypes`` -- the same hardware path the DPDK ``net_ntacc`` PMD uses in its
"mode 2" transmit function -- so no DPDK/EAL is required.

It is a **transmit-only** socket; ``recv`` is not implemented.

Requirements
============

- A Napatech SmartNIC with the Napatech driver installed and ``ntservice``
  running.
- ``libntapi.so`` reachable by the loader (e.g. ``/opt/napatech3/lib``; set
  ``LD_LIBRARY_PATH`` if needed).
- The target TX port enabled for transmit in the adapter configuration.

Using NtaccSocket in Scapy
==========================

Load the contrib module and open a socket on the TX port you want to use:

.. code-block:: pycon3

    >>> from scapy.contrib.ntacc import NtaccSocket
    >>> s = NtaccSocket(port=0)
    >>> s.send(Ether()/IP(dst="10.0.0.1")/ICMP())
    >>> s.close()

It behaves like any other :py:class:`~scapy.supersocket.SuperSocket`, so you
can also drive it through the high-level :py:func:`~scapy.sendrecv.sendp`:

.. code-block:: pycon3

    >>> sendp(Ether()/IP()/ICMP(), socket=s)

.. note::

    The adapter appends the 4-byte Ethernet FCS itself, so pass the L2 frame
    **without** an FCS (a normal ``Ether(...)/...`` frame). Frames shorter than
    the 60-byte minimum on-wire length (excluding FCS) are zero-padded
    automatically.

NtaccSocket reference
=====================

.. py:class:: NtaccSocket(SuperSocket)

    A transmit-only socket that sends frames through a Napatech SmartNIC via
    ``NT_NetTxAddPacket()``.

    .. py:method:: __init__(port=0, timeout=0, name="scapy", cache=True)

        :param int port:
            Napatech TX port number to transmit on.

        :param int timeout:
            Per-packet ``NT_NetTxAddPacket`` timeout, in milliseconds. ``0``
            (the default) is non-blocking: it returns immediately if the TX
            buffer is full. A positive value blocks for buffer space, which is
            useful when blasting at line rate.

        :param str name:
            Stream name shown in Napatech tooling.

        :param bool cache:
            When True (default), reuse the serialized bytes when the *same*
            packet object is sent repeatedly (the loop/flood pattern), skipping
            re-serialization. Pass ``cache=False`` if you mutate a packet in
            place between sends, so each send re-serializes it.
