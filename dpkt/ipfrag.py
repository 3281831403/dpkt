# -*- coding: utf-8 -*-
"""Reassembly of IPv4 and IPv6 fragmented datagrams.

dpkt decodes each packet in isolation, so a datagram split across IP
fragments is invisible to anything that looks at one packet: the first
fragment is handed to the transport decoder as if it were the whole
datagram, while later fragments carry no transport header and stay raw
bytes.  :class:`dpkt.ip6.IP6` used to miss a Fragment Header that follows
another extension header (Hop-by-Hop, for example); with the old
``nxt == 44`` guard it could decode the middle of a datagram as UDP.
That parser bug is fixed, and this module provides the actual reassembly.

:class:`IPFragmentReassembler` collects fragments and returns the
complete datagram as soon as every byte is present.  Fragments may arrive
out of order, may be duplicated, and may overlap.  The result is raw
bytes with its length fields and checksums recomputed for the whole
datagram, so it can be fed straight back into :class:`dpkt.ip.IP` /
:class:`dpkt.ip6.IP6` (or serialized and re-parsed).

Overlap policy
--------------

* IPv4: the bytes that arrived first win.  A later fragment contributes
  only bytes no earlier fragment supplied, so it cannot change data that
  was already accepted (the classic "first-fragment-wins" rule, which
  also defeats overlapping-fragment evasion).
* IPv6: any overlap between fragments invalidates the whole datagram
  (RFC 8200 section 4.5 / RFC 5722).  The group is discarded and all
  later fragments carrying the same key are rejected.

An identical retransmission whose bytes are *entirely* covered by what
was already received is a duplicate, not an overlap: it is absorbed
silently for both versions, and cannot influence the result.

Errors
------

Anomalies are recorded as :class:`FragmentError` entries with a
``reason`` and an ``offset`` (a byte offset into the reassembled
transport payload):

``'gap'``
    Missing bytes; one entry per contiguous hole at its first missing
    byte.  Recomputed as fragments arrive, so a hole that is later filled
    disappears from ``group.errors``.
``'overlap'``
    The fragment shares bytes with data received earlier, located at the
    first shared byte.  For IPv6 this also discards the group.
``'oversize'``
    The datagram exceeds the protocol's maximum payload (16-bit length
    fields), or declares a final offset larger than the protocol allows.
    Discards the group.
``'no-first-fragment'``
    The last fragment has arrived but no fragment starts at offset 0,
    so there is no network header to rebuild the datagram from.  Transient
    until (or unless) the first fragment arrives.

``group.errors`` holds the errors of one datagram; ``reassembler.errors``
is an append-only log that additionally carries the datagram ``key`` and
survives the group being discarded.

Rebuilt packets have the whole-datagram fields recomputed: the IPv4 Total
Length and header checksum, the IPv6 Payload Length, the UDP Length, and
the UDP/TCP/ICMP/ICMPv6 checksums (over the IPv4 or IPv6 pseudo-header).  The
IPv4 Fragment Offset and More-Fragments fields are cleared.  For IPv6 the
Fragment Header is removed, the Next Header field that pointed at it is
repointed at the protocol it carried, and every other extension header is
preserved.

Example::

    reasm = IPFragmentReassembler()
    for raw in fragments:
        complete = reasm.add(raw)
        if complete is not None:
            net = dpkt.ip.IP(complete)     # or dpkt.ip6.IP6(complete)
    for err in reasm.errors:
        print(err.reason, err.offset)
"""
from __future__ import absolute_import

import struct
import time

from . import dpkt
from . import ip
from . import ip6

#: bytes missing from the datagram
REASON_GAP = 'gap'
#: fragment shares bytes with bytes received earlier
REASON_OVERLAP = 'overlap'
#: datagram exceeds the protocol's maximum size
REASON_OVERSIZE = 'oversize'
#: datagram is complete but no fragment starts at offset 0
REASON_NO_FIRST_FRAGMENT = 'no-first-fragment'

#: largest payload an IPv4 datagram can carry (Total Length is 16 bits)
IP4_MAX_PAYLOAD = ip.IP_LEN_MAX - ip.IP_HDR_LEN
#: largest payload an IPv6 datagram can carry (Payload Length is 16 bits)
IP6_MAX_PAYLOAD = 0xffff

#: default seconds an incomplete datagram is retained
DEFAULT_TIMEOUT = 60.0

_IP6_HDR_LEN = ip6.IP6.__hdr_len__
_IP6_FRAG_HDR_LEN = ip6.IP6FragmentHeader.__hdr_len__
_UDP_HDR_LEN = 8

#: offset of the checksum field inside the transport header
_CKSUM_OFFSET = {
    ip.IP_PROTO_ICMP: 2,
    ip.IP_PROTO_TCP: 6,
    ip.IP_PROTO_UDP: 6,
    ip.IP_PROTO_ICMP6: 2,
}
#: minimum length of a transport header carrying a checksum
_TRANSPORT_MIN_LEN = {
    ip.IP_PROTO_ICMP: 4,
    ip.IP_PROTO_TCP: 20,
    ip.IP_PROTO_UDP: 8,
    ip.IP_PROTO_ICMP6: 4,
}


def _checksum(buf):
    """Return the Internet checksum of ``buf``."""
    return dpkt.in_cksum(buf)


def _pseudo_header(version, src, dst, proto, length):
    """Return the transport pseudo-header for packed addresses."""
    if version == 4:
        return struct.pack('>4s4sxBH', src, dst, proto, length)
    # 'xBH' and the RFC 8200 'I3xB' encoding both produce 00 00 <length>
    return struct.pack('>16s16sxBH', src, dst, proto, length)


def _ext_header_len(proto, header):
    """Return the length of an IPv6 extension header, or 0 if unknown."""
    if len(header) < 2:
        return 0
    if proto in (ip.IP_PROTO_HOPOPTS, ip.IP_PROTO_ROUTING,
                 ip.IP_PROTO_DSTOPTS):
        return (header[1] + 1) * 8
    if proto == ip.IP_PROTO_AH:
        return (header[1] + 2) * 4
    # ESP and unknown protocols cannot be walked any further
    return 0


def _upper_layer(version, payload, proto):
    """Locate the transport header inside a reassembled payload.

    Returns ``(transport_proto, offset)``, or ``(None, None)`` when the
    transport protocol cannot be identified (e.g. ESP or a malformed
    extension-header chain).
    """
    offset = 0
    if version == 6:
        while proto in ip6.EXT_HDRS:
            if proto in (ip.IP_PROTO_ESP, ip.IP_PROTO_FRAGMENT):
                return None, None
            length = _ext_header_len(proto, payload[offset:])
            if length <= 0 or offset + length > len(payload):
                return None, None
            proto = payload[offset]
            offset += length
    return proto, offset


def _transport_checksum(version, src, dst, proto, payload, offset=None):
    """Return the checksum of a complete transport segment.

    ``offset`` is the position of the segment inside ``payload``; it is
    nonzero only when extension headers precede the transport header.
    """
    if offset is None:
        offset = 0
    cksum_off = _CKSUM_OFFSET.get(proto)
    if cksum_off is None:
        return None
    segment = payload[offset:]
    if len(segment) < max(cksum_off + 2, _TRANSPORT_MIN_LEN.get(proto, 0)):
        return None
    zeroed = segment[:cksum_off] + b'\x00\x00' + segment[cksum_off + 2:]
    if proto == ip.IP_PROTO_ICMP and version == 4:
        # ICMPv4 is the only checksummed protocol without a pseudo-header
        checksum = _checksum(zeroed)
    else:
        checksum = _checksum(
            _pseudo_header(version, src, dst, proto, len(zeroed)) + zeroed)
    if proto == ip.IP_PROTO_UDP and checksum == 0:
        # RFC 768: a computed zero is transmitted as all ones
        checksum = 0xffff
    return checksum


def _patch_transport(version, src, dst, payload, proto):
    """Recompute the length and checksum fields of the transport segment."""
    transport_proto, start = _upper_layer(version, payload, proto)
    if transport_proto is None:
        return payload
    cksum_off = _CKSUM_OFFSET.get(transport_proto)
    if cksum_off is None:
        return payload
    if len(payload) - start < _TRANSPORT_MIN_LEN.get(transport_proto, 0):
        return payload

    if transport_proto == ip.IP_PROTO_UDP:
        # the UDP length covers the whole reassembled segment; do this
        # before the checksum so the new value is covered by it
        segment_len = len(payload) - start
        payload = (payload[:start + 4] + struct.pack('>H', segment_len)
                   + payload[start + 6:])

    checksum = _transport_checksum(version, src, dst, transport_proto,
                                   payload, start)
    if checksum is None:
        return payload
    return (payload[:start + cksum_off] + struct.pack('>H', checksum)
            + payload[start + cksum_off + 2:])


def _find_v6_fragment(raw):
    """Walk the raw IPv6 extension-header chain to the Fragment Header.

    :meth:`dpkt.ip6.IP6.unpack` cannot be trusted here: it stops decoding
    after a non-first fragment and, when the Fragment Header follows
    another extension header, it can decode mid-datagram bytes as a
    transport packet.  The chain is therefore re-walked over the serialized
    bytes.

    Returns a dict with the Fragment Header offset, its fields and the
    offset of the Next Header field that points at it, or None when the
    packet carries no Fragment Header.
    """
    if len(raw) < _IP6_HDR_LEN:
        raise dpkt.UnpackError('truncated IPv6 header')
    nxt = raw[6]
    offset = _IP6_HDR_LEN
    next_header_offset = 6  # Next Header field of the fixed header

    while True:
        if nxt == ip.IP_PROTO_FRAGMENT:
            if offset + _IP6_FRAG_HDR_LEN > len(raw):
                raise dpkt.UnpackError('truncated IPv6 fragment header')
            value = struct.unpack('>H', raw[offset + 2:offset + 4])[0]
            return {
                'offset': offset,
                'next_header_offset': next_header_offset,
                # the Fragment Header's Next Header field is at its offset
                'nxt': raw[offset],
                'frag_off': value >> 3,
                'm_flag': value & 1,
                'id': struct.unpack('>I', raw[offset + 4:offset + 8])[0],
            }
        if nxt in (ip.IP_PROTO_ESP, ip.IP_PROTO_NONE):
            return None
        if offset + 2 > len(raw):
            raise dpkt.UnpackError('truncated IPv6 extension header')
        length = _ext_header_len(nxt, raw[offset:offset + 2])
        if not length:
            return None
        if offset + length > len(raw):
            raise dpkt.UnpackError('truncated IPv6 extension header')
        # the extension header at `offset` starts with its Next Header field
        next_header_offset = offset
        nxt = raw[offset]
        offset += length


class FragmentError(object):
    """One anomaly detected while reassembling a datagram.

    Attributes:
        reason (str): one of :data:`REASON_GAP`, :data:`REASON_OVERLAP`,
            :data:`REASON_OVERSIZE`, :data:`REASON_NO_FIRST_FRAGMENT`.
        offset (int): byte offset into the reassembled transport payload
            (0 for whole-datagram problems).
        key (tuple): datagram identity; set by
            :attr:`IPFragmentReassembler.errors` entries and None in
            :attr:`FragmentGroup.errors`.
        length (int): fragment payload length involved, when relevant.
    """

    __slots__ = ('reason', 'offset', 'key', 'length')

    def __init__(self, reason, offset, key=None, length=None):
        self.reason = reason
        self.offset = offset
        self.key = key
        self.length = length

    def _fields(self):
        return (self.reason, self.offset, self.key, self.length)

    def __eq__(self, other):
        if isinstance(other, FragmentError):
            return self._fields() == other._fields()
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    def __hash__(self):
        return hash(self._fields())

    def __repr__(self):
        parts = ['reason=%r' % self.reason, 'offset=%r' % self.offset]
        if self.key is not None:
            parts.append('key=%r' % (self.key,))
        if self.length is not None:
            parts.append('length=%r' % self.length)
        return 'FragmentError(%s)' % ', '.join(parts)


class FragmentGroup(object):
    """Reassembly state for one fragmented datagram.

    Attributes:
        key: tuple identifying the datagram; see :meth:`IPFragmentReassembler.add`.
        version (int): 4 or 6.
        errors (list): :class:`FragmentError` entries seen for this group.
        buf (bytearray): bytes accepted so far, truncated to the highest
            offset received.
        seen (bytearray): one flag per byte in ``buf``: 1 when that byte
            has been received, 0 when it is still a hole.
        done (bool): True once the fragment with More-Fragments cleared
            has arrived.
        last_offset (int): payload end declared by that fragment, or None.
        first (dict): details of the offset-0 fragment, or None.
        deadline (float): ``time.monotonic()`` value after which
            :meth:`IPFragmentReassembler.purge` may drop the group, or
            None when timeouts are disabled.
    """

    def __init__(self, key, version, timeout):
        self.key = key
        self.version = version
        self.buf = bytearray()
        self.seen = bytearray()
        self.first = None
        self.last_offset = None
        self.done = False
        self.errors = []
        self.deadline = None if timeout is None else time.monotonic() + timeout

    def record(self, reason, offset, length=None):
        """Append one anomaly to :attr:`errors`."""
        self.errors.append(FragmentError(reason, offset, length=length))

    def has_error(self, reason, offset=None):
        """Return True when a matching anomaly is already recorded."""
        return any(error.reason == reason and
                   (offset is None or error.offset == offset)
                   for error in self.errors)

    @property
    def total_len(self):
        """Highest payload end offset accepted so far."""
        return len(self.buf)


class IPFragmentReassembler(object):
    """Reassemble IPv4 and IPv6 fragments into complete datagrams.

    Fragments are passed to :meth:`add` in any order.  ``add`` returns the
    raw bytes of the reassembled datagram once it is complete, and None
    while fragments are missing or the fragment was not a fragment at all.

    Args:
        timeout (float): seconds an incomplete datagram is retained before
            :meth:`purge` may drop it.  None disables expiry.
        max_payload_v4 (int): maximum accepted reassembled IPv4 payload.
        max_payload_v6 (int): maximum accepted reassembled IPv6 payload.

    Attributes:
        groups (dict): incomplete datagrams keyed by the identifying tuple.
        errors (list): append-only log of :class:`FragmentError` entries,
            each also carrying the datagram ``key``.
        dead_keys (dict): keys invalidated by an anomaly, mapped to the
            time until which later fragments with the same key are
            rejected.
    """

    def __init__(self, timeout=DEFAULT_TIMEOUT,
                 max_payload_v4=IP4_MAX_PAYLOAD,
                 max_payload_v6=IP6_MAX_PAYLOAD):
        self.timeout = timeout
        self.max_payload = {4: max_payload_v4, 6: max_payload_v6}
        self.groups = {}
        self.errors = []
        self.dead_keys = {}

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def add(self, pkt):
        """Add one fragment.

        Args:
            pkt: raw bytes of an IPv4/IPv6 fragment, or a parsed
                :class:`dpkt.ip.IP` / :class:`dpkt.ip6.IP6` fragment.

        Returns:
            bytes: the reassembled datagram once every byte is present,
            otherwise None.  Packets that are not fragments are ignored
            and return None, so a whole stream may be fed through.

        Raises:
            dpkt.UnpackError: if ``pkt`` is neither an IPv4 nor an IPv6
                packet, or its header is truncated or malformed.
        """
        raw = self._raw(pkt)
        if not raw:
            raise dpkt.UnpackError('empty packet')
        version = raw[0] >> 4
        if version == 4:
            return self._add_v4(raw)
        if version == 6:
            return self._add_v6(raw)
        raise dpkt.UnpackError('unknown IP version: %r' % version)

    def add_all(self, fragments):
        """Add every fragment; return the list of reassembled datagrams."""
        result = []
        for fragment in fragments:
            packet = self.add(fragment)
            if packet is not None:
                result.append(packet)
        return result

    def purge(self, now=None):
        """Drop timed-out datagrams; return the removed group keys.

        Expired rejection entries are forgotten too, so tracking invalidated
        datagrams stays bounded.
        """
        if now is None:
            now = time.monotonic()
        stale = [key for key, group in self.groups.items()
                 if group.deadline is not None and group.deadline <= now]
        for key in stale:
            del self.groups[key]
        expired = [key for key, deadline in self.dead_keys.items()
                   if deadline is not None and deadline <= now]
        for key in expired:
            del self.dead_keys[key]
        return stale

    # ------------------------------------------------------------------
    # input normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _raw(pkt):
        """Return the raw bytes of a fragment, parsing it if necessary."""
        if isinstance(pkt, (bytes, bytearray, memoryview)):
            return bytes(pkt)
        if isinstance(pkt, ip.IP):
            data = pkt.data
            if not isinstance(data, (bytes, bytearray, memoryview)):
                data = bytes(data)
            return pkt.pack_hdr() + bytes(pkt.opts) + data
        if isinstance(pkt, ip6.IP6):
            header = pkt.pack_hdr()
            for ext in getattr(pkt, 'all_extension_headers', None) or []:
                serialized = bytes(ext)
                header += serialized[:getattr(ext, 'length', len(serialized))]
            data = pkt.data
            if not isinstance(data, (bytes, bytearray, memoryview)):
                data = bytes(data)
            return header + data
        raise dpkt.UnpackError('not an IPv4/IPv6 packet: %r' % type(pkt))

    # ------------------------------------------------------------------
    # shared machinery
    # ------------------------------------------------------------------

    def _record(self, group, reason, offset, length=None):
        """Record an anomaly on the group and in the global log.

        The same reason at the same offset is recorded once per group.
        """
        if group.has_error(reason, offset):
            return
        group.record(reason, offset, length=length)
        entry = FragmentError(reason, offset, key=group.key, length=length)
        if entry not in self.errors:
            self.errors.append(entry)

    def _clear(self, group, reasons):
        """Forget transient anomalies of the given reasons on the group.

        :attr:`errors` is an append-only audit log and is left alone.
        """
        group.errors = [error for error in group.errors
                        if error.reason not in reasons]

    def _hole_starts(self, group):
        """Return the first offset of every contiguous hole so far."""
        total = group.last_offset
        if total is None:
            return []
        holes = []
        in_hole = False
        for offset in range(total):
            missing = offset >= len(group.seen) or not group.seen[offset]
            if missing and not in_hole:
                holes.append(offset)
            in_hole = missing
        return holes

    def _refresh(self, group):
        """Recompute the transient gap / no-first-fragment errors.

        These depend on what is currently missing, so they are dropped and
        rebuilt whenever a fragment arrives: a hole filled later must not
        linger in ``group.errors``.
        """
        self._clear(group, (REASON_GAP, REASON_NO_FIRST_FRAGMENT))
        if not group.done:
            return
        if group.first is None:
            self._record(group, REASON_NO_FIRST_FRAGMENT, 0)
            return
        for offset in self._hole_starts(group):
            self._record(group, REASON_GAP, offset)
        # bytes past the end declared by the last fragment are spurious
        if group.total_len > group.last_offset:
            self._record(group, REASON_OVERSIZE, group.last_offset)

    def _get_group(self, key, version):
        group = self.groups.get(key)
        if group is None:
            group = FragmentGroup(key, version, self.timeout)
            self.groups[key] = group
        if group.deadline is not None:
            group.deadline = time.monotonic() + self.timeout
        return group

    def _discard(self, group):
        """Drop the group and reject later fragments of the datagram."""
        self.groups.pop(group.key, None)
        deadline = (None if self.timeout is None
                    else time.monotonic() + self.timeout)
        self.dead_keys[group.key] = deadline

    @staticmethod
    def _set_end(group, end_offset):
        """Note the payload end declared by the last fragment."""
        group.done = True
        if group.last_offset is None or end_offset > group.last_offset:
            group.last_offset = end_offset

    def _accept(self, group, offset, payload):
        """Store one fragment's payload at ``offset``.

        Returns False when the datagram must be discarded.
        """
        limit = self.max_payload[group.version]
        end = offset + len(payload)

        if offset > limit or end > limit:
            self._record(group, REASON_OVERSIZE, offset, length=len(payload))
            return False
        if not payload:
            return True

        buf = group.buf
        seen = group.seen
        if end > len(buf):
            grow = end - len(buf)
            buf.extend(b'\x00' * grow)
            seen.extend(b'\x00' * grow)

        overlap = seen.find(b'\x01', offset, end) != -1
        if overlap:
            # compare only the bytes that have already been received
            first_overlap = None
            conflicting = False
            fresh = False
            for position in range(offset, end):
                if seen[position]:
                    if first_overlap is None:
                        first_overlap = position
                    if buf[position] != payload[position - offset]:
                        conflicting = True
                else:
                    fresh = True
            if not fresh and not conflicting:
                # an identical duplicate, which is absorbed silently
                return True
            self._record(group, REASON_OVERLAP, first_overlap,
                         length=len(payload))
            if group.version == 6:
                # RFC 8200 section 4.5: discard the whole datagram
                return False

        # IPv4 keeps the first-arrived byte.  IPv6 only reaches here when
        # the overlapping bytes are identical and new bytes are added too.
        for position in range(offset, end):
            if not seen[position]:
                buf[position] = payload[position - offset]
                seen[position] = 1
        return True

    def _complete(self, group):
        """Return the contiguous payload, or None while gaps remain."""
        self._refresh(group)
        if not group.done or group.first is None:
            return None
        if self._hole_starts(group):
            return None
        return bytes(group.buf[:group.last_offset])

    def _finish(self, group):
        """Return the rebuilt datagram, or None if it is not complete."""
        payload = self._complete(group)
        if payload is None:
            return None
        self.groups.pop(group.key, None)
        if group.version == 4:
            return self._build_v4(group, payload)
        return self._build_v6(group, payload)

    # ------------------------------------------------------------------
    # IPv4
    # ------------------------------------------------------------------

    def _add_v4(self, raw):
        if len(raw) < ip.IP_HDR_LEN:
            raise dpkt.UnpackError('truncated IPv4 header')
        ihl = (raw[0] & 0x0f) * 4
        if ihl < ip.IP_HDR_LEN or ihl > len(raw):
            raise dpkt.UnpackError('invalid IPv4 header length: %r' % ihl)
        total_len = struct.unpack('>H', raw[2:4])[0]
        if total_len and total_len < ihl:
            raise dpkt.UnpackError('invalid IPv4 total length: %r' % total_len)
        end = min(total_len, len(raw)) if total_len else len(raw)
        payload = raw[ihl:end]

        flags_offset = struct.unpack('>H', raw[6:8])[0]
        offset = (flags_offset & ip.IP_OFFMASK) * 8
        more_fragments = bool(flags_offset & ip.IP_MF)
        if offset == 0 and not more_fragments:
            # not a fragment: nothing to reassemble
            return None

        src = raw[12:16]
        dst = raw[16:20]
        ident = struct.unpack('>H', raw[4:6])[0]
        key = (4, src, dst, ident, raw[9])
        if key in self.dead_keys:
            return None

        group = self._get_group(key, 4)
        if offset == 0 and group.first is None:
            group.first = {'header': raw[:ihl], 'ihl': ihl}
        if not self._accept(group, offset, payload):
            self._discard(group)
            return None
        if not more_fragments:
            self._set_end(group, offset + len(payload))

        return self._finish(group)

    def _build_v4(self, group, payload):
        """Rebuild a complete IPv4 datagram from the offset-0 fragment."""
        header = bytearray(group.first['header'])
        ihl = group.first['ihl']
        proto = header[9]
        src = bytes(header[12:16])
        dst = bytes(header[16:20])

        payload = _patch_transport(4, src, dst, payload, proto)
        total_len = ihl + len(payload)
        if total_len > ip.IP_LEN_MAX:
            # header options leave less room than the default payload limit
            self._record(group, REASON_OVERSIZE, 0, length=len(payload))
            self._discard(group)
            return None

        header[2:4] = struct.pack('>H', total_len)
        header[6:8] = b'\x00\x00'  # a rebuilt datagram is not a fragment
        header[10:12] = b'\x00\x00'
        header[10:12] = struct.pack('>H', _checksum(bytes(header)))
        return bytes(header) + payload

    # ------------------------------------------------------------------
    # IPv6
    # ------------------------------------------------------------------

    def _add_v6(self, raw):
        if len(raw) < _IP6_HDR_LEN:
            raise dpkt.UnpackError('truncated IPv6 header')
        fragment = _find_v6_fragment(raw)
        if fragment is None:
            # not a fragment: nothing to reassemble
            return None

        plen = struct.unpack('>H', raw[4:6])[0]
        end = min(_IP6_HDR_LEN + plen, len(raw)) if plen else len(raw)
        payload_start = fragment['offset'] + _IP6_FRAG_HDR_LEN
        payload = raw[payload_start:end]

        offset = fragment['frag_off'] * 8
        src = raw[8:24]
        dst = raw[24:40]
        key = (6, src, dst, fragment['id'], fragment['nxt'])
        if key in self.dead_keys:
            return None

        group = self._get_group(key, 6)
        if offset == 0 and group.first is None:
            group.first = {
                'prefix': raw[:fragment['offset']],
                'next_header_offset': fragment['next_header_offset'],
                'nxt': fragment['nxt'],
            }
        if not self._accept(group, offset, payload):
            self._discard(group)
            return None
        if not fragment['m_flag']:
            self._set_end(group, offset + len(payload))

        return self._finish(group)

    def _build_v6(self, group, payload):
        """Rebuild a complete IPv6 datagram, removing the Fragment Header."""
        prefix = bytearray(group.first['prefix'])
        proto = group.first['nxt']
        src = bytes(prefix[8:24])
        dst = bytes(prefix[24:40])

        payload = _patch_transport(6, src, dst, payload, proto)

        # the header in front of the removed Fragment Header now points
        # straight at the protocol it carried
        prefix[group.first['next_header_offset']] = proto
        plen = len(prefix) - _IP6_HDR_LEN + len(payload)
        if plen > IP6_MAX_PAYLOAD:
            self._record(group, REASON_OVERSIZE, 0, length=len(payload))
            self._discard(group)
            return None
        prefix[4:6] = struct.pack('>H', plen)
        return bytes(prefix) + payload


# Unit tests
#
# The fragments below are fixed byte streams (headers, lengths and checksums
# were computed by hand), so the tests do not depend on dpkt being able to
# serialize fragments itself.

# UDP over IPv4: 8-byte header + 40-byte payload, split 24/16/8
_V4_SRC = b'\x0a\x00\x00\x01'
_V4_DST = b'\x0a\x00\x00\x02'
_V4_UDP = (b'\x04\xd2\x00\x50\x00\x30\x00\x00'
           b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
           b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'
           b'\x20\x21\x22\x23\x24\x25\x26\x27')
_V4_F0 = (b'\x45\x00\x00\x2c\x12\x34\x20\x00\x40\x11\x34\x8b\x0a\x00\x00\x01'
          b'\x0a\x00\x00\x02\x04\xd2\x00\x50\x00\x30\x00\x00'
          b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f')
_V4_F1 = (b'\x45\x00\x00\x24\x12\x34\x20\x03\x40\x11\x34\x90\x0a\x00\x00\x01'
          b'\x0a\x00\x00\x02'
          b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f')
_V4_F2 = (b'\x45\x00\x00\x1c\x12\x34\x00\x05\x40\x11\x54\x96\x0a\x00\x00\x01'
          b'\x0a\x00\x00\x02\x20\x21\x22\x23\x24\x25\x26\x27')
# covers payload bytes 16..31, which _V4_F0 already supplied
_V4_EVIL = (b'\x45\x00\x00\x24\x12\x34\x20\x02\x40\x11\x34\x91\x0a\x00\x00\x01'
            b'\x0a\x00\x00\x02' + b'\xff' * 16)
# a complete, unfragmented IPv4 UDP packet
_V4_PLAIN = (b'\x45\x00\x00\x30\x12\x34\x00\x00\x40\x11\x54\x0e\x0a\x00\x00\x01'
             b'\x0a\x00\x00\x02' + _V4_UDP)

# UDP over IPv6 behind a Hop-by-Hop Options header, split 24/16/8
_V6_SRC = b'\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
_V6_DST = b'\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'
_V6_UDP = (b'\x1a\x0a\x00\x35\x00\x30\x00\x00'
           b'\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37'
           b'\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47'
           b'\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f')
_V6_HBH = b'\x2c' + b'\x00' * 7  # nxt=Fragment, len=0 (8 bytes total)
_V6_F0 = (b'\x60\x00\x00\x00\x00\x50\x00\x40'
          + _V6_SRC + _V6_DST
          + _V6_HBH
          + b'\x11\x00\x00\x01\x00\x00\x11\x11'  # UDP, offset 0, MF
          + _V6_UDP[:24])
_V6_F1 = (b'\x60\x00\x00\x00\x00\x48\x00\x40'
          + _V6_SRC + _V6_DST
          + _V6_HBH
          + b'\x11\x00\x00\x19\x00\x00\x11\x11'  # UDP, offset 24
          + _V6_UDP[24:40])
_V6_F2 = (b'\x60\x00\x00\x00\x00\x40\x00\x40'
          + _V6_SRC + _V6_DST
          + _V6_HBH
          + b'\x11\x00\x00\x28\x00\x00\x11\x11'  # UDP, offset 40, last
          + _V6_UDP[40:48])
# covers payload bytes 16..31, which _V6_F0 already supplied
_V6_EVIL = (b'\x60\x00\x00\x00\x00\x48\x00\x40'
            + _V6_SRC + _V6_DST
            + _V6_HBH
            + b'\x11\x00\x00\x11\x00\x00\x11\x11'  # offset 16
            + b'\xff' * 16)
# the same datagram without hop-by-hop: fragment header right after the
# fixed header, split 24/24
_V6_F0_NOHBH = (b'\x60\x00\x00\x00\x00\x48\x2c\x40'
                + _V6_SRC + _V6_DST
                + b'\x11\x00\x00\x01\x00\x00\x33\x33'
                + _V6_UDP[:24])
_V6_F1_NOHBH = (b'\x60\x00\x00\x00\x00\x48\x2c\x40'
                + _V6_SRC + _V6_DST
                + b'\x11\x00\x00\x18\x00\x00\x33\x33'
                + _V6_UDP[24:48])
# a complete IPv6 packet with no fragment header
_V6_PLAIN = (b'\x60\x00\x00\x00\x00\x30\x11\x40'
             + _V6_SRC + _V6_DST + _V6_UDP)

_V4_KEY = (4, _V4_SRC, _V4_DST, 0x1234, ip.IP_PROTO_UDP)
_V6_KEY = (6, _V6_SRC, _V6_DST, 0x1111, ip.IP_PROTO_UDP)


def _errors(errors):
    """Return the errors as (reason, offset) pairs for easy assertions."""
    return [(error.reason, error.offset) for error in errors]


def _without_checksum(segment):
    """Return a transport segment with its checksum field zeroed."""
    return segment[:6] + b'\x00\x00' + segment[8:]


def test_v4_reassembly_in_order():
    from . import udp

    reasm = IPFragmentReassembler()
    assert reasm.add(_V4_F0) is None
    assert reasm.add(_V4_F1) is None
    out = reasm.add(_V4_F2)
    assert out is not None

    parsed = ip.IP(out)
    assert parsed.len == len(out)
    assert parsed.mf == 0 and parsed.offset == 0
    assert isinstance(parsed.data, udp.UDP)
    assert _without_checksum(bytes(parsed.data)) == _V4_UDP  # checksum recomputed
    assert parsed.udp.ulen == len(_V4_UDP)
    # the IPv4 header checksum covers the recomputed whole header
    assert dpkt.in_cksum(out[:parsed.hl * 4]) == 0
    # the UDP checksum covers pseudo-header + the whole segment
    assert parsed.udp.sum == _transport_checksum(4, _V4_SRC, _V4_DST,
                                                 ip.IP_PROTO_UDP, _V4_UDP)
    assert bytes(ip.IP(out)) == out
    assert reasm.errors == []
    assert reasm.groups == {}


def test_v4_out_of_order_and_duplicate():
    reasm = IPFragmentReassembler()
    assert reasm.add(_V4_F2) is None
    assert reasm.add(_V4_F0) is None
    assert reasm.add(_V4_F0) is None  # identical duplicate
    out = reasm.add(_V4_F1)
    assert out is not None
    assert ip.IP(out).data.data == _V4_UDP[8:]
    # the duplicate itself was absorbed silently; the audit log only holds
    # the transient no-first-fragment and gap that later fragments repaired
    assert _errors(reasm.errors) == [(REASON_NO_FIRST_FRAGMENT, 0),
                                     (REASON_GAP, 24)]
    assert reasm.groups == {}


def test_v4_overlap_first_arrival_wins():
    reasm = IPFragmentReassembler()
    assert reasm.add(_V4_F0) is None
    assert reasm.add(_V4_EVIL) is None  # overlaps 16..31, arrives late
    assert _errors(reasm.groups[_V4_KEY].errors) == [(REASON_OVERLAP, 16)]
    assert _errors(reasm.errors) == [(REASON_OVERLAP, 16)]
    assert reasm.errors[0].key == _V4_KEY
    assert reasm.add(_V4_F1) is None
    out = reasm.add(_V4_F2)
    assert out is not None
    # first-come wins: F0 kept 16..23, and _V4_EVIL arrived before _V4_F1,
    # so its bytes 24..31 are kept too
    expected = _V4_UDP[:24] + b'\xff' * 8 + _V4_UDP[32:]
    assert _without_checksum(bytes(ip.IP(out).data)) == expected


def test_v4_gap_recorded():
    reasm = IPFragmentReassembler()
    reasm.add(_V4_F0)
    assert reasm.add(_V4_F2) is None
    # F0 covers 0..23 and F2 starts at 40: the hole begins at 24
    assert _errors(reasm.groups[_V4_KEY].errors) == [(REASON_GAP, 24)]
    # filling the hole clears the transient gap and completes the datagram
    out = reasm.add(_V4_F1)
    assert out is not None
    assert _without_checksum(bytes(ip.IP(out).data)) == _V4_UDP
    assert reasm.groups == {}
    # the audit log keeps the gap that was seen, even though it was filled
    assert _errors(reasm.errors) == [(REASON_GAP, 24)]


def test_v4_missing_first_fragment():
    reasm = IPFragmentReassembler()
    assert reasm.add(_V4_F2) is None
    assert _errors(reasm.groups[_V4_KEY].errors) == [
        (REASON_NO_FIRST_FRAGMENT, 0)]
    # the datagram can still be completed once the first fragment arrives
    reasm.add(_V4_F0)
    out = reasm.add(_V4_F1)
    assert out is not None
    assert _without_checksum(bytes(ip.IP(out).data)) == _V4_UDP


def test_v4_oversize():
    reasm = IPFragmentReassembler(max_payload_v4=32)
    reasm.add(_V4_F0)
    assert reasm.add(_V4_F2) is None  # 40..47 lies past the 32-byte limit
    assert _errors(reasm.errors) == [(REASON_OVERSIZE, 40)]
    assert reasm.errors[0].length == 8
    assert reasm.groups == {}
    assert _V4_KEY in reasm.dead_keys


def test_v6_reassembly_in_order():
    from . import udp

    reasm = IPFragmentReassembler()
    assert reasm.add(_V6_F0) is None
    assert reasm.add(_V6_F1) is None
    out = reasm.add(_V6_F2)
    assert out is not None

    parsed = ip6.IP6(out)
    assert isinstance(parsed.data, udp.UDP)
    assert _without_checksum(bytes(parsed.data)) == _V6_UDP  # checksum recomputed
    assert parsed.udp.ulen == len(_V6_UDP)
    assert parsed.plen == len(out) - ip6.IP6.__hdr_len__
    # the Fragment Header is gone, the Hop-by-Hop header is preserved
    assert ip.IP_PROTO_HOPOPTS in parsed.extension_hdrs
    assert ip.IP_PROTO_FRAGMENT not in parsed.extension_hdrs
    assert parsed.udp.sum == _transport_checksum(6, _V6_SRC, _V6_DST,
                                                 ip.IP_PROTO_UDP, _V6_UDP)
    assert bytes(ip6.IP6(out)) == out
    assert reasm.errors == []
    assert reasm.groups == {}


def test_v6_fragment_header_behind_hopbyhop_is_not_misparsed():
    from . import udp

    # the Fragment Header follows Hop-by-Hop, so it is only found by
    # walking the chain; non-first fragments stay raw instead of having
    # their mid-datagram bytes decoded as UDP
    first = ip6.IP6(_V6_F0)
    assert ip.IP_PROTO_HOPOPTS in first.extension_hdrs
    assert ip.IP_PROTO_FRAGMENT in first.extension_hdrs
    assert first.extension_hdrs[ip.IP_PROTO_FRAGMENT].frag_off == 0
    middle = ip6.IP6(_V6_F1)
    assert middle.extension_hdrs[ip.IP_PROTO_FRAGMENT].frag_off == 3
    assert not isinstance(middle.data, udp.UDP)
    assert middle.data == _V6_UDP[24:40]

    reasm = IPFragmentReassembler()
    reasm.add(_V6_F0)
    assert reasm.add(_V6_F1) is None  # 40..47 still missing
    out = reasm.add(_V6_F2)
    assert ip6.IP6(out).udp.data == _V6_UDP[8:]


def test_v6_fragment_without_extension_headers():
    reasm = IPFragmentReassembler()
    assert reasm.add(_V6_F0_NOHBH) is None
    out = reasm.add(_V6_F1_NOHBH)
    assert out is not None
    parsed = ip6.IP6(out)
    assert parsed.nxt == ip.IP_PROTO_UDP
    assert parsed.data.data == _V6_UDP[8:]


def test_v6_overlap_discards_whole_group():
    reasm = IPFragmentReassembler()
    reasm.add(_V6_F0)
    assert reasm.add(_V6_EVIL) is None
    # the error survives the group being discarded
    assert _errors(reasm.errors) == [(REASON_OVERLAP, 16)]
    assert reasm.errors[0].key == _V6_KEY
    assert reasm.groups == {}
    assert _V6_KEY in reasm.dead_keys
    # every later fragment of that datagram is rejected
    assert reasm.add(_V6_F1) is None
    assert reasm.add(_V6_F2) is None
    assert reasm.groups == {}


def test_v6_exact_duplicate_is_not_an_overlap():
    # identical retransmissions are harmless, unlike conflicting overlaps
    reasm = IPFragmentReassembler()
    reasm.add(_V6_F0)
    assert reasm.add(_V6_F0) is None
    assert reasm.add(_V6_F1) is None
    out = reasm.add(_V6_F2)
    assert out is not None
    assert ip6.IP6(out).udp.data == _V6_UDP[8:]
    assert reasm.errors == []


def test_v6_gap_and_completion():
    reasm = IPFragmentReassembler()
    reasm.add(_V6_F0)
    assert reasm.add(_V6_F2) is None
    # F0 covers 0..23 and F2 starts at 40: the hole begins at 24
    assert _errors(reasm.groups[_V6_KEY].errors) == [(REASON_GAP, 24)]
    out = reasm.add(_V6_F1)
    assert out is not None
    assert _V6_KEY not in reasm.groups


def test_v6_oversize_discards_group():
    reasm = IPFragmentReassembler(max_payload_v6=32)
    reasm.add(_V6_F0)
    assert reasm.add(_V6_F2) is None
    assert _errors(reasm.errors) == [(REASON_OVERSIZE, 40)]
    assert reasm.groups == {}
    assert _V6_KEY in reasm.dead_keys


def test_v6_icmpv6_checksum():
    from . import icmp6

    echo = icmp6.ICMP6(type=icmp6.ICMP6_ECHO_REQUEST, code=0, data=b'Q' * 24)
    full = bytes(echo)
    f0 = (b'\x60\x00\x00\x00\x00\x10\x2c\x40' + _V6_SRC + _V6_DST
          + b'\x3a\x00\x00\x01\x00\x00\x44\x44' + full[:8])
    f1 = (b'\x60\x00\x00\x00\x00\x1c\x2c\x40' + _V6_SRC + _V6_DST
          + b'\x3a\x00\x00\x08\x00\x00\x44\x44' + full[8:])

    reasm = IPFragmentReassembler()
    assert reasm.add(f0) is None
    out = reasm.add(f1)
    assert out is not None
    parsed = ip6.IP6(out)
    assert isinstance(parsed.data, icmp6.ICMP6)
    # ICMPv6 keeps its checksum at transport offset 2, not 6
    assert parsed.data.sum == _transport_checksum(6, _V6_SRC, _V6_DST,
                                                  ip.IP_PROTO_ICMP6, full)
    assert bytes(ip6.IP6(out)) == out


def test_accepts_parsed_packets():
    reasm = IPFragmentReassembler()
    reasm.add(ip.IP(_V4_F0))
    reasm.add(ip.IP(_V4_F1))
    out = reasm.add(ip.IP(_V4_F2))
    assert _without_checksum(bytes(ip.IP(out).data)) == _V4_UDP

    reasm = IPFragmentReassembler()
    reasm.add(ip6.IP6(_V6_F0))
    reasm.add(ip6.IP6(_V6_F1))
    out = reasm.add(ip6.IP6(_V6_F2))
    assert ip6.IP6(out).udp.data == _V6_UDP[8:]


def test_add_all_interleaved():
    reasm = IPFragmentReassembler()
    out = reasm.add_all(
        [_V4_F2, _V6_F0, _V4_F0, _V6_F1, _V4_F1, _V6_F2, _V4_F0])
    assert len(out) == 2
    assert _without_checksum(bytes(ip.IP(out[0]).data)) == _V4_UDP
    assert ip6.IP6(out[1]).udp.data == _V6_UDP[8:]


def test_non_fragments_are_ignored():
    reasm = IPFragmentReassembler()
    assert reasm.add(_V4_PLAIN) is None
    assert reasm.add(_V6_PLAIN) is None
    assert reasm.groups == {}
    assert reasm.errors == []


def test_purge():
    reasm = IPFragmentReassembler(timeout=0.01)
    reasm.add(_V4_F0)
    assert len(reasm.groups) == 1
    time.sleep(0.02)
    assert reasm.purge() == [_V4_KEY]
    assert reasm.groups == {}
    assert IPFragmentReassembler(timeout=None).purge() == []


def test_fragment_error_shape():
    error = FragmentError(REASON_GAP, 3)
    assert error.reason == REASON_GAP and error.offset == 3
    assert error.key is None and error.length is None
    assert error == FragmentError(REASON_GAP, 3)
    assert error != FragmentError(REASON_GAP, 4)
    assert 'reason' in repr(error) and 'offset' in repr(error)

    group = FragmentGroup(('k',), 4, None)
    group.record(REASON_GAP, 3)
    assert _errors(group.errors) == [(REASON_GAP, 3)]
    assert group.has_error(REASON_GAP) and not group.has_error(REASON_GAP, 4)
    assert group.deadline is None


def test_rejects_non_ip():
    import pytest

    reasm = IPFragmentReassembler()
    for bad in (b'', b'\x00' * 20, b'\x40' + b'\x00' * 19, 'not a packet'):
        with pytest.raises(dpkt.UnpackError):
            reasm.add(bad)
