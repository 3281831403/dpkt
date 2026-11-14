# $Id: sctp.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Stream Control Transmission Protocol."""
from __future__ import print_function
from __future__ import absolute_import

import struct

from . import dpkt
from . import crc32c

# Stream Control Transmission Protocol
# http://tools.ietf.org/html/rfc2960

# Chunk Types
DATA = 0
INIT = 1
INIT_ACK = 2
SACK = 3
HEARTBEAT = 4
HEARTBEAT_ACK = 5
ABORT = 6
SHUTDOWN = 7
SHUTDOWN_ACK = 8
ERROR = 9
COOKIE_ECHO = 10
COOKIE_ACK = 11
ECNE = 12
CWR = 13
SHUTDOWN_COMPLETE = 14

# DATA chunk flags (RFC 4960, section 3.3.1)
DATA_ENDING = 0x01      # E bit: last fragment of a user message
DATA_BEGINNING = 0x02   # B bit: first fragment of a user message
DATA_UNORDERED = 0x04   # U bit: unordered user message


class SCTP(dpkt.Packet):
    """Stream Control Transmission Protocol.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of SCTP.
        TODO.
    """

    __hdr__ = (
        ('sport', 'H', 0),
        ('dport', 'H', 0),
        ('vtag', 'I', 0),
        ('sum', 'I', 0)
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        l_ = []
        while self.data:
            chunk = Chunk(self.data)
            l_.append(chunk)
            if len(chunk) == 0:
                self.data = b''
                break
            self.data = self.data[len(chunk):]
        self.chunks = l_

    def __len__(self):
        return self.__hdr_len__ + sum(len(x) for x in self.chunks)

    def __bytes__(self):
        l_ = [bytes(x) for x in self.chunks]
        if self.sum == 0:
            s = crc32c.add(0xffffffff, self.pack_hdr())
            for x in l_:
                s = crc32c.add(s, x)
            self.sum = crc32c.done(s)
        return self.pack_hdr() + b''.join(l_)


class Chunk(dpkt.Packet):
    __hdr__ = (
        ('type', 'B', INIT),
        ('flags', 'B', 0),
        ('len', 'H', 0)
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)

        self.data = self.data[:self.len - self.__hdr_len__]
        self.padding = b''  # optional padding

        # Every chunk is padded to a 4-byte boundary (RFC 4960, section 3.2);
        # the padding is not included in the chunk length field.
        if self.len >= self.__hdr_len__ and self.len % 4:
            plen = 4 - self.len % 4  # padded length
            if plen:
                pos = self.__hdr_len__ + len(self.data)  # end of data in buf
                self.padding = buf[pos:pos + plen]

    def __len__(self):
        return self.len + len(self.padding)

    def __bytes__(self):
        return self.pack_hdr() + bytes(self.data) + self.padding

    # DATA chunk header fields (RFC 4960, section 3.3.1). These are views
    # onto self.data, so parsing and packing are not affected by them.
    # Each returns None for non-DATA chunks or truncated DATA headers.

    @property
    def tsn(self):
        """Transmission Sequence Number of a DATA chunk."""
        if self.type == DATA and len(self.data) >= 4:
            return struct.unpack('>I', self.data[:4])[0]

    @property
    def stream_id(self):
        """Stream identifier of a DATA chunk."""
        if self.type == DATA and len(self.data) >= 6:
            return struct.unpack('>H', self.data[4:6])[0]

    @property
    def stream_seq(self):
        """Stream sequence number of a DATA chunk."""
        if self.type == DATA and len(self.data) >= 8:
            return struct.unpack('>H', self.data[6:8])[0]

    @property
    def ppid(self):
        """Payload protocol identifier of a DATA chunk."""
        if self.type == DATA and len(self.data) >= 12:
            return struct.unpack('>I', self.data[8:12])[0]

    @property
    def payload(self):
        """User data of a DATA chunk (None if the DATA header is truncated)."""
        if self.type == DATA and len(self.data) >= 12:
            return self.data[12:]

    @property
    def unordered(self):
        """U bit of a DATA chunk: user message is unordered."""
        return bool(self.flags & DATA_UNORDERED)

    @property
    def beginning(self):
        """B bit of a DATA chunk: first fragment of a user message."""
        return bool(self.flags & DATA_BEGINNING)

    @property
    def ending(self):
        """E bit of a DATA chunk: last fragment of a user message."""
        return bool(self.flags & DATA_ENDING)


class Message(object):
    """A user message reassembled from the DATA chunks of one SCTP association.

    Attributes:
        stream_id: (int) stream the message was received on.
        stream_seq: (int) stream sequence number.
        tsn_first: (int) TSN of the first (B) fragment.
        tsn_last: (int) TSN of the last (E) fragment.
        ppid: (int) payload protocol identifier.
        unordered: (bool) True if the U bit was set.
        data: (bytes) reassembled user data.
    """

    __slots__ = ('stream_id', 'stream_seq', 'tsn_first', 'tsn_last', 'ppid', 'unordered', 'data')

    def __init__(self, stream_id, stream_seq, tsn_first, tsn_last, ppid, unordered, data):
        self.stream_id = stream_id
        self.stream_seq = stream_seq
        self.tsn_first = tsn_first
        self.tsn_last = tsn_last
        self.ppid = ppid
        self.unordered = unordered
        self.data = data

    def __repr__(self):
        return ('Message(stream_id=%r, stream_seq=%r, tsn_first=%r, tsn_last=%r, ppid=%r, unordered=%r, data=%r)'
                % (self.stream_id, self.stream_seq, self.tsn_first, self.tsn_last, self.ppid, self.unordered,
                   self.data))

    def __eq__(self, other):
        return (isinstance(other, Message) and
                all(getattr(self, k) == getattr(other, k) for k in self.__slots__))

    def __ne__(self, other):
        return not self.__eq__(other)


class Association(object):
    """Reassembles the user messages of a single SCTP association.

    Feed one SCTP packet (bytes, starting at the SCTP common header) per
    call to feed(); each call returns the list of Message objects that
    became deliverable. Fragments are merged by B/E bits, ordered messages
    are released per stream in stream-sequence order, retransmitted TSNs
    are dropped, and missing TSNs are recorded in gaps. Parse problems are
    appended to errors (truncated chunks included) and never raised.

    Note: TSN wraparound at 2**32 is not handled; it does not occur in
    practice for captured or relayed packet sequences of realistic size.
    """

    def __init__(self):
        self.errors = []        # parse problems, recorded as strings
        self.duplicates = 0     # retransmitted DATA chunks dropped by TSN
        self._gaps = []         # open TSN gaps, as [first_tsn, last_tsn] lists
        self._tsns = set()      # seen TSNs above _cum_tsn
        self._cum_tsn = None    # every TSN <= this has been seen
        self._max_tsn = None    # highest TSN seen so far
        self._frags = {}        # (stream_id, stream_seq) -> fragment buffer
        self._stream_tsns = {}  # stream_id -> set of TSNs seen on that stream
        self._pending = {}      # stream_id -> {stream_seq: Message} awaiting in-order release
        self._next_ssn = {}     # stream_id -> next expected ordered stream sequence

    @property
    def gaps(self):
        """Open TSN gaps as a list of (first_tsn, last_tsn) tuples."""
        return [tuple(g) for g in self._gaps]

    def feed(self, buf):
        """Feed one SCTP packet; return newly deliverable Message objects."""
        delivered = []
        if len(buf) < SCTP.__hdr_len__:
            self.errors.append('truncated SCTP header: %d of %d bytes' % (len(buf), SCTP.__hdr_len__))
            return delivered
        off = SCTP.__hdr_len__
        end = len(buf)
        while off < end:
            if end - off < Chunk.__hdr_len__:
                self.errors.append('truncated chunk header at offset %d: %d bytes left' % (off, end - off))
                break
            try:
                chunk = Chunk(buf[off:])
            except dpkt.UnpackError as e:
                self.errors.append('bad chunk at offset %d: %s' % (off, e))
                break
            if chunk.len < Chunk.__hdr_len__:
                self.errors.append('invalid chunk length %d at offset %d' % (chunk.len, off))
                break
            if off + chunk.len > end:
                self.errors.append('truncated chunk at offset %d: type %d declares %d bytes, %d available'
                                   % (off, chunk.type, chunk.len, end - off))
                break
            if chunk.type == DATA:
                delivered.extend(self._feed_data(chunk))
            off += (chunk.len + 3) & ~3  # chunks are 4-byte aligned
        return delivered

    def _feed_data(self, chunk):
        """Process one DATA chunk; return newly deliverable messages."""
        if len(chunk.data) < 12:
            self.errors.append('short DATA chunk: %d bytes after chunk header, need at least 12'
                               % len(chunk.data))
            return []
        tsn = chunk.tsn
        if self._cum_tsn is None:
            # the first TSN seen defines the baseline; nothing before it counts as missing
            self._cum_tsn = tsn - 1
            self._max_tsn = tsn - 1
        if tsn <= self._cum_tsn or tsn in self._tsns:
            self.duplicates += 1  # retransmission
            return []
        self._tsns.add(tsn)
        self._note_tsn(tsn)
        while self._cum_tsn + 1 in self._tsns:
            self._cum_tsn += 1
            self._tsns.discard(self._cum_tsn)

        sid = chunk.stream_id
        ssn = chunk.stream_seq
        frag = self._frags.get((sid, ssn))
        if frag is None:
            frag = self._frags[(sid, ssn)] = {
                'ppid': chunk.ppid, 'unordered': chunk.unordered,
                'parts': {}, 'begin': None, 'end': None,
            }
        frag['parts'][tsn] = chunk.payload
        if chunk.beginning:
            frag['begin'] = tsn
        if chunk.ending:
            frag['end'] = tsn
        stream_tsns = self._stream_tsns.setdefault(sid, set())
        stream_tsns.add(tsn)

        begin, end, parts = frag['begin'], frag['end'], frag['parts']
        if begin is None or end is None:
            return []
        # Fragments of one message are never interleaved with other messages
        # of the same stream, so every TSN of this stream between B and E
        # is a fragment of this message; all of them must be present.
        for t in stream_tsns:
            if begin <= t <= end and t not in parts:
                return []  # a fragment is still missing
        del self._frags[(sid, ssn)]
        tsns = sorted(parts)
        msg = Message(stream_id=sid, stream_seq=ssn, tsn_first=tsns[0], tsn_last=tsns[-1],
                      ppid=frag['ppid'], unordered=frag['unordered'],
                      data=b''.join(parts[t] for t in tsns))
        return self._deliver(msg)

    def _note_tsn(self, tsn):
        """Open or fill TSN gaps for a freshly seen, non-duplicate TSN."""
        if tsn > self._max_tsn:
            if tsn > self._max_tsn + 1:
                self._gaps.append([self._max_tsn + 1, tsn - 1])
            self._max_tsn = tsn
            return
        # a late (reordered) TSN fills part of an open gap
        for gap in self._gaps:
            if gap[0] <= tsn <= gap[1]:
                if tsn == gap[0] == gap[1]:
                    self._gaps.remove(gap)
                elif tsn == gap[0]:
                    gap[0] = tsn + 1
                elif tsn == gap[1]:
                    gap[1] = tsn - 1
                else:
                    self._gaps.append([tsn + 1, gap[1]])
                    gap[1] = tsn - 1
                return

    def _deliver(self, msg):
        """Release a complete message, buffering ordered ones per stream."""
        if msg.unordered:
            return [msg]
        pending = self._pending.setdefault(msg.stream_id, {})
        if msg.stream_id not in self._next_ssn:
            # first ordered message on this stream defines the baseline
            self._next_ssn[msg.stream_id] = msg.stream_seq
        pending[msg.stream_seq] = msg
        out = []
        nxt = self._next_ssn[msg.stream_id]
        while nxt in pending:
            out.append(pending.pop(nxt))
            nxt = (nxt + 1) & 0xFFFF
        self._next_ssn[msg.stream_id] = nxt
        return out


__s = (b'\x80\x44\x00\x50\x00\x00\x00\x00\x30\xba\xef\x54\x01\x00\x00\x3c\x3b\xb9\x9c\x46\x00\x01'
       b'\xa0\x00\x00\x0a\xff\xff\x2b\x2d\x7e\xb2\x00\x05\x00\x08\x9b\xe6\x18\x9b\x00\x05\x00\x08'
       b'\x9b\xe6\x18\x9c\x00\x0c\x00\x06\x00\x05\x00\x00\x80\x00\x00\x04\xc0\x00\x00\x04\xc0\x06'
       b'\x00\x08\x00\x00\x00\x00')


def test_sctp_pack():
    sctp = SCTP(__s)
    assert (__s == bytes(sctp))
    sctp.sum = 0
    assert (__s == bytes(sctp))


def test_sctp_unpack():
    sctp = SCTP(__s)
    assert (sctp.sport == 32836)
    assert (sctp.dport == 80)
    assert (len(sctp.chunks) == 1)
    assert (len(sctp) == 72)
    chunk = sctp.chunks[0]
    assert (chunk.type == INIT)
    assert (chunk.len == 60)


def test_sctp_data_chunk():  # https://github.com/kbandla/dpkt/issues/499
    # packet 5 from 'sctp-www.cap' downloaded from https://wiki.wireshark.org/SampleCaptures
    # chunk len == 419 so requires padding to a 4-byte boundary
    d = (b'\x80\x44\x00\x50\xd2\x6a\xc1\xe5\x70\xe5\x5b\x4c\x00\x03\x01\xa3\x2b\x2d\x7e\xb2\x00\x00'
         b'\x00\x00\x00\x00\x00\x00\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a'
         b'\x48\x6f\x73\x74\x3a\x20\x32\x30\x33\x2e\x32\x35\x35\x2e\x32\x35\x32\x2e\x31\x39\x34\x0d'
         b'\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35'
         b'\x2e\x30\x20\x28\x58\x31\x31\x3b\x20\x55\x3b\x20\x4c\x69\x6e\x75\x78\x20\x69\x36\x38\x36'
         b'\x3b\x20\x6b\x6f\x2d\x4b\x52\x3b\x20\x72\x76\x3a\x31\x2e\x37\x2e\x31\x32\x29\x20\x47\x65'
         b'\x63\x6b\x6f\x2f\x32\x30\x30\x35\x31\x30\x30\x37\x20\x44\x65\x62\x69\x61\x6e\x2f\x31\x2e'
         b'\x37\x2e\x31\x32\x2d\x31\x0d\x0a\x41\x63\x63\x65\x70\x74\x3a\x20\x74\x65\x78\x74\x2f\x78'
         b'\x6d\x6c\x2c\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x6d\x6c\x2c\x61\x70\x70'
         b'\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x68\x74\x6d\x6c\x2b\x78\x6d\x6c\x2c\x74\x65\x78'
         b'\x74\x2f\x68\x74\x6d\x6c\x3b\x71\x3d\x30\x2e\x39\x2c\x74\x65\x78\x74\x2f\x70\x6c\x61\x69'
         b'\x6e\x3b\x71\x3d\x30\x2e\x38\x2c\x69\x6d\x61\x67\x65\x2f\x70\x6e\x67\x2c\x2a\x2f\x2a\x3b'
         b'\x71\x3d\x30\x2e\x35\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x4c\x61\x6e\x67\x75\x61\x67\x65'
         b'\x3a\x20\x6b\x6f\x2c\x65\x6e\x2d\x75\x73\x3b\x71\x3d\x30\x2e\x37\x2c\x65\x6e\x3b\x71\x3d'
         b'\x30\x2e\x33\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x45\x6e\x63\x6f\x64\x69\x6e\x67\x3a\x20'
         b'\x67\x7a\x69\x70\x2c\x64\x65\x66\x6c\x61\x74\x65\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x43'
         b'\x68\x61\x72\x73\x65\x74\x3a\x20\x45\x55\x43\x2d\x4b\x52\x2c\x75\x74\x66\x2d\x38\x3b\x71'
         b'\x3d\x30\x2e\x37\x2c\x2a\x3b\x71\x3d\x30\x2e\x37\x0d\x0a\x4b\x65\x65\x70\x2d\x41\x6c\x69'
         b'\x76\x65\x3a\x20\x33\x30\x30\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a\x20\x6b'
         b'\x65\x65\x70\x2d\x61\x6c\x69\x76\x65\x0d\x0a\x0d\x0a\x00')  # <-- ends with \x00 padding

    sctp = SCTP(d)
    assert sctp.chunks
    assert len(sctp.chunks) == 1

    ch = sctp.chunks[0]
    assert ch.type == DATA
    assert ch.len == 419
    assert len(ch) == 420  # 419 +1 byte padding
    assert ch.data[-14:] == b'keep-alive\r\n\r\n'  # no padding byte at the end

    # no remaining sctp data
    assert sctp.data == b''

    # test packing of the padded chunk
    assert bytes(ch) == d[SCTP.__hdr_len__:]
  


def test_malformed_sctp_data_chunk():  
    # packet 7964 from '4.pcap' downloaded from https://research.unsw.edu.au/projects/unsw-nb15-dataset
    d = (b'\x27\x0f\xe1\xc3\xc2\x73\x4d\x32\x4f\x54\x27\x8c' #header
         b'\x0b\x00\x00\x04' #chunk 0, COOKIE_ACK chunk
         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00') #chunk 1, malformed DATA chunk, size labeled as 0


    sctp = SCTP(d)
    assert sctp.chunks
    assert len(sctp.chunks) == 2

    ch = sctp.chunks[1]
    assert ch.type == DATA
    assert ch.len == 0
    assert len(ch) == 0
    assert ch.data == b'\x00\x00'

    # no remaining sctp data
    assert sctp.data == b''


# --- reassembly tests: fixed packet sequences -------------------------------


def _data_chunk(tsn, stream_id, stream_seq, ppid=0, flags=0, payload=b''):
    body = struct.pack('>IHHI', tsn, stream_id, stream_seq, ppid) + payload
    clen = 4 + len(body)
    pad = b'\x00' * ((-clen) % 4)
    return struct.pack('>BBH', DATA, flags, clen) + body + pad


def _heartbeat_chunk(info=b'\x00\x01\x00\x05\xaa'):  # len 9 -> 3 bytes padding
    clen = 4 + len(info)
    pad = b'\x00' * ((-clen) % 4)
    return struct.pack('>BBH', HEARTBEAT, 0, clen) + info + pad


def _packet(*chunks):
    return struct.pack('>HHII', 5060, 5060, 0x1234, 0) + b''.join(chunks)


def test_data_chunk_fields():
    ch = Chunk(_data_chunk(0x01020304, 3, 7, ppid=46, flags=DATA_BEGINNING | DATA_ENDING, payload=b'diameter'))
    assert ch.type == DATA
    assert ch.tsn == 0x01020304
    assert ch.stream_id == 3
    assert ch.stream_seq == 7
    assert ch.ppid == 46
    assert ch.payload == b'diameter'
    assert ch.beginning and ch.ending and not ch.unordered
    # non-DATA chunks have no DATA fields
    hb = Chunk(_heartbeat_chunk())
    assert hb.tsn is None and hb.stream_id is None and hb.payload is None


def test_non_data_chunk_padding():
    # a padded HEARTBEAT bundled before a DATA chunk must not desynchronise
    # the chunk walk (previously only DATA chunks consumed padding)
    hb = _heartbeat_chunk()
    dc = _data_chunk(100, 3, 7, flags=DATA_BEGINNING | DATA_ENDING, payload=b'diameter')
    sctp = SCTP(_packet(hb, dc))
    assert len(sctp.chunks) == 2
    assert sctp.chunks[0].type == HEARTBEAT
    assert len(sctp.chunks[0].padding) == 3
    assert sctp.chunks[1].type == DATA
    assert sctp.chunks[1].tsn == 100
    assert sctp.chunks[1].payload == b'diameter'
    assert sctp.data == b''
    # packing is unchanged
    assert bytes(sctp.chunks[0]) == hb
    assert bytes(sctp.chunks[1]) == dc


def test_association_in_order():
    a = Association()
    msgs = a.feed(_packet(_data_chunk(1, 0, 0, flags=DATA_BEGINNING | DATA_ENDING, payload=b'aaa')))
    assert len(msgs) == 1
    m = msgs[0]
    assert (m.stream_id, m.stream_seq, m.tsn_first, m.tsn_last) == (0, 0, 1, 1)
    assert m.data == b'aaa'
    assert not m.unordered
    msgs = a.feed(_packet(_data_chunk(2, 0, 1, flags=DATA_BEGINNING | DATA_ENDING, payload=b'bbb')))
    assert [m.data for m in msgs] == [b'bbb']
    assert a.errors == [] and a.gaps == [] and a.duplicates == 0


def test_association_bundled_chunks_with_padding():
    a = Association()
    pkt = _packet(_heartbeat_chunk(),
                  _data_chunk(1, 0, 0, flags=DATA_BEGINNING | DATA_ENDING, payload=b'diameter'))
    msgs = a.feed(pkt)
    assert [m.data for m in msgs] == [b'diameter']
    assert a.errors == []


def test_association_fragment_reassembly():
    a = Association()
    assert a.feed(_packet(_data_chunk(10, 1, 5, flags=DATA_BEGINNING, payload=b'Hel'))) == []
    assert a.feed(_packet(_data_chunk(11, 1, 5, flags=0, payload=b'lo '))) == []
    msgs = a.feed(_packet(_data_chunk(12, 1, 5, flags=DATA_ENDING, payload=b'world')))
    assert len(msgs) == 1
    assert msgs[0].data == b'Hello world'
    assert (msgs[0].stream_id, msgs[0].stream_seq) == (1, 5)
    assert (msgs[0].tsn_first, msgs[0].tsn_last) == (10, 12)
    assert a.errors == []


def test_association_interleaved_streams():
    # fragments of stream 0 interleave with a complete message on stream 1
    a = Association()
    assert a.feed(_packet(_data_chunk(1, 0, 0, flags=DATA_BEGINNING, payload=b'AA'))) == []
    msgs = a.feed(_packet(_data_chunk(2, 1, 0, flags=DATA_BEGINNING | DATA_ENDING, payload=b'x')))
    assert [m.data for m in msgs] == [b'x']
    msgs = a.feed(_packet(_data_chunk(3, 0, 0, flags=DATA_ENDING, payload=b'BB')))
    assert len(msgs) == 1
    assert msgs[0].data == b'AABB'
    assert (msgs[0].tsn_first, msgs[0].tsn_last) == (1, 3)
    assert a.errors == []


def test_association_out_of_order_and_gap_fill():
    a = Association()
    msgs = a.feed(_packet(_data_chunk(1, 0, 0, flags=DATA_BEGINNING | DATA_ENDING, payload=b'm0')))
    assert [m.data for m in msgs] == [b'm0']
    # tsn 3 (stream seq 2) arrives before tsn 2 (stream seq 1):
    # a TSN gap opens and ordered delivery is held
    assert a.feed(_packet(_data_chunk(3, 0, 2, flags=DATA_BEGINNING | DATA_ENDING, payload=b'm2'))) == []
    assert a.gaps == [(2, 2)]
    # tsn 2 arrives: the gap closes and both messages are released in order
    msgs = a.feed(_packet(_data_chunk(2, 0, 1, flags=DATA_BEGINNING | DATA_ENDING, payload=b'm1')))
    assert a.gaps == []
    assert [m.data for m in msgs] == [b'm1', b'm2']
    assert a.duplicates == 0
    assert a.errors == []


def test_association_permanent_gap():
    a = Association()
    a.feed(_packet(_data_chunk(1, 0, 0, flags=DATA_BEGINNING | DATA_ENDING, payload=b'm0')))
    a.feed(_packet(_data_chunk(3, 0, 1, flags=DATA_BEGINNING | DATA_ENDING, payload=b'm1')))
    assert a.gaps == [(2, 2)]


def test_association_duplicate_tsn():
    a = Association()
    pkt = _packet(_data_chunk(5, 0, 0, flags=DATA_BEGINNING | DATA_ENDING, payload=b'x'))
    assert len(a.feed(pkt)) == 1
    assert a.feed(pkt) == []  # retransmission is dropped
    assert a.duplicates == 1
    assert a.errors == []


def test_association_unordered_delivery():
    a = Association()
    a.feed(_packet(_data_chunk(1, 0, 0, flags=DATA_BEGINNING | DATA_ENDING, payload=b'm0')))
    # unordered messages are delivered immediately, even with a stream seq gap
    msgs = a.feed(_packet(_data_chunk(2, 0, 2, flags=DATA_BEGINNING | DATA_ENDING | DATA_UNORDERED,
                                      payload=b'u')))
    assert len(msgs) == 1
    assert msgs[0].data == b'u'
    assert msgs[0].unordered


def test_association_truncated_chunk():
    a = Association()
    good = _data_chunk(1, 0, 0, flags=DATA_BEGINNING | DATA_ENDING, payload=b'ok')
    # a chunk header declaring 100 bytes followed by only 3
    pkt = _packet(good) + struct.pack('>BBH', DATA, 0, 100) + b'\x00' * 3
    msgs = a.feed(pkt)
    assert [m.data for m in msgs] == [b'ok']  # earlier chunks still processed
    assert len(a.errors) == 1
    assert 'truncated chunk' in a.errors[0]


def test_association_truncated_chunk_header():
    a = Association()
    msgs = a.feed(_packet() + b'\x00\x00')  # 2 bytes, less than a chunk header
    assert msgs == []
    assert len(a.errors) == 1
    assert 'truncated chunk header' in a.errors[0]


def test_association_truncated_sctp_header():
    a = Association()
    assert a.feed(b'\x00' * 5) == []
    assert len(a.errors) == 1
    assert 'truncated SCTP header' in a.errors[0]


def test_association_short_data_chunk():
    a = Association()
    # DATA chunk with only 8 bytes after the chunk header (DATA header needs 12)
    pkt = _packet(struct.pack('>BBH', DATA, 0, 12) + b'\x00' * 8)
    assert a.feed(pkt) == []
    assert len(a.errors) == 1
    assert 'short DATA chunk' in a.errors[0]


def test_message_equality():
    m1 = Message(stream_id=1, stream_seq=2, tsn_first=3, tsn_last=4, ppid=46, unordered=False, data=b'x')
    m2 = Message(stream_id=1, stream_seq=2, tsn_first=3, tsn_last=4, ppid=46, unordered=False, data=b'x')
    m3 = Message(stream_id=1, stream_seq=2, tsn_first=3, tsn_last=5, ppid=46, unordered=False, data=b'x')
    assert m1 == m2
    assert m1 != m3
    assert 'stream_id=1' in repr(m1)
