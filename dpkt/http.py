# $Id: http.py 86 2013-03-05 19:25:19Z andrewflnr@gmail.com $
# -*- coding: utf-8 -*-
"""Hypertext Transfer Protocol."""
from __future__ import print_function
from __future__ import absolute_import
from collections import OrderedDict
from . import dpkt
from .compat import BytesIO, iteritems


def _parse_header_line(line):
    """Split one 'name: value' header line into a lowercase (key, value)."""
    l_ = line.split(':', 1)
    if len(l_[0].split()) != 1:
        raise dpkt.UnpackError('invalid header: %r' % line)
    k = l_[0].lower()
    v = len(l_) != 1 and l_[1].lstrip() or ''
    return k, v


def parse_headers(f):
    """Return dict of HTTP headers parsed from a file object."""
    d = OrderedDict()
    while 1:
        # The following logic covers two kinds of loop exit criteria.
        # 1) If the header is valid, when we reached the end of the header,
        #    f.readline() would return with '\r\n', then after strip(),
        #    we can break the loop.
        # 2) If this is a weird header, which do not ends with '\r\n',
        #    f.readline() would return with '', then after strip(),
        #    we still get an empty string, also break the loop.
        line = f.readline().strip().decode("ascii", "ignore")
        if not line:
            break
        k, v = _parse_header_line(line)
        if k in d:
            if not type(d[k]) is list:
                d[k] = [d[k]]
            d[k].append(v)
        else:
            d[k] = v
    return d


def _header_values(headers, name):
    """Return every raw value of a possibly repeated/comma-listed header."""
    value = headers.get(name)
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    # RFC 7230 allows equivalent values to be combined into a comma list,
    # e.g. 'Content-Length: 1, 1'.
    out = []
    for v in values:
        out.extend(part for part in v.split(','))
    return out


def _parse_trailers(f):
    """Parse the trailer header block following the last (zero-sized) chunk."""
    trailers = OrderedDict()
    while 1:
        line = f.readline()
        # A trailer block is terminated by an empty line. Tolerate a bare LF
        # when the preceding chunk data happened to end in CR (the terminating
        # CRLF's CR was then consumed together with the chunk data).
        if line in (b'\r\n', b'\n', b''):
            break
        line = line.strip().decode("ascii", "ignore")
        if not line:
            break
        k, v = _parse_header_line(line)
        if k in trailers:
            if not type(trailers[k]) is list:
                trailers[k] = [trailers[k]]
            trailers[k].append(v)
        else:
            trailers[k] = v
    return trailers


def _read_chunk_terminator(f):
    """Consume the CRLF that ends one chunk.

    A chunk whose own data ends in CR/LF can leave the boundary line as a
    bare CR or bare LF; only a non-empty line means the stream no longer
    follows the chunk framing (historical tolerance preserved). Returns
    ``False`` when framing has been lost.
    """
    return not f.readline().strip()


def _parse_chunked(f):
    """Parse a chunked transfer-coded body (RFC 7230 section 4.1).

    Returns ``(body, trailers)``. Chunk extensions on the chunk-size line are
    tolerated and discarded, and the trailer block is parsed on its own
    instead of being left in the stream. Error types and messages match the
    historical parser.
    """
    chunks = []
    found_end = False
    trailers = OrderedDict()
    while 1:
        try:
            sz = f.readline().split(None, 1)[0]
        except IndexError:
            raise dpkt.UnpackError('missing chunk size')
        # A chunk-size line may carry chunk extensions after a semicolon,
        # e.g. '4; name="value"'.
        try:
            n = int(sz.split(b';', 1)[0], 16)
        except ValueError:
            raise dpkt.UnpackError('invalid chunk size')

        buf = f.read(n)
        if not _read_chunk_terminator(f):
            break

        if n == 0:
            # Only now does the (possibly empty) trailer block begin.
            found_end = True
            trailers = _parse_trailers(f)
            break

        if len(buf) == n:
            chunks.append(buf)
        else:
            # only possible when len(buf) < n, which will happen if the
            # file object ends before reading a complete file chunk
            break
    if not found_end:
        raise dpkt.NeedData('premature end of chunked body')
    return b''.join(chunks), trailers


class Framing(object):
    """Framing decision for a single HTTP message.

    A ``Framing`` instance is attached to every parsed :class:`Message` as
    ``msg.framing`` and records *how* the body was split out of the byte
    stream, including interpretations that were not adopted, so ambiguous
    messages can be triaged without manual byte counting.

    Attributes:
        method: framing actually used to split out the body; one of
            ``'content-length'``, ``'chunked'``, ``'read-to-end'`` (the
            legacy Content-Type fallback that consumes the whole stream) or
            ``'none'`` (no body allowed / no framing header).
        ambiguous: ``True`` when the framing information on the wire is
            conflicting: duplicate Content-Length headers with different
            values, or Content-Length together with Transfer-Encoding.
        transfer_encoding: the effective Transfer-Encoding header value, or
            ``None``.
        content_length: the effective Content-Length value used for framing,
            or ``None``.
        content_length_values: every integer Content-Length value found on
            the wire (duplicate headers and comma lists included).
        body: the body accepted by the parser; identical to ``Message.body``.
        trailers: trailer header block of a chunked message (may be empty).
        body_by_content_length: ``(body, remaining)`` computed by splitting at
            the first Content-Length value, or ``None`` when no
            Content-Length is present.
        body_by_chunked: ``(body, trailers, remaining)`` computed by parsing
            the chunked transfer coding, or ``None`` when chunked coding is
            not in effect.
        remaining: bytes left after this message; identical to
            ``Message.data``. Feed it back into :class:`Request` or
            :class:`Response` to walk pipelined messages on one connection.
    """

    def __init__(self):
        self.method = None
        self.ambiguous = False
        self.transfer_encoding = None
        self.content_length = None
        self.content_length_values = []
        self.body = b''
        self.trailers = OrderedDict()
        self.body_by_content_length = None
        self.body_by_chunked = None
        self.remaining = b''


def _content_length_cut(f, n):
    """Split ``(body, remaining)`` at ``n`` bytes from the current position."""
    body = f.read(n)
    return body, f.read()


def _frame_body(f, headers, is_body_allowed=True):
    """Decide how one HTTP message is framed and parse its body.

    The file object is consumed up to the end of the accepted message so the
    caller can read pipelined messages from the remainder.
    """
    framing = Framing()
    if not is_body_allowed:
        framing.method = 'none'
        framing.remaining = f.read()
        return framing

    cl_values = []
    for raw in _header_values(headers, 'content-length'):
        raw = raw.strip()
        try:
            n = int(raw)
        except ValueError:
            raise dpkt.UnpackError('invalid content-length: %r' % raw)
        if n < 0:
            raise dpkt.UnpackError('invalid content-length: %r' % raw)
        cl_values.append(n)
    framing.content_length_values = cl_values

    distinct_cl = []
    for n in cl_values:
        if n not in distinct_cl:
            distinct_cl.append(n)
    # RFC 7230 3.3.2: duplicate Content-Length with differing values is an
    # unrecoverable framing error; flag it instead of crashing on int(list).
    if len(distinct_cl) > 1:
        framing.ambiguous = True

    te_values = _header_values(headers, 'transfer-encoding')
    te = te_values[-1].strip() if te_values else ''
    framing.transfer_encoding = te or None
    chunked = te.lower() == 'chunked'
    # RFC 7230 3.3.3: senders MUST NOT send both; a tolerant parser ignores
    # Content-Length and frames by the chunked transfer coding.
    if chunked and cl_values:
        framing.ambiguous = True

    start = f.tell()

    # Content-Length interpretation, computed whenever a CL is present even
    # when another framing ends up being adopted.
    if cl_values:
        f.seek(start)
        framing.body_by_content_length = _content_length_cut(f, cl_values[0])

    # Chunked interpretation (also the accepted pass when chunked is in use).
    if chunked:
        f.seek(start)
        body, trailers = _parse_chunked(f)
        framing.body_by_chunked = (body, trailers, f.read())

    if chunked:
        framing.method = 'chunked'
        framing.body = body
        framing.trailers = trailers
        framing.remaining = framing.body_by_chunked[2]
    elif cl_values:
        framing.method = 'content-length'
        framing.content_length = cl_values[0]
        framing.body, framing.remaining = framing.body_by_content_length
        if len(framing.body) != cl_values[0]:
            raise dpkt.NeedData('short body (missing %d bytes)'
                                % (cl_values[0] - len(framing.body)))
    elif 'content-type' in headers:
        framing.method = 'read-to-end'
        f.seek(start)
        framing.body = f.read()
    else:
        framing.method = 'none'
        f.seek(start)
        framing.remaining = f.read()
    return framing


def parse_body(f, headers):
    """Return HTTP body parsed from a file object, given HTTP header dict.

    Backwards-compatible wrapper around the framing analysis; see
    :class:`Framing` for the full ambiguity/trailer breakdown.
    """
    return _frame_body(f, headers).body


class Message(dpkt.Packet):
    """Hypertext Transfer Protocol headers + body.

    HTTP messages are how data is exchanged between a server and a client. There are two types of messages: requests
    sent by the client to trigger an action on the server, and responses, the answer from the server. HTTP messages are
     composed of textual information encoded in ASCII, and span over multiple lines.

    Attributes:
        __hdr__: Header fields of HTTP.
            The start-line and HTTP headers of the HTTP message are collectively known as the head of the requests,
            whereas its payload is known as the body.
    """

    __metaclass__ = type
    __hdr_defaults__ = {}
    headers = None
    body = None
    framing = None
    trailers = None

    def __init__(self, *args, **kwargs):
        if args:
            self.unpack(args[0])
        else:
            self.headers = OrderedDict()
            self.body = b''
            self.data = b''
            self.framing = Framing()
            self.trailers = self.framing.trailers
            # NOTE: changing this to iteritems breaks py3 compatibility
            for k, v in self.__hdr_defaults__.items():
                setattr(self, k, v)
            for k, v in iteritems(kwargs):
                setattr(self, k, v)

    def unpack(self, buf, is_body_allowed=True):
        f = BytesIO(buf)
        # Parse headers
        self.headers = parse_headers(f)
        # Decide how the message is framed and parse the body. The framing
        # object also carries the alternative cuts, trailers and ambiguity
        # verdict for security triage.
        self.framing = _frame_body(f, self.headers, is_body_allowed)
        self.body = self.framing.body
        self.trailers = self.framing.trailers
        # Save the rest
        self.data = self.framing.remaining

    def pack_hdr(self):
        return ''.join(['%s: %s\r\n' % t for t in iteritems(self.headers)])

    def __len__(self):
        return len(str(self))

    def __str__(self):
        return '%s\r\n%s' % (self.pack_hdr(), self.body.decode("utf8", "ignore"))

    def __bytes__(self):
        return self.pack_hdr().encode("ascii", "ignore") + b'\r\n' + (self.body or b'')


class Request(Message):
    """Hypertext Transfer Protocol Request.

    HTTP requests are messages sent by the client to initiate an action on the server. Their start-line contain three
    elements. An HTTP method, a verb (like GET, PUT or POST) or a noun (like HEAD or OPTIONS), The request target,
    usually a URL, or the absolute path of the protocol, port, and domain are usually characterized by the request
    context and The HTTP version, which defines the structure of the remaining message, acting as an indicator of the
    expected version to use for the response.

    Attributes:
        __hdr__: Header fields of HTTP request.
            Many headers can appear in requests. They can be divided in several groups:
                General headers, like Via, apply to the message as a whole.
                Request headers, like User-Agent or Accept, modify the request by specifying it further (like Accept-
                    Language), by giving context (like Referer), or by conditionally restricting it (like If-None).
                Representation headers like Content-Type that describe the original format of the message data and
                    any encoding applied (only present if the message has a body).
    """

    __hdr_defaults__ = {
        'method': 'GET',
        'uri': '/',
        'version': '1.0',
    }
    __methods = dict.fromkeys((
        'GET', 'PUT', 'ICY',
        'COPY', 'HEAD', 'LOCK', 'MOVE', 'POLL', 'POST',
        'BCOPY', 'BMOVE', 'MKCOL', 'TRACE', 'LABEL', 'MERGE',
        'DELETE', 'SEARCH', 'UNLOCK', 'REPORT', 'UPDATE', 'NOTIFY',
        'BDELETE', 'CONNECT', 'OPTIONS', 'CHECKIN',
        'PROPFIND', 'CHECKOUT', 'CCM_POST',
        'SUBSCRIBE', 'PROPPATCH', 'BPROPFIND',
        'BPROPPATCH', 'UNCHECKOUT', 'MKACTIVITY',
        'MKWORKSPACE', 'UNSUBSCRIBE', 'RPC_CONNECT',
        'VERSION-CONTROL',
        'BASELINE-CONTROL'
    ))
    __proto = 'HTTP'

    def unpack(self, buf):
        f = BytesIO(buf)
        line = f.readline().decode("ascii", "ignore")
        l_ = line.strip().split()
        if len(l_) < 2:
            raise dpkt.UnpackError('invalid request: %r' % line)
        if l_[0] not in self.__methods:
            raise dpkt.UnpackError('invalid http method: %r' % l_[0])
        if len(l_) == 2:
            # HTTP/0.9 does not specify a version in the request line
            self.version = '0.9'
        else:
            if not l_[2].startswith(self.__proto):
                raise dpkt.UnpackError('invalid http version: %r' % l_[2])
            self.version = l_[2][len(self.__proto) + 1:]
        self.method = l_[0]
        self.uri = l_[1]
        Message.unpack(self, f.read())

    def __str__(self):
        return '%s %s %s/%s\r\n' % (self.method, self.uri, self.__proto,
                                    self.version) + Message.__str__(self)

    def __bytes__(self):
        str_out = '%s %s %s/%s\r\n' % (self.method, self.uri, self.__proto,
                                       self.version)
        return str_out.encode("ascii", "ignore") + Message.__bytes__(self)


class Response(Message):
    """Hypertext Transfer Protocol Response.

    The start line of an HTTP response, called the status line, contains the following information. The protocol
    version, usually HTTP/1.1, a status code, indicating success or failure of the request. Common status codes are 200,
     404, or 302, a status text. A brief, purely informational, textual description of the status code to help a human
     understand the HTTP message. A typical status line looks like: HTTP/1.1 404 Not Found.

    Attributes:
        __hdr__: Header fields of HTTP Response.
            Many headers can appear in responses. These can be divided into several groups:
                General headers, like Via, apply to the whole message.
                Response headers, like Vary and Accept-Ranges, give additional information about the server which
                    doesn't fit in the status line.
                Representation headers like Content-Type that describe the original format of the message data and any
                    encoding applied (only present if the message has a body).
    """

    __hdr_defaults__ = {
        'version': '1.0',
        'status': '200',
        'reason': 'OK'
    }
    __proto = 'HTTP'

    def unpack(self, buf):
        f = BytesIO(buf)
        line = f.readline()
        l_ = line.strip().decode("ascii", "ignore").split(None, 2)
        if len(l_) < 2 or not l_[0].startswith(self.__proto) or not l_[1].isdigit():
            raise dpkt.UnpackError('invalid response: %r' % line)
        self.version = l_[0][len(self.__proto) + 1:]
        self.status = l_[1]
        self.reason = l_[2] if len(l_) > 2 else ''
        # RFC Sec 4.3.
        # http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.3.
        # For response messages, whether or not a message-body is included with
        # a message is dependent on both the request method and the response
        # status code (section 6.1.1). All responses to the HEAD request method
        # MUST NOT include a message-body, even though the presence of entity-
        # header fields might lead one to believe they do. All 1xx
        # (informational), 204 (no content), and 304 (not modified) responses
        # MUST NOT include a message-body. All other responses do include a
        # message-body, although it MAY be of zero length.
        is_body_allowed = int(self.status) >= 200 and 204 != int(self.status) != 304
        Message.unpack(self, f.read(), is_body_allowed)

    def __str__(self):
        return '%s/%s %s %s\r\n' % (self.__proto, self.version, self.status,
                                    self.reason) + Message.__str__(self)

    def __bytes__(self):
        str_out = '%s/%s %s %s\r\n' % (self.__proto, self.version, self.status,
                                       self.reason)
        return str_out.encode("ascii", "ignore") + Message.__bytes__(self)


def test_parse_request():
    s = (b"""POST /main/redirect/ab/1,295,,00.html HTTP/1.0\r\nReferer: http://www.email.com/login/snap/login.jhtml\r\n"""
         b"""Connection: Keep-Alive\r\nUser-Agent: Mozilla/4.75 [en] (X11; U; OpenBSD 2.8 i386; Nav)\r\n"""
         b"""Host: ltd.snap.com\r\nAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n"""
         b"""Accept-Encoding: gzip\r\nAccept-Language: en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n"""
         b"""Content-type: application/x-www-form-urlencoded\r\nContent-length: 61\r\n\r\n"""
         b"""sn=em&mn=dtest4&pw=this+is+atest&fr=true&login=Sign+in&od=www""")
    r = Request(s)
    assert r.method == 'POST'
    assert r.uri == '/main/redirect/ab/1,295,,00.html'
    assert r.body == b'sn=em&mn=dtest4&pw=this+is+atest&fr=true&login=Sign+in&od=www'
    assert r.headers['content-type'] == 'application/x-www-form-urlencoded'

    Request(s[:60])


def test_format_request():
    r = Request()
    assert str(r) == 'GET / HTTP/1.0\r\n\r\n'
    r.method = 'POST'
    r.uri = '/foo/bar/baz.html'
    r.headers['content-type'] = 'text/plain'
    r.headers['content-length'] = '5'
    r.body = b'hello'
    s = str(r)
    assert s.startswith('POST /foo/bar/baz.html HTTP/1.0\r\n')
    assert s.endswith('\r\n\r\nhello')
    assert '\r\ncontent-length: 5\r\n' in s
    assert '\r\ncontent-type: text/plain\r\n' in s
    s = bytes(r)
    assert s.startswith(b'POST /foo/bar/baz.html HTTP/1.0\r\n')
    assert s.endswith(b'\r\n\r\nhello')
    assert b'\r\ncontent-length: 5\r\n' in s
    assert b'\r\ncontent-type: text/plain\r\n' in s
    r = Request(bytes(r))
    assert bytes(r) == s


def test_chunked_response():
    from binascii import unhexlify
    header = (
        b"HTTP/1.1 200 OK\r\n"
        b"Cache-control: no-cache\r\n"
        b"Pragma: no-cache\r\n"
        b"Content-Type: text/javascript; charset=utf-8\r\n"
        b"Content-Encoding: gzip\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Set-Cookie: S=gmail=agg:gmail_yj=v2s:gmproxy=JkU; Domain=.google.com; Path=/\r\n"
        b"Server: GFE/1.3\r\n"
        b"Date: Mon, 12 Dec 2005 22:33:23 GMT\r\n"
        b"\r\n"
    )
    body = unhexlify(
        '610d0a1f8b08000000000000000d0a3135320d0a6d914d4fc4201086effe0a82c99e58'
        '4a4be9b6eec1e81e369e34f1e061358652da12596880bafaef85ee1a2ff231990cef30'
        '3cc381a0c301e610c13ca765595435a1a4ace1db153aa49d0cfa354b00f62eaaeb86d5'
        '79cd485995348ebc2a688c8e214c3759e627eb82575acf3e381e6487853158d863e6bc'
        '175a898fac208465de0a215d961769b5027b7bc27a301e0f23379c77337699329dfcc2'
        '6338ea5b2f4550d6bcce84d0ceabf760271fac53d2c7d2fb94024edc040feeba195803'
        '547457d7b4d9920abc58a73bb09b2710243f46fdf3437a50748a55efb8c88b2d18edec'
        '3ce083850821f8225bb0d36a826893b8cfd89bbadad09214a4610d630d654dfd873d58'
        '3b68d96a3be0646217c202bdb046c2696e23fb3ab6c47815d69f8aafcf290b5ebce769'
        '11808b004401d82f8278f6d8f74a28ae2f11701f2bc470093afefddfa359faae347f00'
        'c5a595a1e20100000d0a300d0a0d0a'
    )
    buf = header + body
    r = Response(buf)
    assert r.version == '1.1'
    assert r.status == '200'
    assert r.reason == 'OK'


def test_multicookie_response():
    s = (b"""HTTP/1.x 200 OK\r\nSet-Cookie: first_cookie=cookie1; path=/; domain=.example.com\r\n"""
         b"""Set-Cookie: second_cookie=cookie2; path=/; domain=.example.com\r\nContent-Length: 0\r\n\r\n""")
    r = Response(s)
    assert type(r.headers['set-cookie']) is list
    assert len(r.headers['set-cookie']) == 2


def test_noreason_response():
    s = b"""HTTP/1.1 200 \r\n\r\n"""
    r = Response(s)
    assert r.reason == ''
    assert bytes(r) == s


def test_response_with_body():
    r = Response()
    r.body = b'foo'
    assert str(r) == 'HTTP/1.0 200 OK\r\n\r\nfoo'
    assert bytes(r) == b'HTTP/1.0 200 OK\r\n\r\nfoo'
    repr(r)


def test_body_forbidden_response():
    s = b'HTTP/1.1 304 Not Modified\r\n'\
        b'Content-Type: text/css\r\n'\
        b'Last-Modified: Wed, 14 Jan 2009 16:42:11 GMT\r\n'\
        b'ETag: "3a7-496e15e3"\r\n'\
        b'Cache-Control: private, max-age=414295\r\n'\
        b'Date: Wed, 22 Sep 2010 17:55:54 GMT\r\n'\
        b'Connection: keep-alive\r\n'\
        b'Vary: Accept-Encoding\r\n\r\n'\
        b'HTTP/1.1 200 OK\r\n'\
        b'Server: Sun-ONE-Web-Server/6.1\r\n'\
        b'ntCoent-length: 257\r\n'\
        b'Content-Type: application/x-javascript\r\n'\
        b'Last-Modified: Wed, 06 Jan 2010 19:34:06 GMT\r\n'\
        b'ETag: "101-4b44e5ae"\r\n'\
        b'Accept-Ranges: bytes\r\n'\
        b'Content-Encoding: gzip\r\n'\
        b'Cache-Control: private, max-age=439726\r\n'\
        b'Date: Wed, 22 Sep 2010 17:55:54 GMT\r\n'\
        b'Connection: keep-alive\r\n'\
        b'Vary: Accept-Encoding\r\n'
    result = []
    while s:
        msg = Response(s)
        s = msg.data
        result.append(msg)

    # the second HTTP response should be an standalone message
    assert len(result) == 2


def test_request_version():
    s = b"""GET / HTTP/1.0\r\n\r\n"""
    r = Request(s)
    assert r.method == 'GET'
    assert r.uri == '/'
    assert r.version == '1.0'

    s = b"""GET /\r\n\r\n"""
    r = Request(s)
    assert r.method == 'GET'
    assert r.uri == '/'
    assert r.version == '0.9'

    import pytest
    s = b"""GET / CHEESE/1.0\r\n\r\n"""
    with pytest.raises(dpkt.UnpackError, match="invalid http version: u?'CHEESE/1.0'"):
        Request(s)


def test_valid_header():
    # valid header.
    s = b'POST /main/redirect/ab/1,295,,00.html HTTP/1.0\r\n' \
        b'Referer: http://www.email.com/login/snap/login.jhtml\r\n' \
        b'Connection: Keep-Alive\r\n' \
        b'User-Agent: Mozilla/4.75 [en] (X11; U; OpenBSD 2.8 i386; Nav)\r\n' \
        b'Host: ltd.snap.com\r\n' \
        b'Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n' \
        b'Accept-Encoding: gzip\r\n' \
        b'Accept-Language: en\r\n' \
        b'Accept-Charset: iso-8859-1,*,utf-8\r\n' \
        b'Content-type: application/x-www-form-urlencoded\r\n' \
        b'Content-length: 61\r\n\r\n' \
        b'sn=em&mn=dtest4&pw=this+is+atest&fr=true&login=Sign+in&od=www'
    r = Request(s)
    assert r.method == 'POST'
    assert r.uri == '/main/redirect/ab/1,295,,00.html'
    assert r.body == b'sn=em&mn=dtest4&pw=this+is+atest&fr=true&login=Sign+in&od=www'
    assert r.headers['content-type'] == 'application/x-www-form-urlencoded'


def test_weird_end_header():
    s_weird_end = b'POST /main/redirect/ab/1,295,,00.html HTTP/1.0\r\n' \
        b'Referer: http://www.email.com/login/snap/login.jhtml\r\n' \
        b'Connection: Keep-Alive\r\n' \
        b'User-Agent: Mozilla/4.75 [en] (X11; U; OpenBSD 2.8 i386; Nav)\r\n' \
        b'Host: ltd.snap.com\r\n' \
        b'Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n' \
        b'Accept-Encoding: gzip\r\n' \
        b'Accept-Language: en\r\n' \
        b'Accept-Charset: iso-8859-1,*,utf-8\r\n' \
        b'Content-type: application/x-www-form-urlencoded\r\n' \
        b'Cookie: TrackID=1PWdcr3MO_C611BGW'
    r = Request(s_weird_end)
    assert r.method == 'POST'
    assert r.uri == '/main/redirect/ab/1,295,,00.html'
    assert r.headers['content-type'] == 'application/x-www-form-urlencoded'


def test_gzip_response():
    import zlib
    # valid response, compressed using gzip
    s = b'HTTP/1.0 200 OK\r\n' \
        b'Server: SimpleHTTP/0.6 Python/2.7.12\r\n' \
        b'Date: Fri, 10 Mar 2017 20:43:08 GMT\r\n' \
        b'Content-type: text/plain\r\n' \
        b'Content-Encoding: gzip\r\n' \
        b'Content-Length: 68\r\n' \
        b'Last-Modified: Fri, 10 Mar 2017 20:40:43 GMT\r\n\r\n' \
        b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03\x0b\xc9\xc8,V\x00\xa2D' \
        b'\x85\xb2\xd4\xa2J\x85\xe2\xdc\xc4\x9c\x1c\x85\xb4\xcc\x9cT\x85\x92' \
        b'|\x85\x92\xd4\xe2\x12\x85\xf4\xaa\xcc\x02\x85\xa2\xd4\xe2\x82\xfc' \
        b'\xbc\xe2\xd4b=.\x00\x01(m\xad2\x00\x00\x00'
    r = Response(s)
    assert r.version == '1.0'
    assert r.status == '200'
    assert r.reason == 'OK'
    # Make a zlib compressor with the appropriate gzip options
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    body = decompressor.decompress(r.body)
    assert body.startswith(b'This is a very small file')


def test_message():
    # s = b'Date: Fri, 10 Mar 2017 20:43:08 GMT\r\n'  # FIXME - unused
    r = Message(content_length=68)
    assert r.content_length == 68
    assert len(r) == 2


def test_invalid():
    import pytest

    s = b'INVALID / HTTP/1.0\r\n'
    with pytest.raises(dpkt.UnpackError, match="invalid http method: u?'INVALID'"):
        Request(s)

    s = b'A'
    with pytest.raises(dpkt.UnpackError, match="invalid response: b?'A'"):
        Response(s)

    s = b'HTTT 200 OK'
    with pytest.raises(dpkt.UnpackError, match="invalid response: b?'HTTT 200 OK'"):
        Response(s)

    s = b'HTTP TWO OK'
    with pytest.raises(dpkt.UnpackError, match="invalid response: b?'HTTP TWO OK'"):
        Response(s)

    s = (
        b'HTTP/1.0 200 OK\r\n'
        b'Invalid Header: invalid\r\n'
    )
    with pytest.raises(dpkt.UnpackError, match="invalid header: "):
        Response(s)

    s = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"\r\n"
    )
    with pytest.raises(dpkt.UnpackError, match="missing chunk size"):
        Response(s)

    s = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"\x01\r\na"
    )
    with pytest.raises(dpkt.UnpackError, match="invalid chunk size"):
        Response(s)

    s = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"2\r\n"
        b"abcd"
    )
    with pytest.raises(dpkt.NeedData, match="premature end of chunked body"):
        Response(s)

    s = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 68\r\n"
        b"\r\n"
        b"a\r\n"
    )
    with pytest.raises(dpkt.NeedData, match=r"short body \(missing 65 bytes\)"):
        Response(s)

    # messy header.
    s_messy_header = b'aaaaaaaaa\r\nbbbbbbbbb'
    with pytest.raises(dpkt.UnpackError, match="invalid request: u?'aaaaaaaa"):
        Request(s_messy_header)


def test_response_str():
    s = (
        b'HTTP/1.0 200 OK\r\n'
        b'Server: SimpleHTTP/0.6 Python/2.7.12\r\n'
        b'Date: Fri, 10 Mar 2017 20:43:08 GMT\r\n'
        b'Content-type: text/plain\r\n'
    )

    # the headers are processed to lowercase keys
    resp = [
        'HTTP/1.0 200 OK',
        'server: SimpleHTTP/0.6 Python/2.7.12',
        'date: Fri, 10 Mar 2017 20:43:08 GMT',
        'content-type: text/plain',
        '',
        '',
    ]

    r_str = str(Response(s))

    s_arr = sorted(resp)
    resp_arr = sorted(r_str.split('\r\n'))

    for line1, line2 in zip(s_arr, resp_arr):
        assert line1 == line2


def test_request_str():
    s = b'GET / HTTP/1.0\r\n'
    r = Request(s)
    req = 'GET / HTTP/1.0\r\n\r\n'
    assert req == str(r)


def test_parse_body():
    import pytest
    from .compat import BytesIO
    buf = BytesIO(
        b'05\r\n'  # size
        b'ERR'     # longer than size
    )
    buf.seek(0)
    headers = {
        'transfer-encoding': 'chunked',
    }
    with pytest.raises(dpkt.NeedData, match="premature end of chunked body"):
        parse_body(buf, headers)


def test_duplicate_content_length():
    import pytest
    # Repeated identical Content-Length: valid, not ambiguous, no TypeError.
    s = (b'POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n'
         b'hello')
    r = Request(s)
    assert r.body == b'hello'
    assert r.framing.method == 'content-length'
    assert r.framing.ambiguous is False
    assert r.framing.content_length_values == [5, 5]
    assert r.framing.body_by_content_length == (b'hello', b'')
    assert r.data == b''

    # Conflicting Content-Length values used to raise TypeError; now the
    # message still parses and is explicitly flagged ambiguous. The first
    # value is the adopted cut, every value is recorded.
    s = (b'POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 7\r\n\r\n'
         b'hello!!REST')
    r = Request(s)
    assert r.framing.ambiguous is True
    assert r.framing.method == 'content-length'
    assert r.framing.content_length_values == [5, 7]
    assert r.framing.content_length == 5
    assert r.body == b'hello'
    # The CL cut reports both the body and the bytes left over by that cut.
    assert r.framing.body_by_content_length == (b'hello', b'!!REST')
    assert r.data == b'!!REST'

    # Comma-combined duplicate values are handled the same way.
    s = b'POST / HTTP/1.1\r\nContent-Length: 5, 7\r\n\r\nhello!!REST'
    r = Request(s)
    assert r.framing.ambiguous is True
    assert r.framing.content_length_values == [5, 7]

    # A non-numeric Content-Length is a dpkt error, not a raw ValueError.
    with pytest.raises(dpkt.UnpackError, match='invalid content-length'):
        Request(b'POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\nx')


def test_content_length_and_transfer_encoding():
    # Both headers present: ambiguous, chunked transfer coding is adopted
    # (RFC 7230 3.3.3), and both interpretations are reported separately.
    after_headers = b'5\r\nhello\r\n0\r\n\r\n\r\nGET /next HTTP/1.1\r\n\r\n'
    s = (b'POST / HTTP/1.1\r\nContent-Length: 7\r\n'
         b'Transfer-Encoding: chunked\r\n\r\n' + after_headers)
    r = Request(s)

    assert r.framing.ambiguous is True
    assert r.framing.method == 'chunked'
    assert r.framing.transfer_encoding == 'chunked'
    assert r.framing.content_length_values == [7]

    # Adopted chunked cut: decoded body, trailers and remaining bytes.
    assert r.body == b'hello'
    assert r.trailers == OrderedDict()
    assert r.framing.body_by_chunked == (
        b'hello', OrderedDict(), b'GET /next HTTP/1.1\r\n\r\n')
    assert r.data == b'GET /next HTTP/1.1\r\n\r\n'

    # Alternative Content-Length cut over the same raw bytes.
    cl_body, cl_remaining = r.framing.body_by_content_length
    assert cl_body == after_headers[:7]
    assert cl_remaining == after_headers[7:]
    assert cl_body + cl_remaining == after_headers

    # The remaining bytes are themselves a parseable message, i.e. the
    # connection can be walked without re-splitting by hand.
    nxt = Request(r.data)
    assert nxt.uri == '/next'


def test_chunk_extensions():
    # Chunk extensions ('4; foo=bar') must not break chunk-size decoding.
    s = (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
         b'4; foo=bar\r\nwiki\r\n'
         b'5; a=1; b=2\r\npedia\r\n'
         b'0\r\n\r\n')
    r = Response(s)
    assert r.body == b'wikipedia'
    assert r.framing.method == 'chunked'
    assert r.framing.ambiguous is False
    assert r.trailers == OrderedDict()
    assert r.data == b''
    assert bytes(Response(s)) == (
        b'HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\nwikipedia')


def test_chunked_trailers():
    # The trailer block is parsed on its own instead of leaking into data,
    # so the next message on the connection starts at the right byte.
    s = (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
         b'4\r\nwiki\r\n5\r\npedia\r\n'
         b'0\r\n\r\nETag: "x"\r\nX-Sum: 9\r\n\r\nNEXTMSG')
    r = Response(s)
    assert r.body == b'wikipedia'
    assert r.trailers == OrderedDict([('etag', '"x"'), ('x-sum', '9')])
    assert r.framing.body_by_chunked == (
        b'wikipedia',
        OrderedDict([('etag', '"x"'), ('x-sum', '9')]),
        b'NEXTMSG')
    assert r.data == b'NEXTMSG'

    # Trailer headers are kept separate from ordinary message headers.
    assert 'etag' not in r.headers
    # Normal message serialization is unaffected: trailers are not appended.
    assert bytes(r) == (
        b'HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\nwikipedia')


def test_pipelined_messages():
    # Several messages back to back on one connection are split in order.
    stream = (
        b'GET /a HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc'
        b'POST /b HTTP/1.1\r\nContent-Length: 4\r\n\r\ndefg'
        b'GET /c HTTP/1.1\r\n\r\n'
    )
    parsed = []
    while stream:
        msg = Request(stream)
        parsed.append((msg.method, msg.uri, msg.body, msg.framing.method))
        stream = msg.data
    assert parsed == [
        ('GET', '/a', b'abc', 'content-length'),
        ('POST', '/b', b'defg', 'content-length'),
        ('GET', '/c', b'', 'none'),
    ]

    # Pipelining also works when an inner message is chunked with trailers.
    stream = (
        b'POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n'
        b'3\r\nfoo\r\n0\r\n\r\nX-T: v\r\n\r\n'
        b'GET /b HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi'
    )
    first = Request(stream)
    assert first.body == b'foo'
    assert first.trailers == OrderedDict([('x-t', 'v')])
    second = Request(first.data)
    assert second.uri == '/b'
    assert second.body == b'hi'
    assert second.data == b''


def test_framing_normal_traffic_unchanged():
    # Plain Content-Length response: method and bytes() stay exactly as before.
    raw = (b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello')
    r = Response(raw)
    assert r.framing.method == 'content-length'
    assert r.framing.ambiguous is False
    assert r.framing.content_length == 5
    assert r.body == b'hello'
    assert r.data == b''
    # Header keys are lowercased on parse (pre-existing behavior); body bytes
    # are preserved exactly.
    assert bytes(r) == b'HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello'

    # Legacy read-to-end fallback via Content-Type keeps working.
    r = Response(b'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nraw')
    assert r.framing.method == 'read-to-end'
    assert r.body == b'raw'

    # A message built without wire bytes exposes an empty framing object.
    r = Request()
    assert isinstance(r.framing, Framing)
    assert r.framing.method is None
    assert r.trailers == OrderedDict()
