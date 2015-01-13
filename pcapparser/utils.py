from __future__ import unicode_literals, print_function, division
import zlib
from pcapparser.constant import Compress

__author__ = 'dongliu'

import json
from io import BytesIO
import gzip


class Mime(object):
    def __init__(self, mime_str):
        if not mime_str:
            self.top_level = None
            self.subtype = None
            return
        idx = mime_str.find(b'/')
        if idx < 0:
            self.top_level = mime_str
            self.subtype = None
            return
        self.top_level = mime_str[:idx]
        self.subtype = mime_str[idx + 1:]


def try_print_json(text, output_file):
    if text is None:
        return
    # may be json
    try:
        data = json.loads(text)
        output_file.write(
            json.dumps(data, indent=2, ensure_ascii=False, separators=(',', ': ')))
        return True
    except Exception:
        output_file.write(text)
        return False


def try_decoded_print(content, buf):
    import urllib

    content = urllib.unquote(content)
    buf.write(content)


def get_compress_type(content_encoding):
    content_encoding = content_encoding.strip()
    if content_encoding == b'gzip':
        return Compress.GZIP
    elif content_encoding == b'deflate':
        return Compress.DEFLATE
    else:
        # there are others compress token, just process the most common two now.
        return Compress.IDENTITY


def gzipped(content):
    """
    test if content is gzipped by magic num.
    first two bytes of gzip stream should be 0x1F and 0x8B,
    the third byte represent for compress algorithm, always 8(deflate) now
    """
    if content is not None and len(content) > 10 \
            and ord(content[0:1]) == 31 and ord(content[1:2]) == 139 \
            and ord(content[2:3]) == 8:
        return True
    return False


def ungzip(content):
    """ungzip content"""
    buf = BytesIO(content)
    gzip_file = gzip.GzipFile(fileobj=buf)
    content = gzip_file.read()
    return content



def decode_deflate(content):
    """decode deflate stream"""
    return zlib.decompressobj(-zlib.MAX_WBITS).decompress(content)


def parse_http_header(header):
    header = header.strip()
    idx = header.find(b':')
    if idx < 0:
        return None, None
    else:
        return header[0:idx].strip(), header[idx + 1:].strip()


_methods = {b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'TRACE', b'OPTIONS', b'PATCH'}


def is_request(body):
    """judge if is http request by the first line"""
    idx = body.find(b' ')
    if idx < 0:
        return False
    method = body[0:idx]
    return method in _methods


def is_response(body):
    """judge if is http response by http status line"""
    return body.startswith(b'HTTP/')


def parse_content_type(content_type):
    if not content_type:
        return None, None
    idx = content_type.find(b';')
    if idx < 0:
        idx = len(content_type)
    mime = content_type[0:idx]
    encoding = content_type[idx + 1:]
    if len(encoding) > 0:
        eidx = encoding.find(b'=')
        if eidx > 0 and encoding[0:eidx].strip() == b'charset':
            encoding = encoding[eidx + 1:]
        else:
            encoding = b''
    return mime.strip().lower(), encoding.strip().lower()


_text_mime_top_levels = {b'text'}
_text_mime_subtypes = {
    b'html', b'xml', b'json', b'javascript', b'ecmascript', b'atom+xml',
    b'rss+xml', b'xhtml+xml', b'rdf+xml', b'x-www-form-urlencoded'
}


def is_text(mime_str):
    mime = Mime(mime_str)
    return mime.top_level in _text_mime_top_levels or mime.subtype in _text_mime_subtypes


_binary_mime_top_levels = {b'audio', b'image', b'video'}
_binary_mime_subtypes = {b'octet-stream', b'pdf', b'postscript', b'zip', b'gzip',
                         b'x-shockwave-flash', b'oct-stream'}


def is_binary(mime_str):
    mime = Mime(mime_str)
    return mime.top_level in _binary_mime_top_levels or mime.subtype in _binary_mime_subtypes


def decode_body(content, charset):
    if content is None:
        return None
    if content == b'':
        return ''
    if charset:
        if type(charset) == type(b''):
            charset = charset.decode('utf-8')
        try:
            return content.decode(charset)
        except:
            return '{decode content failed with charset: %s}' % charset

    # todo: encoding detect
    try:
        return content.decode('utf-8')
    except:
        pass
    try:
        return content.decode('gb18030')
    except:
        pass
    return '{decode content failed, unknown charset}'
