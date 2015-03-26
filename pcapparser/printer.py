# Changes made to integrate with CapTipper in lines: 31-47,57-60,88-94,108-112, 129-135, 148-150,188-189
# coding=utf-8
from __future__ import unicode_literals, print_function, division

from io import StringIO
import sys
import CTCore

from pcapparser.config import OutputLevel
# print http req/resp
from pcapparser import utils
from pcapparser import config
import threading
from pcapparser.constant import Compress

printer_lock = threading.Lock()


def _get_full_url(uri, host):
    if uri.startswith(b'http://') or uri.startswith(b'https://'):
        return uri
    else:
        return b'http://' + host + uri


class HttpPrinter(object):
    def __init__(self, client_host, remote_host):
        self.parse_config = config.get_config()
        self.buf = StringIO()
        self.client_host = client_host
        self.remote_host = remote_host
        self.uri = ""
        self.req_head = ""
        self.res_body = ""
        self.orig_resp = ""
        self.orig_chunked_resp = ""
        self.res_head = ""
        self.res_num = ""
        self.res_type = ""
        self.redirect_to = ""
        self.host = ""
        self.referer = ""
        self.filename = ""
        self.method = ""
        self.res_len = 0
        self.time = 0


    def on_http_req(self, req_header, req_body):
        """
        :type req_header: HttpRequestHeader
        :type req_body: bytes
        """
        if self.parse_config.level == OutputLevel.ONLY_URL:
            self._println(req_header.method + b" " + _get_full_url(req_header.uri, req_header.host))
        elif self.parse_config.level == OutputLevel.HEADER:
            self._println(req_header.raw_data)
            self._println()
        elif self.parse_config.level >= OutputLevel.TEXT_BODY:
            self._println(req_header.raw_data)
            #self._println()
            self.uri = req_header.uri
            self.req_head = req_header.raw_data
            self.host = req_header.host
            self.referer = req_header.referer
            self.method = req_header.method
            self.time = req_header.time

            mime, charset = utils.parse_content_type(req_header.content_type)
            # usually charset is not set in http post
            output_body = self._if_output(mime)
            if self.parse_config.encoding and not charset:
                charset = self.parse_config.encoding
            if req_header.compress == Compress.IDENTITY:
                # if is gzip by content magic header
                # someone missed the content-encoding header
                if utils.gzipped(req_body):
                    req_header.compress = Compress.GZIP
            if output_body:
                self._print_body(req_body, req_header.compress, mime, charset)
                #self._println('')

    def on_http_resp(self, resp_header, resp_body, orig_chunked_resp):
        """
        :type resp_header: HttpResponseHeader
        :type resp_body: bytes
        """
        if self.parse_config.level == OutputLevel.ONLY_URL:
            self._println(resp_header.status_line)
        elif self.parse_config.level == OutputLevel.HEADER:
            self._println(resp_header.raw_data)
            self._println()
        elif self.parse_config.level >= OutputLevel.TEXT_BODY:
            self._println(resp_header.raw_data)
            #self._println()
            self.res_head = resp_header.raw_data
            self.orig_chunked_resp = orig_chunked_resp
            self.res_type = resp_header.content_type
            self.res_len = resp_header.content_len
            self.res_num = resp_header.status_line[resp_header.status_line.find(' ') + 1:]
            self.redirect_to = resp_header.redirect_to
            self.filename = resp_header.filename

            mime, charset = utils.parse_content_type(resp_header.content_type)
            # usually charset is not set in http post
            output_body = self._if_output(mime)
            if self.parse_config.encoding and not charset:
                charset = self.parse_config.encoding
            if resp_header.compress == Compress.IDENTITY:
                # if is gzip by content magic header
                # someone missed the content-encoding header
                if utils.gzipped(resp_body):
                    resp_header.compress = Compress.GZIP
            if output_body:
                self._print_body(resp_body, resp_header.compress, mime, charset)
                #self._println()
                self.orig_resp = resp_body
                if self.res_body == b"":
                    self.res_body = resp_body

                if (self.res_body is not None) and (len(self.res_body) > 0) and (self.res_len == 0):
                    self.res_len = len(self.res_body)

        if not config.get_config().group:
            self._do_output()

    def finish(self):
        """called when this connection finished"""
        self._do_output()

    def _do_output(self):
        printer_lock.acquire()

        try:
            value = self.buf.getvalue()
            self.buf = StringIO()
            if value:
                #print("[%s:%d] -- -- --> [%s:%d] " % (self.client_host[0], self.client_host[1],
                 #                                     self.remote_host[0], self.remote_host[1]),
                #      file=config.out)
                #print(value.encode('utf8'), file=config.out)

                CTCore.finish_conversation(self)
                #config.out.flush()
        except IOError as e:
            if e.errno == 32:
                # may be pipe closed
                sys.exit(0)
            else:
                print(e, file=sys.stderr)
                sys.exit(-1)

        finally:
            printer_lock.release()

    def _if_output(self, mime):
        return True
        #return self.parse_config.level >= OutputLevel.ALL_BODY and not utils.is_binary(mime) \
        #       or self.parse_config.level >= OutputLevel.TEXT_BODY and utils.is_text(mime)

    def _println(self, line=''):
        if type(line) == type(b''):
            line = line.decode('utf-8')
        self.buf.write(line)
        self.buf.write('\n')

    def _println_if(self, level, line):
        if self.parse_config.level >= level:
            self._println(line)

    def _print_body(self, body, compress, mime, charset):
        try:
            if compress == Compress.GZIP:
                body = utils.ungzip(body)
            elif compress == Compress.DEFLATE:
                body = utils.decode_deflate(body)

            self.res_body = ""
            if CTCore.b_auto_ungzip:
                self.res_body = body

            content = utils.decode_body(body, charset)
            if content:
                if not mime:
                    # guess mime...
                    if content.startswith('{') and content.endswith('}') or content.startswith('[') \
                            and content.endswith(']'):
                        mime = b'application/json'
                if mime is None:
                    mime = ''
                if self.parse_config.pretty:
                    if b'json' in mime:
                        utils.try_print_json(content, self.buf)
                    elif b'www-form-urlencoded' in mime:
                        utils.try_decoded_print(content, self.buf)
                    else:
                        self.buf.write(content)
                else:
                    self.buf.write(content)
                self.buf.write('\n')
        except Exception,e:
            content = utils.decode_body(body, charset)
            self.buf.write(content)
            self.buf.write('\n')
            print(CTCore.colors.RED +  "[-] Error parsing body of uri: " + self.uri + " : " + str(e) + CTCore.colors.END)