#
#          CapTipper is a malicious HTTP traffic explorer tool
#          By Omri Herscovici <omriher AT gmail.com>
#          http://omriher.com
#          @omriher
#
#          This file is part of CapTipper
#
#          CapTipper is a free software under the GPLv3 License
#

# This file belongs to pcap-parser written by Dong Liu
# https://github.com/xiaxiaocao/pcap-parser
# dongliu@live.cn
#
# Licensed under the Apache License, Version 2.0.
#
# This file and the library itself were modified to integrate with CapTipper

from __future__ import unicode_literals, print_function, division
import signal

import sys
# check python version
import time
import CTCore

major, minor, = sys.version_info[:2]
if major != 2 or minor < 7:
    print("Python version 2.7.* needed.", file=sys.stderr)
    sys.exit(1)

import io

from pcapparser import packet_parser
from pcapparser import pcap, pcapng, utils
from pcapparser.constant import FileFormat
from pcapparser.printer import HttpPrinter
from collections import OrderedDict
import struct

from pcapparser.httpparser import HttpType, HttpParser
from pcapparser import config

# when press Ctrl+C, stop the proxy.
def signal_handler(signal, frame):
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

class HttpConn:
    """all data having same source/dest ip/port in one http connection."""
    STATUS_BEGIN = 0
    STATUS_RUNNING = 1
    STATUS_CLOSED = 2
    STATUS_ERROR = -1

    def __init__(self, tcp_pac):
        self.source_ip = tcp_pac.source
        self.source_port = tcp_pac.source_port
        self.dest_ip = tcp_pac.dest
        self.dest_port = tcp_pac.dest_port

        self.status = HttpConn.STATUS_BEGIN

        # start parser thread
        self.processor = HttpPrinter((self.source_ip, self.source_port),
                                     (self.dest_ip, self.dest_port))
        self.http_parser = HttpParser(self.processor)
        self.append(tcp_pac)

    def append(self, tcp_pac):
        if len(tcp_pac.body) == 0:
            return
        if self.status == HttpConn.STATUS_ERROR or self.status == HttpConn.STATUS_CLOSED:
            # not http conn or conn already closed.
            return

        if self.status == HttpConn.STATUS_BEGIN:
            if tcp_pac.body:
                if utils.is_request(tcp_pac.body):
                    self.status = HttpConn.STATUS_RUNNING
        if tcp_pac.source == self.source_ip:
            http_type = HttpType.REQUEST
        else:
            http_type = HttpType.RESPONSE

        if self.status == HttpConn.STATUS_RUNNING and tcp_pac.body:
            self.http_parser.send(http_type, tcp_pac.body, tcp_pac.micro_second)

        if tcp_pac.pac_type == -1:
            # end of connection
            if self.status == HttpConn.STATUS_RUNNING:
                self.status = HttpConn.STATUS_CLOSED
            else:
                self.status = HttpConn.STATUS_ERROR

    def finish(self):
        self.http_parser.finish()

def get_file_format(infile):
    """
    get cap file format by magic num.
    return file format and the first byte of string
    :type infile:file
    """
    buf = infile.read(4)
    if len(buf) == 0:
        # EOF
        print("empty file", file=sys.stderr)
        sys.exit(-1)
    if len(buf) < 4:
        print("file too small", file=sys.stderr)
        sys.exit(-1)
    magic_num, = struct.unpack(b'<I', buf)
    if magic_num == 0xA1B2C3D4 or magic_num == 0x4D3C2B1A:
        return FileFormat.PCAP, buf
    elif magic_num == 0x0A0D0D0A:
        return FileFormat.PCAP_NG, buf
    else:
        return FileFormat.UNKNOWN, buf


def pcap_file(conn_dict, infile):
    """
    :type conn_dict: dict
    :type infile:file
    """
    file_format, head = get_file_format(infile)
    if file_format == FileFormat.PCAP:
        pcap_file = pcap.PcapFile(infile, head).read_packet
    elif file_format == FileFormat.PCAP_NG:
        pcap_file = pcapng.PcapngFile(infile, head).read_packet
    else:
        print("unknown file format.", file=sys.stderr)
        sys.exit(1)

    _filter = config.get_filter()
    for tcp_pac in packet_parser.read_package_r(pcap_file):
        # filter
        # get time
        if CTCore.activity_date_time == "":
            CTCore.activity_date_time = time.strftime('%a, %x %X', time.gmtime(int(str(tcp_pac.micro_second)[:10])))

        if CTCore.client.headers["IP"] == "":
            CTCore.client.headers["IP"] = tcp_pac.source

        if CTCore.client.headers["MAC"] == "":
            CTCore.client.headers["MAC"] = tcp_pac.src_mac

        if not (_filter.by_ip(tcp_pac.source) or _filter.by_ip(tcp_pac.dest)):
            continue
        if not (_filter.by_port(tcp_pac.source_port) or _filter.by_port(tcp_pac.dest_port)):
            continue

        key = tcp_pac.gen_key()
        # we already have this conn
        if key in conn_dict:
            conn_dict[key].append(tcp_pac)
            # conn closed.
            if tcp_pac.pac_type == packet_parser.TcpPack.TYPE_CLOSE:
                conn_dict[key].finish()
                del conn_dict[key]

        # begin tcp connection.
        elif tcp_pac.pac_type == 1:
            conn_dict[key] = HttpConn(tcp_pac)
        elif tcp_pac.pac_type == 0:
            # tcp init before capture, we found a http request header, begin parse
            # if is a http request?
            if utils.is_request(tcp_pac.body):
                conn_dict[key] = HttpConn(tcp_pac)


def run(file_path):
    conn_dict = OrderedDict()
    try:
        if file_path != '-':
            infile = io.open(file_path, "rb")
        else:
            infile = sys.stdin
        try:
            pcap_file(conn_dict, infile)
        finally:
            infile.close()
    finally:
        for conn in conn_dict.values():
            conn.finish()