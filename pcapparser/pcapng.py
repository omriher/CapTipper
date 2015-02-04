# read and parse pcapng file
# see
# http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
# http://wiki.wireshark.org/Development/PcapNg
from __future__ import unicode_literals, print_function, division
import struct
import sys
from pcapparser.constant import *

__author__ = 'dongliu'


class SectionInfo(object):
    def __init__(self):
        self.byteorder = b'@'
        self.length = -1
        self.major = -1
        self.minor = -1
        self.link_type = -1
        self.capture_len = -1
        self.tsresol = 1  # Resolution of timestamps. we use microsecond here
        self.tsoffset = 0  # value that specifies the offset of timestamp. we use microsecond


class PcapngFile(object):
    def __init__(self, infile, head):
        self.infile = infile
        self.section_info = SectionInfo()
        # the first 4 byte head has been read by pcap file format checker
        self.head = head

    def parse_section_header_block(self, block_header):
        """get section info from section header block"""

        # read byte order info first.
        byteorder_magic = self.infile.read(4)
        byteorder_magic, = struct.unpack(b'>I', byteorder_magic)
        if byteorder_magic == 0x1A2B3C4D:
            byteorder = b'>'
        elif byteorder_magic == 0x4D3C2B1A:
            byteorder = b'<'
        else:
            print("Not a byteorder magic num: %d" % byteorder_magic, file=sys.stderr)
            return None

        block_len, = struct.unpack(byteorder + b'4xI', block_header)

        # read version, should be 1, 0
        versions = self.infile.read(4)
        major, minor = struct.unpack(byteorder + b'HH', versions)

        # section len
        section_len = self.infile.read(8)
        section_len, = struct.unpack(byteorder + b'q', section_len)
        if section_len == -1:
            # usually did not have a known section length
            pass

        self.infile.read(block_len - 12 - 16)

        self.section_info.byteorder = byteorder
        self.section_info.major = major
        self.section_info.minor = minor
        self.section_info.length = section_len

    def parse_interface_description_block(self, block_len):
        # read link type and capture size
        buf = self.infile.read(4)
        link_type, = struct.unpack(self.section_info.byteorder + b'H2x', buf)
        buf = self.infile.read(4)
        snap_len = struct.unpack(self.section_info.byteorder + b'I', buf)
        self.section_info.link_type = link_type
        self.section_info.snap_len = snap_len

        # read if_tsresol option to determined how to interpreter the timestamp of packet
        options = self.infile.read(block_len - 12 - 8)
        offset = 0
        while offset < len(options):
            option = options[offset:]
            code, = struct.unpack(self.section_info.byteorder + b'H', option[:2])
            raw_len, = struct.unpack(self.section_info.byteorder + b'H', option[2:4])
            padding_len = raw_len
            if code == 9:
                # if_tsresol
                if_tsresol = ord(option[4])
                sig = (if_tsresol & 0x80)
                count = if_tsresol & 0x7f
                # we use microsecond
                if sig == 0:
                    # the remaining bits indicates the resolution of the timestamp
                    # as as a negative power of 10
                    self.section_info.tsresol = (10 ** -count) * (10 ** 6)
                else:  # sig == 1
                    # the resolution as as negative power of 2
                    self.section_info.tsresol = (2 ** -count) * (10 ** 6)
            elif code == 14:
                # if_tsoffset
                self.section_info.tsoffset, = struct.unpack(self.section_info.byteorder + b'Q',
                                                            option[4:12])
                self.section_info.tsoffset *= 10 ** 6
            elif code == 0:
                # end of option
                break
            mod = raw_len % 4
            if mod != 0:
                padding_len += (4 - mod)
            offset += 4 + padding_len

    def parse_enhanced_packet(self, block_len):
        buf = self.infile.read(4)
        # interface_id, = struct.unpack(self.section_info.byteorder + b'I', buf)

        # skip timestamp
        buf = self.infile.read(8)
        h, l, = struct.unpack(self.section_info.byteorder + b'II', buf)
        timestamp = (h << 32) + l
        micro_second = long(timestamp * self.section_info.tsresol + self.section_info.tsoffset)

        # capture len
        buf = self.infile.read(8)
        capture_len, packet_len = struct.unpack(self.section_info.byteorder + b'II', buf)
        # padded_capture_len = ((capture_len - 1) // 4 + 1) * 4

        # the captured data
        data = self.infile.read(capture_len)

        # skip other optional fields
        self.infile.read(block_len - 12 - 20 - capture_len)
        return micro_second, data

    def parse_block(self):
        """read and parse a block"""
        if self.head is not None:
            block_header = self.head + self.infile.read(8 - len(self.head))
            self.head = None
        else:
            block_header = self.infile.read(8)
        if len(block_header) < 8:
            return None
        block_type, block_len = struct.unpack(self.section_info.byteorder + b'II', block_header)

        data = ''
        micro_second = 0
        if block_type == BlockType.SECTION_HEADER:
            self.parse_section_header_block(block_header)
        elif block_type == BlockType.INTERFACE_DESCRIPTION:
            # read link type and capture size
            self.parse_interface_description_block(block_len)
        elif block_type == BlockType.ENHANCED_PACKET:
            micro_second, data = self.parse_enhanced_packet(block_len)
        elif block_type > 0x80000000:
            # private protocol type, ignore
            data = self.infile.read(block_len - 12)
        else:
            self.infile.read(block_len - 12)
            print("unknown block type:%s, size:%d" % (hex(block_type), block_len), file=sys.stderr)

        # read author block_len
        block_len_t = self.infile.read(4)
        block_len_t, = struct.unpack(self.section_info.byteorder + b'I', block_len_t)
        if block_len_t != block_len:
            print("block_len not equal, header:%d, tail:%d." % (block_len, block_len_t),
                  file=sys.stderr)
        return micro_second, data

    def read_packet(self):
        while True:
            data = self.parse_block()
            if data is None:
                return
            micro_second, link_packet = data
            if len(link_packet) == 0:
                continue
            yield self.section_info.link_type, micro_second, link_packet