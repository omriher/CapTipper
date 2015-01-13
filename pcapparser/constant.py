from __future__ import unicode_literals, print_function, division

__author__ = 'dongliu'


class HttpType(object):
    REQUEST = 0
    RESPONSE = 1


# see http://www.tcpdump.org/linktypes.html
# http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html#appendixLinkTypes
class LinkLayerType(object):
    """LinkType"""
    ETHERNET = 1
    LINUX_SLL = 113


class NetworkProtocol(object):
    IP = 2048
    IPV6 = 34525
    # Virtual Bridged Local Area Networks
    P802_1Q = 33024
    # IP Upper PPP 0x0021
    PPP_IP = 33
    # PPPOE Session 0x8864
    PPPOE_SESSION = 34916


class TransferProtocol(object):
    TCP = 6


class FileFormat(object):
    PCAP = 0xA1B2C3D4
    PCAP_NG = 0x0A0D0D0A
    UNKNOWN = -1


class BlockType(object):
    SECTION_HEADER = 0x0A0D0D0A
    INTERFACE_DESCRIPTION = 0x00000001
    PACKET = 0x00000002
    SIMPLE_PACKET = 0x00000003
    NAME_RESOLUTION = 0x00000004
    INTERFACE_STATISTICS = 0x00000005
    ENHANCED_PACKET = 0x00000006
    IRIG_TIMESTAMP = 0x00000007
    ARINC_429 = 0x00000008


class Compress(object):
    IDENTITY = 0  # No transformation is used. This is the default value for content coding.
    GZIP = 1
    DEFLATE = 2
    COMPRESS = 3  # UNIX "compress" program method (historic; deprecated in most applications)
    EXI = 4  # W3C Efficient XML Interchange
    PACK200_GZIP = 5  # Network Transfer Format for Java Archives

    # unofficial or non-standardized tokens
    BZIP2 = 6
    LZMA = 7
    SDCH = 8 # chrome vcdiff encoder