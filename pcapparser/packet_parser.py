# Changes made to integrate with CapTipper in lines: 18,30,101,115,120,123,126,131,172
from __future__ import unicode_literals, print_function, division

__author__ = 'dongliu'

import struct
import socket
from pcapparser.constant import *


class TcpPack:
    """ a tcp packet, header fields and data. """

    TYPE_INIT = 1  # init tcp connection
    TYPE_INIT_ACK = 2
    TYPE_ESTABLISH = 0  # establish conn
    TYPE_CLOSE = -1  # close tcp connection

    def __init__(self, source, source_port, dest, dest_port, pac_type, seq, ack, body, src_mac):
        self.source = source
        self.source_port = source_port
        self.dest = dest
        self.dest_port = dest_port
        self.pac_type = pac_type
        self.seq = seq
        self.ack = ack
        self.body = body
        self.direction = 0
        self.key = None
        self.micro_second = None
        self.src_mac = src_mac

    def __str__(self):
        return "%s:%d  -->  %s:%d, type:%d, seq:%d, ack:%s size:%d" % \
               (self.source, self.source_port, self.dest, self.dest_port, self.pac_type, self.seq,
                self.ack, len(self.body))

    def gen_key(self):
        if self.key:
            return self.key
        skey = '%s:%d' % (self.source, self.source_port)
        dkey = '%s:%d' % (self.dest, self.dest_port)
        if skey < dkey:
            self.key = skey + '-' + dkey
        else:
            self.key = dkey + '-' + skey
        return self.key

    def expect_ack(self):
        if self.pac_type == TcpPack.TYPE_ESTABLISH:
            return self.seq + len(self.body)
        else:
            return self.seq + 1


# http://standards.ieee.org/about/get/802/802.3.html
def dl_parse_ethernet(link_packet):
    """ parse Ethernet packet """

    eth_header_len = 14
    # ethernet header
    ethernet_header = link_packet[0:eth_header_len]

    (n_protocol, ) = struct.unpack(b'!12xH', ethernet_header)

    if n_protocol == NetworkProtocol.P802_1Q:
        # 802.1q, we need to skip two bytes and read another two bytes to get protocol/len
        type_or_len = link_packet[eth_header_len:eth_header_len + 4]
        eth_header_len += 4
        n_protocol, = struct.unpack(b'!2xH', type_or_len)
    if n_protocol == NetworkProtocol.PPPOE_SESSION:
        # skip PPPOE SESSION Header
        eth_header_len += 8
        type_or_len = link_packet[eth_header_len - 2:eth_header_len]
        n_protocol, = struct.unpack(b'!H', type_or_len)
    if n_protocol < 1536:
        # TODO n_protocol means package len
        pass
    return n_protocol, link_packet[eth_header_len:]


# http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
def dl_parse_linux_sll(link_packet):
    """ parse linux sll packet """

    sll_header_len = 16

    # Linux cooked header
    linux_cooked = link_packet[0:sll_header_len]

    packet_type, link_type_address_type, link_type_address_len, link_type_address, n_protocol \
        = struct.unpack(b'!HHHQH', linux_cooked)
    return n_protocol, link_packet[sll_header_len:]


# see http://en.wikipedia.org/wiki/Ethertype
def read_ip_pac(link_packet, link_layer_parser):
    # ip header
    n_protocol, ip_packet = link_layer_parser(link_packet)

    if n_protocol == NetworkProtocol.IP or n_protocol == NetworkProtocol.PPP_IP:
        src_mac = ":".join("{:02x}".format(ord(c)) for c in link_packet[6:12])
        ip_base_header_len = 20
        ip_header = ip_packet[0:ip_base_header_len]
        (ip_info, ip_length, protocol) = struct.unpack(b'!BxH5xB10x', ip_header)
        # real ip header len.
        ip_header_len = (ip_info & 0xF) * 4
        ip_version = (ip_info >> 4) & 0xF

        # skip all extra header fields.
        if ip_header_len > ip_base_header_len:
            pass

        # not tcp, skip.
        if protocol != TransferProtocol.TCP:
            return 0, None, None, None, None

        source = socket.inet_ntoa(ip_header[12:16])
        dest = socket.inet_ntoa(ip_header[16:])

        return 1, source, dest, ip_packet[ip_header_len:ip_length], src_mac
    elif n_protocol == NetworkProtocol.IPV6:
        # TODO: deal with ipv6 package
        return 0, None, None, None, None
    else:
        # skip
        return 0, None, None, None, None


def read_tcp_pac(link_packet, link_layer_parser):
    """read tcp data.http only build on tcp, so we do not need to support other protocols."""
    state, source, dest, tcp_packet, src_mac = read_ip_pac(link_packet, link_layer_parser)
    if state == 0:
        return 0, None

    tcp_base_header_len = 20
    # tcp header
    tcp_header = tcp_packet[0:tcp_base_header_len]
    source_port, dest_port, seq, ack_seq, t_f, flags = struct.unpack(b'!HHIIBB6x', tcp_header)
    # real tcp header len
    tcp_header_len = ((t_f >> 4) & 0xF) * 4
    # skip extension headers
    if tcp_header_len > tcp_base_header_len:
        pass

    fin = flags & 1
    syn = (flags >> 1) & 1
    rst = (flags >> 2) & 1
    psh = (flags >> 3) & 1
    ack = (flags >> 4) & 1
    urg = (flags >> 5) & 1

    # body
    body = tcp_packet[tcp_header_len:]
    # workaround to ignore no-data tcp packs
    if 0 < len(body) < 20:
        total = 0
        for ch in body:
            total += ord(ch)
        if total == 0:
            body = b''

    if syn == 1 and ack == 0:
        # init tcp connection
        pac_type = TcpPack.TYPE_INIT
    elif syn == 1 and ack == 1:
        pac_type = TcpPack.TYPE_INIT_ACK
    elif fin == 1:
        pac_type = TcpPack.TYPE_CLOSE
    else:
        pac_type = TcpPack.TYPE_ESTABLISH

    return 1, TcpPack(source, source_port, dest, dest_port, pac_type, seq, ack_seq, body, src_mac)


def get_link_layer_parser(link_type):
    if link_type == LinkLayerType.ETHERNET:
        return dl_parse_ethernet
    elif link_type == LinkLayerType.LINUX_SLL:
        return dl_parse_linux_sll
    else:
        return None


def read_tcp_packet(read_packet):
    """ generator, read a *TCP* package once."""

    for link_type, micro_second, link_packet in read_packet():
        try:
            link_layer_parser = get_link_layer_parser(link_type)
            state, pack = read_tcp_pac(link_packet, link_layer_parser)
            if state == 1 and pack:
                pack.micro_second = micro_second
                yield pack
                continue
            else:
                continue
        except:
            pass


def read_package_r(pcap_file):
    """
    clean up tcp packages.
    note:we abandon the last ack package after fin.
    """
    conn_dict = {}
    reverse_conn_dict = {}
    direction_dict = {}
    for pack in read_tcp_packet(pcap_file):
        key = pack.gen_key()
        # if a SYN is received, erase cached connection with same key.
        if key in conn_dict and pack.pac_type == TcpPack.TYPE_INIT:
            del conn_dict[key]
        # if we haven't keep this connection, construct one.
        if key not in conn_dict:
            # remember the next SEQ should appear as list[0] to skip all retransmit
            # packets. list[1] to indicate whether the socket is closed.
            conn_dict[key] = [pack.seq, 0, []]
            # if it's SYN, the data length is considered as 1.
            if pack.pac_type == TcpPack.TYPE_INIT:
                conn_dict[key][0] += 1
            reverse_conn_dict[key] = [pack.ack, 0, []]
            direction_dict[key] = pack.source + str(pack.source_port)

        if pack.source + str(pack.source_port) == direction_dict[key]:
            hold_packs = conn_dict[key]
        else:
            hold_packs = reverse_conn_dict[key]

        # if the connection is insert into dictionary by SYN, we should update
        # reverse SEQ, consider the SYN+ACK packet data length as 1.
        if pack.pac_type == TcpPack.TYPE_INIT_ACK:
            if reverse_conn_dict[key][0] == 0:
                reverse_conn_dict[key][0] = pack.seq + 1

        # do not receive anything after FIN/RST
        if hold_packs[1] == 1:
            continue
        if pack.pac_type == TcpPack.TYPE_CLOSE:
            hold_packs[1] = 1

        # only store FIN/RST or packets which have payload data.
        if pack.body or pack.pac_type == TcpPack.TYPE_CLOSE:
            hold_packs[2].append(pack)
            hold_packs[2] = sorted(hold_packs[2], key=lambda x: x.seq)

        yield_list = []
        while len(hold_packs[2]) > 0:
            first_pack = hold_packs[2][0]
            if not first_pack.body:
                # this must be a RST/FIN packet without data.
                yield_list.append(first_pack)
                del hold_packs[2][0]
                continue
            elif first_pack.seq > hold_packs[0]:
                # there has some packets lost, wait.
                break
            elif first_pack.seq == hold_packs[0]:
                # the first packet matches the expected SEQ exactly.
                hold_packs[0] = first_pack.seq + len(first_pack.body)
                yield_list.append(first_pack)
                del hold_packs[2][0]
            elif first_pack.seq + len(first_pack.body) <= hold_packs[0]:
                # the packet is a retransmit packet.
                del hold_packs[2][0]
            else:
                # part of the packet data is retransmit, part of it is useful.
                trim_len = first_pack.seq + len(first_pack.body) - hold_packs[0]
                first_pack.body = first_pack.body[-1 * trim_len:]
                first_pack.seq = hold_packs[0]
                hold_packs[0] += trim_len
                yield_list.append(first_pack)
                del hold_packs[2][0]

        for ipack in yield_list:
            yield ipack
