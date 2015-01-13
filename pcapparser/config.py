from __future__ import unicode_literals, print_function, division

__author__ = 'dongliu'


class OutputLevel(object):
    ONLY_URL = 0
    HEADER = 1
    TEXT_BODY = 2
    ALL_BODY = 3


class ParseConfig(object):
    """ global settings """

    def __init__(self):
        self.level = OutputLevel.ALL_BODY # Changed to integrate with CapTipper
        self.pretty = False
        self.encoding = None
        self.group = False


_parse_config = ParseConfig()


def get_config():
    global _parse_config
    return _parse_config


class Filter(object):
    """filter settings"""

    def __init__(self):
        self.ip = None
        self.port = None
        self.domain = None
        self.uri_pattern = None

    def by_ip(self, ip):
        return not self.ip or self.ip == ip

    def by_port(self, port):
        return not self.port or self.port == port

    def by_domain(self, domain):
        return not self.domain or self.domain == domain

    def by_uri(self, uri):
        return not self.uri_pattern or self.uri_pattern in uri

_filter = Filter()


def get_filter():
    global _filter
    return _filter


out = None
