#
#          CapTipper is a malicious HTTP traffic explorer tool
#          By Omri Herscovici <omriher AT gmail.com>
#          http://omriher.com
#          @omriher
#
#          This file is part of CapTipper
#
#          CapTipper is a free software under the Apache License
#

from collections import namedtuple
import json
import urllib
import urllib2
import os
import collections
import urlparse

all_conversations = []
objects = []
hosts = collections.OrderedDict()
request_logs = []
VERSION = "0.01"
BUILD = "01"

# WS configurations
web_server_turned_on = False
HOST = "localhost"
PORT = 80

newLine = os.linesep

class colors:
    SKY = '\033[36m'
    PINK = '\033[35m'
    BLUE = '\033[34m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    END = '\033[37m'

# VirusTotal PUBLIC API KEY
APIKEY = ""

class client_struct:
    def __init__(self):
        self.headers = {}
        self.headers["IP"] = ""
        self.headers["MAC"] = ""
        self.ignore_headers = ['ACCEPT','ACCEPT-ENCODING','ACCEPT-LANGUAGE','CONNECTION','HOST','REFERER', \
                               'CACHE-CONTROL','CONTENT-TYPE', 'COOKIE', 'CONTENT-LENGTH']

    def add_header(self, key, value):
        if not self.headers.has_key(key.upper()) and not key.upper() in self.ignore_headers:
            self.headers[key.upper()] = value

    def get_information(self):
        return self.headers

# Client Information object
client = client_struct()
activity_date_time = ""

def add_object(type, value, id=-1, empty=False, name=""):
    object_num = len(objects)

    objects.append(collections.namedtuple('obj', ['type', 'value', 'conv_id', 'name']))

    objects[object_num].type = type
    if not empty:
        objects[object_num].value = value
    if id != -1:
        objects[object_num].conv_id = str(id)
        objects[object_num].name = type + "-" + get_name(id)
    else:
        objects[object_num].conv_id = str(object_num)
        objects[object_num].name = name

    return object_num

def get_name(id):
    name = ""
    try:
        name = objects[int(id)].name
    finally:
        return name

def show_hosts():
    for host in hosts.keys():
        print " " + host
        for host_uri in hosts[host]:
            #chr_num = 195 # Extended ASCII tree symbol
            chr_num = 9500  # UNICODE tree symbol

            # Checks if last one
            if (host_uri == hosts[host][len(hosts[host]) - 1]):
                #chr_num = 192 # Extended ASCII tree symbol
                chr_num = 9492 # UNICODE tree symbol

            try:
                print " " + unichr(chr_num) + "-- " + host_uri.encode('utf8')
            except:
                print " |-- " + host_uri.encode('utf8')
        print newLine

def check_duplicate_url(host, uri):
    bDup = False
    for conv in all_conversations:
        if (conv.uri.lower() == uri.lower()) and (conv.host.lower() == host.lower()):
            bDup = True
            break
    return bDup

def check_duplicate_uri(uri):
    bDup = False
    for conv in all_conversations:
        if (conv.uri.lower() == uri.lower()):
            bDup = True
            break
    return bDup

# In case of a duplicate URI, turns "/index.html" to "/index.html(2)"
def create_next_uri(uri):
    duplicate_uri = True
    orig_uri = uri
    uri_num = 2
    while duplicate_uri:
        duplicate_uri = False
        for conv in all_conversations:
            if (conv.uri.lower() == uri.lower()):
                uri = orig_uri + "(" + str(uri_num) + ")"
                uri_num += 1
                duplicate_uri = True
                break

    return uri

def finish_conversation(self):

    if not (check_duplicate_url(self.host, self.uri)):
        if check_duplicate_uri(self.uri):
            self.uri = create_next_uri(self.uri)

        obj_num = len(all_conversations)
        all_conversations.append(namedtuple('Conv',
            ['server_ip', 'uri','req_head','res_body','res_head','res_num','res_type','host','referer','filename','res_len']))

        # hosts list
        if (hosts.has_key(self.host)):
            hosts[self.host].append(self.uri + "   [" + str(obj_num) + "]")
        else:
            hosts[self.host] = [self.uri + "   [" + str(obj_num) + "]"]

        # convs list
        all_conversations[obj_num].server_ip = str(self.remote_host[0]) + ":" + str(self.remote_host[1])
        all_conversations[obj_num].uri = self.uri
        all_conversations[obj_num].req_head = self.req_head
        all_conversations[obj_num].res_body = self.res_body
        add_object("body", self.res_body)

        all_conversations[obj_num].orig_resp = self.orig_resp
        all_conversations[obj_num].res_head = self.res_head
        all_conversations[obj_num].res_num = self.res_num

        if ";" in self.res_type:
            all_conversations[obj_num].res_type = self.res_type[:self.res_type.find(";")]
        else:
            all_conversations[obj_num].res_type = self.res_type

        all_conversations[obj_num].host = self.host
        all_conversations[obj_num].referer = self.referer
        all_conversations[obj_num].filename = self.filename

        # In case no filename was given from the server, split by URI
        if (all_conversations[obj_num].filename == ""):
            uri_name = urlparse.urlsplit(str(all_conversations[obj_num].uri)).path
            all_conversations[obj_num].filename = uri_name.split('/')[-1]

            if (str(all_conversations[obj_num].filename).find('?') > 0):
                all_conversations[obj_num].filename = \
                    all_conversations[obj_num].filename[:str(all_conversations[obj_num].filename).find('?')]

            if (str(all_conversations[obj_num].filename).find('&') > 0):
                all_conversations[obj_num].filename = \
                    all_conversations[obj_num].filename[:str(all_conversations[obj_num].filename).find('&')]

        # In case the URI was '/' then this is still empty
        if (all_conversations[obj_num].filename == ""):
            all_conversations[obj_num].filename = str(obj_num) + ".html"


        objects[obj_num].name = all_conversations[obj_num].filename

        all_conversations[obj_num].res_len = self.res_len

# Display all found conversations
def show_conversations():
    cnt = -1
    for conv in all_conversations:
        try:
            cnt += 1
            typecolor = colors.END
            if ("pdf" in conv.res_type):
                typecolor = colors.RED
            elif ("javascript" in conv.res_type):
                typecolor = colors.BLUE
            elif ("octet-stream" in conv.res_type) or ("application" in conv.res_type):
                typecolor = colors.YELLOW
            elif ("image" in conv.res_type):
                typecolor = colors.GREEN

            print str(cnt) + ": " + colors.PINK + conv.uri + colors.END + " -> " + conv.res_type,
            if (conv.filename != ""):
                print typecolor + "(" + conv.filename.rstrip() + ")" + colors.END + " [" + str(conv.res_len) + " B]"
            else:
                print newLine
        except:
            pass
    print ""

def hexdump(src, length=16):
    result = []
    digits = 4 if isinstance(src, unicode) else 2
    for i in xrange(0, len(src), length):
        s = src[i:i + length]
        hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
        result.append(b"%04X   %-*s   %s" % (i, length * (digits + 1), hexa, text))
    return b'\n'.join(result)

from HTMLParser import HTMLParser

class CapTipperHTMLParser(HTMLParser):
    def __init__(self, find_tag):
        HTMLParser.__init__(self)
        self.find_tag = find_tag
        self.iframes = []

    def handle_starttag(self, tag, attrs):
        if tag == self.find_tag:
            for att in attrs:
                if (att[0] == "src"):
                    self.iframes.append(att[1])

    def print_iframes(self):
        if (len(self.iframes) > 0):
            print " " + str(len(self.iframes)) + " Iframe(s) Found!" + newLine
            cnt = 1
            for iframe in self.iframes:
                print " [I] " + str(cnt) + " : " + iframe
        else:
            print "     No Iframes Found"


def send_to_vt(md5, key_vt):
    if key_vt == "":
        return(-1, "No Public API Key Found")

    url_vt = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'resource':md5,'apikey':key_vt}
    try:
        body = urllib.urlencode(params)
        req = urllib2.Request(url_vt, body)
        res = urllib2.urlopen(req)
        res_json = res.read()
    except:
        return (-1, 'Request to Virus Total Failed')
    try:
        json_dict = json.loads(res_json)
    except:
        return (-1, 'Error during Virus Total response parsing')
    return (0, json_dict)

