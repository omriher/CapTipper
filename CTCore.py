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


from collections import namedtuple
import StringIO
import json
import urllib
import urllib2
import os
import collections
import urlparse
import gzip
import re
import sys
import zipfile

from CTMagic import Whatype

newLine = os.linesep
conversations = []
objects = []
Errors = []
hosts = collections.OrderedDict()
request_logs = []
plugins = []
plugins_folder = "plugins/"
pcap_file = ""
VERSION = "0.3"
BUILD = "13"
ABOUT = "CapTipper v" + VERSION + " b" + BUILD + " - Malicious HTTP traffic explorer tool" + newLine + \
        "Copyright 2015 Omri Herscovici <omriher@gmail.com>" + newLine

USAGE = ("CapTipper.py <pcap_file> [options]" + newLine + newLine +
        "Examples: CapTipper.py ExploitKit.pcap           -     explore and start server on port 80" + newLine +
        "          CapTipper.py ExploitKit.pcap -p 1234   -     explore and start server on port 1234" + newLine +
        "          CapTipper.py ExploitKit.pcap -d /tmp/  -     dumps all files and exit" + newLine +
        "          CapTipper.py ExploitKit.pcap -r /tmp/  -     create json & html report and exit" + newLine +
        "          CapTipper.py ExploitKit.pcap -s        -     explore without web server" + newLine)

# WS configurations
web_server_turned_on = False
HOST = "0.0.0.0"
PORT = 80

console_output = False

b_use_short_uri = False
b_auto_ungzip = False

class msg_type:
    GOOD = 0
    ERROR = 1
    INFO = 2

class colors:
    SKY = '\033[36m'
    PINK = '\033[35m'
    BLUE = '\033[34m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    END = '\033[0;0m'
    #END = '\033[37m'
    STRONG_BRIGHT = '\033[1m'
    NORMAL_BRIGHT = '\033[22m'

# VirusTotal PUBLIC API KEY
VT_APIKEY = ""

try:
    WhatypeMagic = Whatype(os.path.join(os.path.dirname(os.path.realpath(__file__)),"magics.csv"))
except Exception, e:
    Errors.append("Couldn't load Whatype for magic identification: " + e.message)

class client_struct:
    def __init__(self):
        self.headers = collections.OrderedDict()
        self.headers["IP"] = ""
        self.headers["MAC"] = ""
        self.ignore_headers = ['ACCEPT','ACCEPT-ENCODING','ACCEPT-LANGUAGE','CONNECTION','HOST','REFERER', \
                               'CACHE-CONTROL','CONTENT-TYPE', 'COOKIE', 'CONTENT-LENGTH', 'X-REQUESTED-WITH', \
                               'IF-MODIFIED-SINCE','IF-NONE-MATCH','ORIGIN','ACCEPT-ASTEROPE','IF-UNMODIFIED-SINCE']

    def add_header(self, key, value):
        if not self.headers.has_key(key.upper()) and not key.upper() in self.ignore_headers:
            self.headers[key.upper()] = value

    def get_information(self):
        return self.headers

def alert_message(text, type):
    if type == msg_type.GOOD:
        message = colors.GREEN + "[+] " + colors.END
    elif type == msg_type.ERROR:
        message = colors.RED + " [E] " + colors.END
    elif type == msg_type.INFO:
        message = colors.YELLOW + "[!] " + colors.END

    message += text
    print message

def show_errors():
    global Errors
    if len(Errors) > 0:
        for err in Errors:
            print err

def check_errors():
    global Errors
    if len(Errors) > 0:
        return True
    else:
        return False

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

def fmt_size(size_bytes):
    for unit in ['B','KB','MB','GB','TB']:
        if size_bytes < 1024.0:
            return "%3.1f %s" % (size_bytes, unit)
        size_bytes /= 1024.0
    return "{%3.1f} {}".format(size_bytes, 'PB')

def get_name(id):
    name = ""
    try:
        name = objects[int(id)].name
    finally:
        return name

def show_hosts():
    for host, ip in hosts.keys():
        print " " + host + " ({})".format(ip)
        hostkey = (host, ip)
        for host_uri,obj_num in hosts[hostkey]:
            #chr_num = 195 # Extended ASCII tree symbol
            chr_num = 9500  # UNICODE tree symbol

            # Checks if last one
            if ((host_uri,obj_num) == hosts[hostkey][len(hosts[hostkey]) - 1]):
                #chr_num = 192 # Extended ASCII tree symbol
                chr_num = 9492 # UNICODE tree symbol

            try:
                print " " + unichr(chr_num) + "-- " + host_uri.encode('utf8') + "   [{}]".format(obj_num)
            except:
                print " |-- " + host_uri.encode('utf8') + "   [{}]".format(obj_num)

        print newLine

def check_duplicate_url(host, uri):
    bDup = False
    for conv in conversations:
        if (conv.uri.lower() == uri.lower()) and (conv.host.lower() == host.lower()):
            bDup = True
            break
    return bDup

def check_duplicate_uri(uri):
    bDup = False
    for conv in conversations:
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
        for conv in conversations:
            if (conv.uri.lower() == uri.lower()):
                uri = orig_uri + "(" + str(uri_num) + ")"
                uri_num += 1
                duplicate_uri = True
                break
    return uri

SHORT_URI_SIZE = 20
def getShortURI(uri):
    shortURL = uri
    if len(uri) > SHORT_URI_SIZE:
        shortURL = uri[0:int(SHORT_URI_SIZE/2)] + "..." + uri[len(uri)-int(SHORT_URI_SIZE/2):len(uri)]
    return shortURL

def byTime(Conv):
    return int(Conv.req_microsec)

def sort_convs():
    conversations.sort(key=byTime)
    for cnt, conv in enumerate(conversations):
        conv.id = cnt
        add_object("body", conv.res_body)
        objects[cnt].name = conv.filename

        # Populating hosts list
        host_tuple = (conv.host, conv.server_ip_port)
        if (hosts.has_key(host_tuple)):
            hosts[host_tuple].append((conv.uri,str(cnt)))
        else:
            hosts[host_tuple] = [(conv.uri,str(cnt))]


def check_order(Conv):
    for curr_conv in conversations:
        if int(curr_conv.req_microsec) > int(str(Conv.time)[:10]):
            return False

    return True

def finish_conversation(self):

    if not (check_duplicate_url(self.host, self.uri)):

        #if check_duplicate_uri(self.uri):
        #    self.uri = create_next_uri(self.uri)

        obj_num = len(conversations)
        conversations.append(namedtuple('Conv',
            ['id','server_ip_port', 'uri','req','res_body','res_head','res_num','res_type','host','referer', \
            'filename','method','redirect_to','req_microsec', 'res_len','magic_name', 'magic_ext']))

        # convs list
        conversations[obj_num].id = obj_num
        conversations[obj_num].server_ip_port = str(self.remote_host[0]) + ":" + str(self.remote_host[1])
        conversations[obj_num].uri = self.uri
        conversations[obj_num].redirect_to = self.redirect_to
        conversations[obj_num].short_uri = getShortURI(self.uri)
        conversations[obj_num].req = self.req
        conversations[obj_num].res_body = self.res_body


        try:
            # FindMagic
            mgc_name = ""
            mgc_ext = ""
            mgc_name, mgc_ext = WhatypeMagic.identify_buffer(self.res_body)
        except:
            pass

        conversations[obj_num].magic_name = mgc_name.rstrip()
        conversations[obj_num].magic_ext = mgc_ext.rstrip()

        conversations[obj_num].orig_chunked_resp = self.orig_chunked_resp
        conversations[obj_num].orig_resp = self.orig_resp
        conversations[obj_num].res_head = self.res_head
        conversations[obj_num].res_num = self.res_num

        if ";" in self.res_type:
            conversations[obj_num].res_type = self.res_type[:self.res_type.find(";")]
        else:
            conversations[obj_num].res_type = self.res_type

        conversations[obj_num].host = self.host
        conversations[obj_num].referer = self.referer
        conversations[obj_num].filename = self.filename
        conversations[obj_num].method = self.method
        conversations[obj_num].req_microsec = str(self.time)[:10]


        # In case no filename was given from the server, split by URI
        if (conversations[obj_num].filename == ""):
            uri_name = urlparse.urlsplit(str(conversations[obj_num].uri)).path
            conversations[obj_num].filename = uri_name.split('/')[-1]

            if (str(conversations[obj_num].filename).find('?') > 0):
                conversations[obj_num].filename = \
                    conversations[obj_num].filename[:str(conversations[obj_num].filename).find('?')]

            if (str(conversations[obj_num].filename).find('&') > 0):
                conversations[obj_num].filename = \
                    conversations[obj_num].filename[:str(conversations[obj_num].filename).find('&')]

        # In case the URI was '/' then this is still empty
        if (conversations[obj_num].filename == ""):
            conversations[obj_num].filename = str(obj_num) + ".html"

        conversations[obj_num].res_len = self.res_len

# Display all found conversations
def show_conversations():
    if (b_use_short_uri):
        alert_message("Displaying shortened URI paths" + newLine, msg_type.INFO)

    for cnt, conv in enumerate(conversations):
        try:
            typecolor = colors.END
            if ("pdf" in conv.res_type):
                typecolor = colors.RED
            elif ("javascript" in conv.res_type):
                typecolor = colors.BLUE
            elif ("octet-stream" in conv.res_type) or ("application" in conv.res_type):
                typecolor = colors.YELLOW
            elif ("image" in conv.res_type):
                typecolor = colors.GREEN

            print str(conv.id) + ": " + colors.PINK,
            if (b_use_short_uri):
                print conv.short_uri,
            else:
                print conv.uri,
            print colors.END + " -> " + conv.res_type,
            if (conv.filename != ""):
                print typecolor + "(" + conv.filename.rstrip() + ")" + colors.END + " [" + str(fmt_size(conv.res_len)) + "]",

                # If magic found
                if conv.magic_ext != "":
                    print " (Magic: " + colors.STRONG_BRIGHT + "{}".format(conv.magic_ext) + colors.NORMAL_BRIGHT + ")"
                else:
                    print ""
            else:
                print newLine
        except:
            pass
    print ""

def show_objects():
    print "Displaying Objects:" + newLine
    print " ID   CID     TYPE          NAME"
    print "---- -----  -----------   --------"

    for id, obj in enumerate(objects):
        print "{0:3} | {1:3} | {2:11} | {3}".format(id, obj.conv_id, obj.type, obj.name)

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

class srcHTMLParser(HTMLParser):
    def __init__(self, find_tag):
        HTMLParser.__init__(self)
        self.find_tag = find_tag
        self.tags = []

    def handle_starttag(self, tag, attrs):
        if tag == self.find_tag:
            for att in attrs:
                if att[0] == "src":
                    self.tags.append(att[1])

    def print_objects(self):
        if len(self.tags) > 0:
            print " " + str(len(self.tags)) + " {}(s) Found!".format(self.find_tag) + newLine

            for cnt, curr_tag in enumerate(self.tags):
                print " [I] " + str(cnt + 1) + " : " + curr_tag
        else:
            print "     No {} Found".format(self.find_tag)

def update_captipper():
    currentVersion = "v{} b{}".format(VERSION,BUILD)
    rawURL = "https://raw.githubusercontent.com/omriher/CapTipper/master/"
    archiveURL = "https://github.com/omriher/CapTipper/archive/"
    CoreFile = "CTCore.py"
    CTArchive = "master.zip"

    CoreURL = rawURL + CoreFile
    print "Checking for updates (Current version: {})".format(currentVersion)
    try:
        print "Connecting to CapTipper Repository"
        coreRepFile = urllib2.urlopen(CoreURL).read()
    except:
        sys.exit("[-] Error connecting to CapTipper repository")

    verPattern = "VERSION = " + chr(34) + "(.*)" + chr(34) + "\s*?BUILD = " + chr(34) + "(.*)" + chr(34)
    repoVer = re.findall(verPattern, coreRepFile)
    if repoVer:
        newVersion = "v{} b{}".format(repoVer[0][0],repoVer[0][1])
    else:
        sys.exit('[-] Error getting repository version')

    if newVersion == currentVersion:
         sys.exit("[+] You have the newest version!")
    else:
        print "[+] Updating CapTipper to {}".format(newVersion)
        bPackSize = False
        nAttempts = 0
        while (not bPackSize and nAttempts < 3):
            try:
                url = archiveURL + CTArchive
                u = urllib2.urlopen(url)
                content_length = u.info().getheaders("content-length")
                if len(content_length) > 0:
                    file_size = int(content_length[0])
                    bPackSize = True
                else:
                    print("[-] Couldn't get package size, Retrying ({} / 3)...".format(str(nAttempts)))
            except Exception,e:
                sys.exit("[-] Error downloading update: {}".format(e.message))
            finally:
                nAttempts += 1

        if not bPackSize:
            sys.exit("[-] Couldn't get package size, Please try again later...")

        try:
            package_name = "CapTipper-package.zip"
            f = open(package_name, 'wb')
            file_downloaded = 0
            block_size = 8192
            while True:
                buffer = u.read(block_size)
                if not buffer:
                    break
                file_downloaded += len(buffer)
                f.write(buffer)
                output = "[+] Downloading {0:.2f}%".format(file_downloaded * 100. / file_size)
                sys.stdout.write('\r%s' % output)
                sys.stdout.flush()
            f.close()
            CapTipper_Folder = os.path.dirname(os.path.realpath(__file__))
        except Exception, e:
            print "[-] Error downloading file: {}".format(e.message)

        print "\nExtracting Files..."
        try:
            z = zipfile.ZipFile('CapTipper-package.zip')
            master_folder = ""
            for name in z.namelist():
                if not master_folder:
                    master_folder = name[:-1]
                full_path = CapTipper_Folder + name.replace(master_folder,"")
                # Case of directory
                if full_path.endswith(r"/"):
                    if not os.path.exists(full_path):
                        os.makedirs(full_path)
                else:
                    if os.name == 'nt':
                        full_path = full_path.replace("/",r"\\")

                    print "Extracting {}".format(full_path)
                    with open(full_path,"wb") as out:
                        out.write(z.read(name))
            try:
                os.remove("CapTipper-package.zip")
            except Exception, ed:
                print "Failed deleting CapTipper-package.zip : " + ed.message
            print "Update Complete! (New version: {})".format(newVersion)
        except Exception,e:
            sys.exit("Failed extracting files: {}".format(e.message))
    sys.exit("Finished updating CapTipper")

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
        return (-1, 'Request to VirusTotal Failed')
    try:
        json_dict = json.loads(res_json)
    except:
        return (-1, 'Error during VirusTotal response parsing')
    return (0, json_dict)

def get_strings(content):
    strings = re.findall("[\x1f-\x7e]{5,}", content)
    strings += [str(ws.decode("utf-16le")) for ws in re.findall("(?:[\x1f-\x7e][\x00]){5,}", content)]
    return strings

def get_request_size(id, size, full_request=False):

    if int(id) >= len(objects) or int(id) < 0:
        raise Exception("   ID number " + str(id) + " isn't within range")

    request = conversations[int(id)].req
    if (size.lower() == "all"):
        size = len(request)
    else:
        size = int(size)
        request = request[0:size]
        if len(request) < size:
            size = len(request)

    return request, size

def get_response_and_size(id, size, full_response=False):
    global Errors
    Errors = []

    if int(id) >= len(objects) or int(id) < 0:
        raise Exception("   ID number " + str(id) + " isn't within range")

    # if full response is needed and not just the body
    if (full_response):
        body = conversations[int(id)].header + '\r\n\r\n' + conversations[int(id)].res_body
    else:
        body = objects[int(id)].value

    if not (isinstance(body, basestring)):
        comp_header = conversations[int(id)].res_head
        test_res = conversations[int(id)].res_head + "\r\n\r\n" + conversations[int(id)].orig_chunked_resp
        body = ""
        if (comp_header + "\r\n\r\n" == test_res):
            #print colors.RED + newLine + "[E] Object: {} ({}) : Response body was empty, showing header instead".format(id, CTCore.objects[int(id)].name) + colors.END + newLine
            Errors.append(colors.RED + newLine + "[E] Object: {} ({}) : Response body was empty".format(id, objects[int(id)].name) + colors.END + newLine)
        else:
            #print colors.RED + newLine + "[E] Object: {} ({}) : Couldn't retrieve BODY, showing full response instead".format(id, CTCore.objects[int(id)].name) + colors.END + newLine
            Errors.append(colors.RED + newLine + "[E] Object: {} ({}) : Couldn't retrieve BODY".format(id, objects[int(id)].name) + colors.END + newLine)

        if (size != "all"):
            size = size * 2

    if (size == "all"):
        response = body
        size = len(response)
    else:
        size = int(size)
        response = body[0:size]
        if len(response) < size:
            size = len(response)

    return response, size

def ungzip_all():
    for conv in conversations:
        try:
            if conv.res_head.lower().find("gzip") > -1:
                name = ""
                try:
                    id = int(conv.id)
                    name = get_name(id)
                    obj_num, name = ungzip_and_add(id)
                    if obj_num != -1:
                        print " GZIP Decompression of object {} ({}) successful!".format(str(id), name)
                        print " New object created: {}".format(obj_num) + newLine
                except Exception, e:
                    print "Error in: {} - {}".format(name,str(e))
        except:
            pass

def ungzip(id):
    body, sz = get_response_and_size(id, "all")
    obj_num = -1
    name = ""
    if not check_errors():
        name = get_name(id)
        decomp = gzip.GzipFile('', 'rb', 9, StringIO.StringIO(body))
        page = decomp.read()

    return page, name

def ungzip_and_add(id):
    page, name = ungzip(id)
    obj_num = add_object("ungzip",page,id=id)
    return obj_num, name

def dump_all_files(path, dump_exe):
    for i in range(0,len(objects)):
        try:
            if (not objects[i].name.lower().endswith(".exe")) or dump_exe:
                dump_file(i, os.path.join(path, str(i) + "-" + objects[i].name))
        except Exception, ef:
            print str(ef)

def dump_file(id, path):
    id = int(id)
    body, sz = get_response_and_size(id, "all")

    show_errors()

    f = open(path, "wb")
    f.write(body)
    f.close()
    print " Object {} written to {}".format(id, path)

def find_plugin(name):
    for plug in plugins:
        if plug.name.lower() == name.lower():
            return plug.module
    return None

def run_plugin(name, *args):
    try:
        module = find_plugin(name)
        if module:
            current = module()
            result = current.run(*args)
            return result
        else:
            return "Plugin " + name + " Does not exist"
    except Exception,e:
        print str(e)
