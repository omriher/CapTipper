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

import StringIO
import cmd
import os
import CTCore
import time

from CTCore import hexdump
from CTCore import colors
from CTServer import server

newLine = os.linesep
DEFAULT_BODY_SIZE = 256

def get_id_size(line):
    l = line.split(" ")
    size = DEFAULT_BODY_SIZE
    if (len(l) > 1):
        size = l[1]

    id = int(l[0])
    return id, size

def get_head(id):
    header = CTCore.all_conversations[int(id)].res_head
    return header

def get_response_size(id, size, full_response=False):
    # if full response is needed and not just the body
    if int(id) >= len(CTCore.objects) or int(id) < 0:
        raise Exception("   ID number " + str(id) + " isn't within range")

    if (full_response):
        body = CTCore.all_conversations[int(id)].header + '\r\n\r\n' + CTCore.all_conversations[int(id)].res_body
    else:
        body = CTCore.objects[int(id)].value

    if not (isinstance(body, basestring)):
        comp_header = CTCore.all_conversations[int(id)].res_head
        body = CTCore.all_conversations[int(id)].res_head + "\r\n\r\n" + CTCore.all_conversations[int(id)].orig_resp
        if (comp_header + "\r\n\r\n" == body):
            print colors.RED + newLine + "[E] Object: {} ({}) : Response body was empty, showing header instead".format(id, CTCore.objects[int(id)].name) + colors.END + newLine
        else:
            print colors.RED + newLine + "[E] Object: {} ({}) : Couldn't retrieve BODY, showing full response instead".format(id, CTCore.objects[int(id)].name) + colors.END + newLine

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

def dump_file(id, path):
    id = int(id)
    body, sz = get_response_size(id, "all")

    f = open(path, "wb")
    f.write(body)
    f.close()
    print " Object {} written to {}".format(id, path)

class console(cmd.Cmd, object):
    """CapTipper console interpreter."""

    prompt = colors.SKY + 'CT> ' + colors.END
    intro = "CapTipper Interpreter" + newLine + \
            "Type 'open <conversation id>' to open address in browser" + newLine + \
            "type 'hosts' to view traffic flow" + newLine + \
            "Type 'help' for more options" + newLine

    def __init__(self):
        super(console, self).__init__()

    def emptyline(self):
        return

    def precmd(self, line):
        if line == 'EOF':
            return 'exit'
        else:
            return line

    def postloop(self):
        if (CTCore.web_server_turned_on):
            CTCore.web_server.shutdown()
        if self.use_rawinput:
            print newLine + "Leaving CapTipper... Good Bye!"

    def do_body(self, line):
        try:
            l = line.split(" ")
            if (l[0] == ""):
                self.help_body()
            else:
                id, size = get_id_size(line)
                response, size = get_response_size(id, size)
                name = CTCore.get_name(id)

                print "Displaying body of object {} ({}) [{} bytes]:".format(id, name, size)
                print newLine + response
        except Exception,e:
            print str(e)


    def help_body(self):
        print newLine + "Displays the text representation of the body"
        print newLine + "Usage: body <conv_id> [size=" + str(DEFAULT_BODY_SIZE) + "]"

    def do_open(self, line):
        try:
            l = line.split(" ")
            if (l[0] == ""):
                self.help_open()
            else:
                id = int(l[0])
                request = CTCore.all_conversations[id].uri
                import webbrowser
                webbrowser.open('http://' + CTCore.HOST + ":" + str(CTCore.PORT) + request)
        except Exception,e:
            print str(e)

    def help_open(self):
        print newLine + "Open the URL of the object in Default Browser"
        print newLine + "Usage: open <conv_id>"

    def do_log(self, line):
        try:
            if (len(CTCore.request_logs) > 0):
                for l in CTCore.request_logs:
                    print l
            else:
                print " No previous web server entries"
        except Exception,e:
            print str(e)

    def help_log(self):
        print newLine + "Displays the web server's Log"
        print newLine + "Usage: log"

    def do_dump(self,line):
        try:
            l = line.split(" ")
            if len(l) < 2:
                self.help_dump()
            else:
                if l[0].lower() == "all":
                    for i in range(0,len(CTCore.objects)):
                        if len(l) > 2:
                            if (l[2].lower() == "-e"):
                                if not CTCore.objects[i].name.lower().endswith(".exe"):
                                    dump_file(i, os.path.join(l[1], str(i) + "-" + CTCore.objects[i].name))
                        else:
                            dump_file(i, os.path.join(l[1],  str(i) + "-" + CTCore.objects[i].name))

                else:
                    dump_file(l[0],l[1])

        except Exception,e:
            print str(e)

    def help_dump(self):
        print newLine + "Dumps the object file to a given folder"
        print newLine + "Usage: dump <conv_id> <path>"
        print "Example: dump 4 c:" + chr(92) + "files" + chr(92) + "index.html"
        print "         Dumps object 4 to given path"
        print "Example: dump all c:" + chr(92) + "files"
        print "         Dumps all files to folder by their found name"
        print "Example: dump all c:" + chr(92) + "files -e"
        print "         Dumps all files to folder by their found name, without EXE files" + newLine


    def do_hexdump(self,line):
        try:
            l = line.split(" ")
            if (l[0] == ""):
                self.help_hexdump()
            else:
                id, size = get_id_size(line)
                response, size = get_response_size(id, size)
                name = CTCore.get_name(id)
                print "Displaying hexdump of object {} ({}) body [{} bytes]:".format(id, name, size)
                print newLine + hexdump(response) + newLine
        except Exception,e:
            print str(e)

    def help_hexdump(self):
        print "Display hexdump of given object"
        print newLine + "Usage: hexdump <conv_id>" + newLine

    def do_head(self,line):
        try:
            l = line.split(" ")
            if (l[0] == ""):
                self.help_head()
            else:
                id = int(l[0])
                header = get_head(id)
                name = CTCore.get_name(id)

                print "Displaying header of object {} ({}):".format(str(id), name)
                print newLine + header
        except Exception,e:
            print str(e)

    def help_head(self):
        print newLine + "Display header of response"
        print newLine + "Usage: head <conv_id>"

    def do_convs(self,line):
        print "Conversations Found:" + newLine
        CTCore.show_conversations()

    def help_convs(self):
        print newLine + "Display the conversations found"
        print newLine + "Usage: convs"

    def do_hosts(self,line):
        print "Found Hosts:" + newLine
        CTCore.show_hosts()

    def help_hosts(self):
        print newLine + "Display the hosts found in pcap and their URI's"
        print newLine + "Usage: hosts"

    def do_info(self,line):
        try:
            l = line.split(" ")
            if (l[0] == ""):
                self.help_info()
            else:
                id = l[0]
                conv_obj = CTCore.all_conversations[int(id)]

                print "Info of conversation {}: ".format(str(id))
                print newLine + \
                      " SERVER IP   : " + conv_obj.server_ip
                print " HOST        : " + conv_obj.host
                print " URI         : " + conv_obj.uri
                print " REFERER     : " + conv_obj.referer
                print " RESULT NUM  : " + conv_obj.res_num
                print " RESULT TYPE : " + conv_obj.res_type
                print " FILE NAME   : " + conv_obj.filename.rstrip()
                print " LENGTH      : " + str(conv_obj.res_len) + " B" + newLine
        except Exception,e:
            print str(e)

    def help_info(self):
        print newLine + "Display info on object"
        print newLine + "Usage: info <conv_id>"

    def do_client(self,line):
        try:
            print newLine + "Info of Client: " + newLine
            for key, value in CTCore.client.get_information().iteritems():
                print " {0:17}:  {1}".format(key, value)
            print ""
        except Exception,e:
            print str(e)

    def help_client(self):
        print newLine + "Displays information about the client"
        print newLine + "Usage: client"

    def do_ungzip(self,line):
        try:
            l = line.split(" ")
            if (l[0] == ""):
                self.help_ungzip()
            else:
                id = l[0]
                body, sz = get_response_size(id, "all")
                name = CTCore.get_name(id)
                import gzip

                decomp = gzip.GzipFile('', 'rb', 9, StringIO.StringIO(body))
                page = decomp.read()

                obj_num = CTCore.add_object("ungzip",page,id=id)
                print " GZIP Decompression of object {} ({}) successful!".format(str(id), name)
                print " New object created: {}".format(obj_num) + newLine
        except Exception,e:
            print str(e)

    def help_ungzip(self):
        print newLine + "Decompress gzip compression"
        print newLine + "Usage: ungzip <conv_id>"

    def do_exit(self, line):
        if (CTCore.web_server_turned_on):
            CTCore.web_server.shutdown()
        return True

    def do_ziplist(self, line):
        try:
            import zipfile
            l = line.split(" ")
            if (l[0] == ""):
                self.help_ziplist()
            else:
                id, size = get_id_size(line)
                response, size = get_response_size(id, "all")
                name = CTCore.get_name(id)
                fp = StringIO.StringIO(response)
                fp.write(response)
                zfp = zipfile.ZipFile(fp, "r")
                print " " + str(len(zfp.namelist())) + " Files found in zip object {} ({}):".format(str(id),name) + newLine
                cnt = 1
                for fl in zfp.namelist():
                    print " [Z] " + str(cnt) + " : " + fl
                    cnt += 1
                print ""
        except Exception,e:
            print "Error unzipping object: " + str(e)

    def help_ziplist(self):
        print newLine + "Lists files inside zip object"
        print newLine + "Usage: ziplist <conv_id>"

    def do_iframes(self,line):
        try:
            l = line.split(" ")
            if (l[0] == ""):
                self.help_resp()
            else:
                id, size = get_id_size(line)
                response, size = get_response_size(id, "all")
                name = CTCore.get_name(id)

                parser = CTCore.CapTipperHTMLParser("iframe")
                print "Searching for iframes in object {} ({})...".format(str(id),name)
                parser.feed(response)
                parser.print_iframes()
                print ""
        except Exception,e:
            print str(e)

    def help_iframes(self):
        print newLine + "Finds iframes in html/js files"
        print newLine + "Usage: iframes <obj_id>"

    def do_server(self,line):
        try:
            l = line.split(" ")
            if (l[0] == ""):
                self.help_server()
            else:
                s_cmd = l[0]
                if s_cmd.lower() == "on":
                    if CTCore.web_server_turned_on:
                        print "     Web Server already on: http://" + CTCore.HOST + ":" + CTCore.PORT
                    else:
                        CTCore.web_server = server()
                        CTCore.web_server.start()
                        time.sleep(0.1) # Fixes graphic issues
                        CTCore.web_server_turned_on = True
                elif s_cmd.lower() == "off":
                    if CTCore.web_server_turned_on:
                        CTCore.web_server.shutdown()
                    else:
                        print "     Web Server already off"
                else:
                    self.help_server()
        except Exception,e:
            print str(e)

    def help_server(self):
        print newLine + "Turn web server ON or OFF"
        print newLine + "Usage: server <on / off>"

    def do_vt(self,line):
        try:
            l = line.split(" ")
            if (l[0] == ""):
                self.help_vt()
            else:
                id = int(l[0])
                body, sz = get_response_size(id, "all")
                name = CTCore.get_name(id)

                print " VirusTotal result for object {} ({}):".format(str(id),name) + newLine

                import hashlib

                hash = hashlib.md5(StringIO.StringIO(body).getvalue()).hexdigest()
                vtdata = CTCore.send_to_vt(hash, CTCore.APIKEY)
                if vtdata[0] != -1:
                    jsonDict = vtdata[1]
                    if jsonDict.has_key('response_code'):
                        if jsonDict['response_code'] == 1:
                            if jsonDict.has_key('scans') and jsonDict.has_key('scan_date') \
                            and jsonDict.has_key('total') and jsonDict.has_key('positives') and jsonDict.has_key('permalink'):
                                print " Detection: {}/{}".format(jsonDict['positives'], jsonDict['total'])
                                print " Last Analysis Date: {}".format(jsonDict['scan_date'])
                                print " Report Link: {}".format(jsonDict['permalink']) + newLine
                                if jsonDict['positives'] > 0:
                                    print " Scan Result:"

                                    for av in jsonDict['scans']:
                                        av_res = jsonDict['scans'][av]
                                        if av_res.has_key('detected') and av_res.has_key('version') and av_res.has_key('result') and av_res.has_key('update'):
                                            if av_res['detected']:
                                                print "\t{}\t{}\t{}\t{}".format(av, av_res['result'], av_res['version'], av_res['update'])
                            else:
                                print " Missing elements in Virus Total Response"
                        else:
                            print " File not found in VirusTotal"

                    else:
                        print " Response from VirusTotal isn't valid"
                else:
                    print vtdata[1]
            print ""

        except Exception,e:
            print str(e)

    def help_vt(self):
        print newLine + "Checks file's md5 hash in virus total"
        print newLine + "Usage: vt <obj_id>"

    def do_hashes(self,line):
        try:
            l = line.split(" ")
            if (l[0] == ""):
                self.help_hashes()
            else:
                id = int(l[0])
                body, sz = get_response_size(id, "all")
                name = CTCore.get_name(id)

                print " Hashes of object {} ({}):".format(str(id),name) + newLine
                import hashlib

                for alg in hashlib.algorithms:
                    hashfunc = getattr(hashlib, alg)
                    hash = hashfunc(StringIO.StringIO(body).getvalue()).hexdigest()
                    print " {0:8}  :   {1}".format(alg, hash)

                print ""

        except Exception,e:
            print str(e)

    def help_hashes(self):
        print newLine + "Prints available hashes of object"
        print newLine + "Usage: hashes <obj_id>"

    def do_about(self, line):
        print newLine + "CapTipper v" + CTCore.VERSION + " - Malicious HTTP traffic explorer tool"
        print "Copyright 2015 Omri Herscovici <omriher@gmail.com>" + newLine
    def help_about(self):
        print newLine + "Prints about information"

    def help_exit(self):
        print 'Exits from the console'
        print 'Usage: exit'