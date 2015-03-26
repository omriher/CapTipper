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

import StringIO
import cmd
import os
import time
import hashlib

import CTCore
from CTCore import hexdump
from CTCore import colors
from CTCore import msg_type
from CTServer import server
from pescanner import PEScanner

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
    header = CTCore.conversations[int(id)].res_head
    return header


SHOW_LEN_AROUND = 25
REPLACE_LIST = ['\r','\n']
def find_pattern(content, pattern):
    import re
    return_results = []
    regex = re.compile(pattern, re.IGNORECASE)
    results = regex.finditer(content)
    for result in results:
        match = result.group()
        if (result.start() - SHOW_LEN_AROUND) < 0:
            start = 0
        else:
            start = result.start() - SHOW_LEN_AROUND

        if (result.end() + SHOW_LEN_AROUND) > len(content):
            end = len(content)
        else:
            end = result.end() + SHOW_LEN_AROUND

        before_match = content[start:result.start()]
        after_match = content[result.end():end]

        for rep in REPLACE_LIST:
            before_match = before_match.replace(rep, "")
            after_match = after_match.replace(rep, "")

        result_line = before_match + colors.STRONG_BRIGHT + match + colors.NORMAL_BRIGHT + after_match + colors.END

        lineno = content.count('\n', 0, result.start()) + 1
        return_results.append(" ({},{}) : ".format(str(lineno), str(result.start())) + result_line)
    return return_results

def find_end_of_block(response, offset):
    index = response.find("{",offset)
    braces_c = 1
    while (braces_c > 0):
        index += 1
        char = response[index]
        if char == "{":
            braces_c += 1
        elif char == "}":
            braces_c -= 1

    return index - offset + 1

def get_bytes(response,offset,length_or_eob):
    if (length_or_eob.lower() == "eob"):
        length = find_end_of_block(response,offset)
    else:
        length = int(length_or_eob)

        if offset > len(response):
            print " Offset {} is not in range, object size is {}".format(str(offset), str(len(response)))

        if offset + length > len(response):
            length = len(response) - offset

    return response[offset:offset+length], length

def in_range(id, list_type='objects'):
    listname = getattr(CTCore, list_type)
    if int(id) >= len(listname) or int(id) < 0:
        print "   ID number " + str(id) + " isn't within range of " + list_type + " list"
        return False

    return True

def check_path(path,type="file"):
    directory = os.path.dirname(path)
    if type == "file" and os.path.isdir(path):
        CTCore.alert_message("Please specify a full path and not a folder",msg_type.ERROR)
        return False

    if not os.path.isdir(directory):
        print newLine + " Directory {} doesn't exists. Create? (Y/n):".format(directory),
        ans = raw_input()
        if ans.lower() == "y" or ans == "":
            os.makedirs(directory)
            return True
        else:
            return False
    else:
        return True

class console(cmd.Cmd, object):
    """CapTipper console interpreter."""

    prompt = colors.SKY + 'CT> ' + colors.END
    intro = "Starting CapTipper Interpreter" + newLine + \
            "Type 'open <conversation id>' to open address in browser" + newLine + \
            "Type 'hosts' to view traffic flow" + newLine + \
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
                response, size = CTCore.get_response_and_size(id, size)
                name = CTCore.get_name(id)
                print "Displaying body of object {} ({}) [{} bytes]:".format(id, name, size)
                CTCore.show_errors()
                print newLine + response
        except Exception,e:
            print str(e)


    def help_body(self):
        print newLine + "Displays the text representation of the body"
        print newLine + "Ufsage: body <conv_id> [size=" + str(DEFAULT_BODY_SIZE) + "]"

    def do_open(self, line):
        try:
            l = line.split(" ")
            if (l[0] == ""):
                self.help_open()
            else:
                bOpen = False
                if not CTCore.web_server_turned_on:
                    print newLine + " Web server is turned off, open anyway? (Y/n):",
                    ans = raw_input()
                    if ans.lower() == "y" or ans == "":
                        bOpen = True
                else:
                    bOpen = True

                if bOpen:
                    id = int(l[0])
                    request = CTCore.conversations[id].uri
                    open_url = 'http://' + CTCore.HOST + ":" + str(CTCore.PORT) + request
                    print("  Opening {} in default browser".format(open_url))
                    import webbrowser
                    webbrowser.open(open_url)
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
                    dump_exe = True
                    if len(l) > 2 and l[2].lower() == "-e":
                        dump_exe = False
                    CTCore.dump_all_files(l[1], dump_exe)
                else:
                    id = l[0]
                    path = l[1]
                    if check_path(path, type="file"):
                        CTCore.dump_file(id,path)

        except Exception,e:
            print str(e)

    def help_dump(self):
        print newLine + "Dumps the object file to a given folder"
        print newLine + "Usage: dump <conv_id> <path>" + newLine
        print "Example: dump 4 c:" + chr(92) + "files" + chr(92) + "index.html"
        print "         Dumps object 4 to given path" + newLine
        print "Example: dump all c:" + chr(92) + "files"
        print "         Dumps all files to folder by their found name" + newLine
        print "Example: dump all c:" + chr(92) + "files -e"
        print "         Dumps all files to folder by their found name, without EXE files" + newLine


    def do_hexdump(self,line):
        try:
            l = line.split(" ")
            if (l[0] == ""):
                self.help_hexdump()
            else:
                id, size = get_id_size(line)
                response, size = CTCore.get_response_and_size(id, size)
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

    def do_objects(self,line):
        CTCore.show_objects()
        print ""

    def help_objects(self):
        print newLine + "Display all objects, found or created"
        print newLine + "Usage: objects"

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
                if in_range(id, list_type='conversations'):
                    conv_obj = CTCore.conversations[int(id)]

                    print "Info of conversation {}: ".format(str(id))
                    print newLine + \
                          " SERVER IP   : " + conv_obj.server_ip
                    print " TIME        : " + time.strftime('%a, %x %X', time.gmtime(int(conv_obj.req_microsec)))
                    print " HOST        : " + conv_obj.host
                    print " URI         : " + conv_obj.uri
                    print " REFERER     : " + conv_obj.referer
                    print " METHOD      : " + conv_obj.method
                    print " RESULT NUM  : " + conv_obj.res_num
                    print " RESULT TYPE : " + conv_obj.res_type
                    print " FILE NAME   : " + conv_obj.filename.rstrip()
                    if conv_obj.magic_name != "":
                        print " MAGIC       : " + conv_obj.magic_name + " ({})".format(conv_obj.magic_ext)
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
                if l[0].lower() == "all":
                    CTCore.ungzip_all()
                else:
                    id = int(l[0])
                    if in_range(id):
                        obj_num, name = CTCore.ungzip(id)
                        if obj_num != -1:
                            print " GZIP Decompression of object {} ({}) successful!".format(str(id), name)
                            print " New object created: {}".format(obj_num) + newLine
                        else:
                            CTCore.show_errors()
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
                if in_range(id):
                    response, size = CTCore.get_response_and_size(id, "all")
                    name = CTCore.get_name(id)
                    fp = StringIO.StringIO(response)
                    fp.write(response)
                    zfp = zipfile.ZipFile(fp, "r")
                    print " " + str(len(zfp.namelist())) + " Files found in zip object {} ({}):".format(str(id),name) + newLine

                    for cnt, fl in enumerate(zfp.namelist()):
                        print " [Z] " + str(cnt + 1) + " : " + fl
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
                response, size = CTCore.get_response_and_size(id, "all")
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
                if not CTCore.VT_APIKEY:
                    print newLine + "No Virus Total API key found, please enter your API key:",
                    CTCore.VT_APIKEY = raw_input()

                id = int(l[0])
                body, sz = CTCore.get_response_and_size(id, "all")
                name = CTCore.get_name(id)

                print " VirusTotal result for object {} ({}):".format(str(id),name) + newLine

                hash = hashlib.md5(StringIO.StringIO(body).getvalue()).hexdigest()
                vtdata = CTCore.send_to_vt(hash, CTCore.VT_APIKEY)
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
                body, sz = CTCore.get_response_and_size(id, "all")
                name = CTCore.get_name(id)

                print " Hashes of object {} ({}):".format(str(id),name) + newLine

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

    def do_peinfo(self, line):
        try:
            l = line.split(" ")
            if (l[0] == ""):
                self.help_peinfo()
            else:
                id, size = get_id_size(line)
                response, size = CTCore.get_response_and_size(id, "all")
                name = CTCore.get_name(id)

                print "Displaying PE info of object {} ({}) [{} bytes]:".format(id, name, size)
                if len(l) > 1 and l[1].lower() == "-p":
                    print "Checking for packers..."
                    pescan = PEScanner(response, '', peid_sigs="userdb.txt")
                else:
                    pescan = PEScanner(response, '', '')

                out = pescan.collect()
                print '\n'.join(out)
        except Exception,e:
            print str(e)

    def help_peinfo(self):
        print newLine + "Display PE info of the file"
        print newLine + "Usage: peinfo <obj_id> [-p]" + newLine
        print newLine + "OPTIONS:"
        print newLine + "-p     -   Check for packers"

    def do_find(self,line):
        try:
            l = line.split(" ")
            if len(l) < 2:
                self.help_find()
            else:
                pattern = " ".join(l[1:])
                if l[0].lower() == "all":
                    print "Searching '{}' in all objects:".format(pattern)
                    for i in range(0,len(CTCore.objects)):
                        response, size = CTCore.get_response_and_size(i, "all")
                        name = CTCore.get_name(i)

                        search_res = find_pattern(response, pattern)
                        if len(search_res) > 0:
                            print newLine + " {} [{}]:".format(name,str(i))
                            for res in search_res:
                                print "   " + res
                    print ""
                else:
                    id, size = get_id_size(line)
                    response, size = CTCore.get_response_and_size(id, "all")
                    name = CTCore.get_name(id)


                    print "Searching '{}' in object {} ({}):".format(pattern, id, name)
                    print ""

                    search_res = find_pattern(response, pattern)
                    if len(search_res) > 0:
                        for res in search_res:
                            print res
                    else:
                        print "     No Results found"
                    print ""
        except Exception,e:
            print str(e)

    def help_find(self):
        print newLine + "Search for a regular expression in all or specific object"
        print newLine + "Usage: find <obj_id / all> <pattern>" + newLine
        print newLine + "Output data is displayed as follows:"
        print newLine + "   ([Line number] , [Offset from begining of file]) : [Found string]" + newLine

    def do_slice(self,line):
        try:
            l = line.split(" ")
            if len(l) < 3:
                self.help_slice()
            else:
                id, size = get_id_size(line)
                response, size = CTCore.get_response_and_size(id, "all")
                name = CTCore.get_name(id)
                offset = int(l[1])
                length = l[2]
                bytes, length = get_bytes(response,offset,length)

                print "Displaying {} of bytes from offset {} in object {} ({}):".format(length, offset, id, name)
                print ""
                print bytes
                print ""
        except Exception,e:
            print str(e)

    def help_slice(self):
        print newLine + "Returns bytes from offset in given length"
        print newLine + "Usage: slice <obj_id> <offset> <len | 'eob'>" + newLine

    def do_req(self, line):
        try:
            l = line.split(" ")
            if (l[0] == ""):
                self.help_req()
            else:
                id, size = get_id_size(line)
                request, size = CTCore.get_request_size(id, "all")
                name = CTCore.get_name(id)
                print "Displaying request for object {} ({}) [{} bytes]:".format(id, name, size)
                CTCore.show_errors()
                print newLine + request
        except Exception,e:
            print str(e)

    def help_req(self):
        print newLine + "Prints full request of object"
        print newLine + "Usage: req <obj_id>"

    def do_jsbeautify(self,line):
        try:
            import jsbeautifier
            l = line.split(" ")
            if len(l) < 2:
                self.help_jsbeautify()
            else:
                OPTIONS = ['slice','obj']
                option = l[0]

                if option not in OPTIONS:
                    print "Invalid option"
                    return False

                id = l[1]
                response, size = CTCore.get_response_and_size(id, "all")
                name = CTCore.get_name(id)

                if option == "slice":
                    offset = int(l[2])
                    length = l[3]

                    bytes, length = get_bytes(response,offset,length)
                    js_bytes = bytes
                    res = jsbeautifier.beautify(js_bytes)
                    print res

                if option == "obj":
                    res = jsbeautifier.beautify(response)
                    obj_num = CTCore.add_object("jsbeautify",res,id=id)
                    print " JavaScript Beautify of object {} ({}) successful!".format(str(id), name)
                    print " New object created: {}".format(obj_num) + newLine

        except Exception,e:
            print str(e)

    def help_jsbeautify(self):
        print newLine + "Display JavaScript code after beautify"
        print newLine + "Usage: jsbeautify <obj_id> <offset> <len>" + newLine
        print newLine + "Example: jsbeautify slice <obj_id> <offset> <len | eob>"
        print newLine + "Example: jsbeautify obj <object_id>"

    def do_update(self, line):
        try:
            CTCore.update_captipper()
        except Exception, e:
            print str(e)

    def do_strings(self, line):
        try:
            l = line.split(" ")
            if (l[0] == ""):
                self.help_strings()
            else:
                id, size = get_id_size(line)
                response, size = CTCore.get_response_and_size(id, "all")
                name = CTCore.get_name(id)

                print "Strings found in object {} ({}) [{} bytes]:".format(id, name, size)
                strings = CTCore.get_strings(response)
                print (newLine.join(str for str in strings))
        except Exception,e:
            print str(e)


    def help_strings(self):
        print newLine + "Display strings found in object"
        print "usage: strings <obj_id>"

    def help_update(self):
        print newLine + "Update CapTipper to the newest version"
        print "usage: update"

    def do_clear(self, line):
        os.system('cls' if os.name == 'nt' else 'clear')

    def help_clear(self):
        print newLine + "Clears the screen"

    def do_about(self, line):
        print CTCore.ABOUT

    def help_about(self):
        print newLine + "Prints about information"

    def help_exit(self):
        print 'Exits from the console'
        print 'Usage: exit'