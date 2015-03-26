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

import SocketServer
from threading import Thread
import CTCore

class server(Thread):
    def __init__(self):
        super(server, self).__init__()
        self.srv = SocketServer.TCPServer((CTCore.HOST, CTCore.PORT), TCPHandler)

    def run(self):
        print CTCore.newLine + CTCore.colors.GREEN + "[+]" + CTCore.colors.END + " Started Web Server on http://" + CTCore.HOST + ":" + str(CTCore.PORT)
        print CTCore.colors.GREEN + "[+]" + CTCore.colors.END + " Listening to requests..." + CTCore.newLine
        self.srv.serve_forever()

    def shutdown(self):
        if (CTCore.web_server_turned_on):
            self.srv.shutdown()
            self.srv.server_close()
            print "WebServer Shutdown."
            CTCore.web_server_turned_on = False

class TCPHandler(SocketServer.BaseRequestHandler):

    def check_request(self, conv_req, get_uri):
        if (get_uri.lower() == conv_req.lower()):
            return True
        # ignore variables
        if (get_uri.find('?') > 0 and conv_req.find('?') > 0) and \
                (get_uri.lower()[:get_uri.find('?')] == conv_req.lower()[:conv_req.find('?')]):
            return True
        else:
            return False

    def get_clear_uri(self):
        try:
            get_request = self.data.splitlines()[0]
            import datetime
            now_s = datetime.datetime.now()
            CTCore.request_logs.append("[" + str(now_s.isoformat()) + "] " + self.client_address[0] + " : " + get_request)

            get_start = get_request.find(' ') + 1
            get_end = get_request.rfind(' ')
            loop_start = get_start + 1
            for i in range(loop_start, get_end):
                if get_request[i] == '/':
                    get_start += 1
                else:
                    break
            get_uri = get_request[get_start:get_end]
            return get_uri
        except Exception,e:
            print "[-] Error parsing data: " + self.data + ":" + str(e)

    def handle(self):
        self.data = self.request.recv(1024).strip()

        if (self.data != ""):
            get_uri = self.get_clear_uri()

            for conv in CTCore.conversations:
                if (self.check_request(conv.uri, get_uri) == True):
                    resp = conv.res_head
                    if conv.orig_chunked_resp != "":
                        resp = resp + "\r\n\r\n" + conv.orig_chunked_resp
                    else:
                        resp = resp + "\r\n\r\n"
                        if conv.orig_resp:
                            resp += conv.orig_resp

                    self.request.send(resp)
                    break