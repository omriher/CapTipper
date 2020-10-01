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

import socketserver
import traceback
from http.server import BaseHTTPRequestHandler
from io import StringIO, BytesIO
import datetime
from urllib.parse import urlparse
from threading import Thread
import CTCore

class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

class server(Thread):
    def __init__(self):
        super(server, self).__init__()
        self.srv = socketserver.ThreadingTCPServer((CTCore.HOST, CTCore.PORT), TCPHandler)

    def run(self):
        print(CTCore.newLine + CTCore.colors.GREEN + "[+]" + CTCore.colors.END + " Started Web Server on http://" + CTCore.HOST + ":" + str(CTCore.PORT))
        print(CTCore.colors.GREEN + "[+]" + CTCore.colors.END + " Listening to requests..." + CTCore.newLine)
        self.srv.serve_forever()

    def shutdown(self):
        if (CTCore.web_server_turned_on):
            self.srv.shutdown()
            self.srv.server_close()
            print("WebServer Shutdown.")
            CTCore.web_server_turned_on = False

class TCPHandler(socketserver.BaseRequestHandler):

    def build_index(self):
        index_page = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
                        <html>
                         <head>
                            <title>Index of CapTipper Server</title>
                         </head>
                        <body>
                        <h1>Index of CapTipper Server</h1>
                        <hr>"""

        for host, ip in list(CTCore.hosts.keys()):
            index_page += " " + host.decode('cp437', 'ignore') + " ({})<br>".format(ip)
            hostkey = (host, ip)
            for host_uri,obj_num in CTCore.hosts[hostkey]:
                #chr_num = 195 # Extended ASCII tree symbol
                chr_num = 9500  # UNICODE tree symbol

                # Checks if last one
                if (host_uri == CTCore.hosts[hostkey][len(CTCore.hosts[hostkey]) - 1]):
                    #chr_num = 192 # Extended ASCII tree symbol
                    chr_num = 9492 # UNICODE tree symbol


                index_page += " " + "-- <a href='/{}".format(host.decode('cp437', 'ignore')) + host_uri.decode('cp437', 'ignore') \
                              + "'>{}</a><br>\r\n".format(host_uri.decode('cp437', 'ignore') + "     [{}]".format(obj_num))
            index_page += "<br>\r\n"

        index_page += "</body></html>"
        return index_page

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
        except Exception as e:
            print("[-] Error parsing data: " + self.data + ":" + str(e))

    def get_domain_folder(self, get_uri):
        folder = get_uri.split("/")[1]
        return folder

    def log(self, uri):
        now_s = datetime.datetime.now()
        CTCore.request_logs.append("[" + str(now_s.isoformat()) + "] " + self.client_address[0] + " : " + uri)

    def handle(self):
        try:
            self.data = self.request.recv(1024).strip()
            request = HTTPRequest(self.data)

            if self.data != "":
                host_folder = self.get_domain_folder(request.path)

                using_host_folder = False
                using_host_header = False
                for chost,ip_port in list(CTCore.hosts.keys()):
                    if chost.decode().lower() == host_folder.lower():
                        req_host = chost
                        using_host_folder = True
                        break

                if not using_host_folder:
                    req_host = request.headers['host']

                    #check if host header is in domains list
                    for chost, ip_port in list(CTCore.hosts.keys()):
                        if chost.lower() == req_host.lower():
                            req_host = chost
                            using_host_header = True
                            break

                    if not using_host_header:
                        if req_host.split(":")[0] == "127.0.0.1":
                            localhost = "http://127.0.0.1/"
                            try:
                                # set req_host to be referer
                                if request.headers['referer'] is None:
                                    referrer = ""
                                else:
                                    referrer = request.headers['referer']
                                # if referer isn't 127.0.0.1
                                if referrer.find(localhost) == 0:
                                    end_of_host = referrer.find("/",len(localhost) + 1)
                                    req_host = referrer[len(localhost):end_of_host]
                            except Exception as e:
                                print(e)
                                traceback.print_exc()

                            # set req_host to be the last request
                            if (len(CTCore.request_logs) > 0) and (request.path.find(req_host) == 1 or req_host.split(":")[0] == "127.0.0.1"):
                                last_req = CTCore.request_logs[-1]
                                last_url = last_req[last_req.find(' : ') + 3:]
                                last_req_parsed = urlparse("http://" + last_url)
                                req_host = last_req_parsed.netloc
                        else:
                            try:
                                # 'try' for the case no referer exists ("/")
                                referrer = request.headers['referer']
                                start_of_uri = referrer.find("/", len("http://") + 1)
                                if (start_of_uri > 0):
                                    end_of_host = referrer.find("/", start_of_uri + 1)
                                    req_host = referrer[start_of_uri + 1:end_of_host]
                            except:
                                pass

                    get_uri = request.path
                else:
                    get_uri = '/' + '/'.join(request.path.split('/')[2:])

                try:
                    req_sent = False
                    for conv in CTCore.conversations:
                        if conv.host == req_host:
                            conv_uri = conv.uri
                            if not isinstance(conv_uri, str):
                                conv_uri = conv_uri.decode("utf-8", "ignore")

                            if (self.check_request(conv_uri, get_uri) == True):
                                resp = conv.res_head
                                if not isinstance(resp, str):
                                    resp = resp.decode("utf-8", "ignore")

                                resp = resp.encode()

                                if conv.orig_chunked_resp != "":
                                    resp = resp + b"\r\n\r\n" + conv.orig_chunked_resp
                                else:
                                    resp = resp + b"\r\n\r\n"
                                    if conv.orig_resp:
                                        original_resp = conv.orig_resp
                                        #if not isinstance(original_resp, str):
                                        #    original_resp = original_resp.decode("utf-8", "ignore")
                                        resp += original_resp

                                self.request.send(resp)
                                req_sent = True
                                res = conv.res_num
                                break

                    if not req_sent:
                        if get_uri == "/":
                            dir_response = b"HTTP/1.1 200 OK\r\n\r\n" + self.build_index().encode()
                            self.request.send(dir_response)
                            res = "200 OK [Main Dir]"
                        else:
                            self.request.send("HTTP/1.1 404 Not Found")
                            res = "404 Not Found"
                except Exception as e:
                    res = str(e)
                finally:
                    if not isinstance(req_host, str):
                     req_host = req_host.decode("cp437", "ignore")
                    if not isinstance(get_uri, str):
                     get_uri = get_uri.decode("cp437", "ignore")
                    if not isinstance(res, str):
                     res = res.decode("cp437", "ignore")
                    self.log(req_host + get_uri + " - " + res)
        except Exception as e:
            print(e)
            traceback.print_exc()
            
