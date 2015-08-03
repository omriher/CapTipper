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

#	This file belongs to the CuckooSploit project

import sys
import time
import os
import logging
import subprocess
import shlex
import re
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "lib", "captipper"))

import parse_pcap
import colorama

import CTCore
from CTConsole import console
from CTServer import server
from CTReport import Report

from subprocess import Popen, PIPE, STDOUT
from lib.common.results import NetlogFile
from lib.common.abstracts import Package
log = logging.getLogger(__name__)

class Pcap(Package):
    """Pcap analysis package."""
    PATHS = [
        ("ProgramFiles", "Internet Explorer", "iexplore.exe"),
    ]
    
    HOSTS_PATHS = [
        ("SystemRoot", "System32", "drivers", "etc", "hosts"),
    ]
    
    TSHARK_PATHS = [
        ("ProgramFiles", "Wireshark", "tshark.exe"),
    ]
    
    hosts_path = "C:\\Windows\\System32\\drivers\\etc\\hosts"
      

    def start(self, path):
        self.tshark_proc = None
        self.tshark_filename = "tshark.pcap"
        log.debug("In pcap analysis package")
        log.debug("path is "+ path)
        # set default options
        args = {}
        #args["server_off"] = self.options["server_off"] if self.options["server_off"] else False
        args["port"] = 80 #self.options["port"] if self.options["port"] else 80
        args["short_url"] = True #self.options["short_url"] if self.options["short_url"] else True
        args["ungzip"] = True #self.options["ungzip"] if self.options["ungzip"] else True
        #args.report = self.options["report"] if self.options["report"] else 
        
        CTCore.pcap_file = path
        
        log.info("[A] Analyzing PCAP: " + CTCore.pcap_file)

        #start_ws = args["server_off"] # Boolean to start web server
        CTCore.PORT = args["port"] # Web server port
        CTCore.b_use_short_uri = args["short_url"] # Display short URI paths
        CTCore.b_auto_ungzip = args["ungzip"]
        
        #if(args.report is not None):
        #    CTCore.b_auto_ungzip = True
        
        parse_pcap.run(CTCore.pcap_file)

        if not CTCore.conversations:
            log.info("No HTTP conversations were found in PCAP file")
            return
        log.info(CTCore.newLine + "[+] Traffic Activity Time: "),
        try:
            log.info(CTCore.activity_date_time)
        except:
            log.error("Couldn't retrieve time")

        #Update hosts file with all hosts found in pcap
        #add each ip directly accessed in pcap to loopback network card
        ip_pattern = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        host_domains = CTCore.hosts.keys()
        if host_domains:
            #self.PATHS = Pcap.HOSTS_PATHS
            with open(self.hosts_path, "a+") as hosts_file:
                for host, ip in host_domains:
                    ip = ip.split(":")[0] #remove the port from the ip address
                    netsh_cmd = "netsh interface ip add address \"Local Area Connection 2\" {0} 255.255.255.255".format(ip)
                    proc = Popen(shlex.split(netsh_cmd), stdout=PIPE, stderr=STDOUT)
                    output, err = proc.communicate()
                    if err:
                        log.error(err)
                    host = host.split(":")[0] #remove port from host if it exists
                    host_is_ip = re.match(ip_pattern, host, re.M)
                    if not host_is_ip:
                        hosts_file.write("\n\n127.0.0.1 {0}".format(host))
                
        try:
            CTCore.web_server = server()
            CTCore.web_server.start()
            time.sleep(0.1) # Fixes graphic issues
            CTCore.web_server_turned_on = True
            
            id = 0
            request = CTCore.conversations[id].uri
            host = CTCore.conversations[id].host
            open_url = 'http://127.0.0.1:' + str(CTCore.PORT) + "/" + host + request
            
            #open_url = 'http://' + CTCore.HOST + ":" + str(CTCore.PORT) + request

            #Pcap.PATHS = Pcap.IE_PATHS
            iexplore = self.get_path("Internet Explorer")
            log.info("iexplore: "+iexplore)
            log.info("url: "+open_url)
            return self.execute(iexplore, args=["%s" % open_url])
        except Exception,e:
            log.error("Error starting Web Server: %s", str(CTCore.msg_type.ERROR))

            if str(e).find("Errno 1004") > 0 or str(e).find("Errno 98") > 0:
                log.error(" Port " + str(CTCore.PORT) + " is already taken.")
                log.error(" Change the port using 'CapTipper.py <pcap_file> -p <port=80>' or use '-s' to disable web server")
                log.error(" Proceeding without starting the web server..." + CTCore.newLine)
            else:
                log.error(str(e))
        
    def finish(self):
        return super(Pcap, self).finish()
