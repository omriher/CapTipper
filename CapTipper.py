#!/usr/bin/env python

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

import colorama
import sys
import time
import parse_pcap

import CTCore
from CTConsole import console
from CTServer import server

def main(args):
    file_path = args[1]
    print("[A] Analyzing PCAP: " + args[1])

    parse_pcap.run(file_path)

    print(CTCore.newLine + "[+] Traffic Activity Time: " + CTCore.activity_date_time.strftime('%a, %x %X'))
    print("[+] Conversations Found:" + CTCore.newLine)
    CTCore.show_conversations()

    start_ws = True
    if (len(args) > 2):
        if args[2].lower() == "-s":
            start_ws = False
        else:
            CTCore.PORT = int(args[2])

    if (start_ws):
        try:
            CTCore.web_server = server()
            CTCore.web_server.start()
            time.sleep(0.1) # Fixes graphic issues
            CTCore.web_server_turned_on = True
        except Exception,e:
            print "[E] Error starting Web Service:"
            if str(e).find("Errno 1004") > 0 or str(e).find("Errno 98") > 0:
                print " Port " + str(CTCore.PORT) + " is already Taken."
                print " Change the port using 'CapTipper.py <pcap_file> [port=80]' or use '-s' to disable web server"
                print " Proceeding without starting the web server..." + CTCore.newLine
            else:
                print " " + str(e)

    try:
        interpreter = console()
        interpreter.cmdloop()
    except:
        print (CTCore.newLine + 'Exiting CapTipper')
        if (CTCore.web_server_turned_on):
            CTCore.web_server.shutdown()

if __name__ == "__main__":
    try:
        print("CapTipper v" + CTCore.VERSION + " - Malicious HTTP traffic explorer tool")
        print("Copyright 2015 Omri Herscovici <omriher@gmail.com>\n")

        colorama.init()
        if (len(sys.argv) > 1):
            main(sys.argv)
        else:
            print("Usage: CapTipper.py <pcap_file> [web_server_port=80]")
            print("       CapTipper.py ExploitKit.pcap      -     explore and start server on port 80")
            print("       CapTipper.py ExploitKit.pcap 1234 -     explore and start server on port 1234")
            print("       CapTipper.py ExploitKit.pcap -s   -     explore without web server")
    except (KeyboardInterrupt, EOFError):
        print (CTCore.newLine + 'Exiting CapTipper')
    except Exception,e:

        print str(e)

