#!/usr/bin/env python

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

__author__ = 'Omri Herscovici'

import colorama
import sys
import time
import argparse
import parse_pcap

import CTCore
from CTConsole import console
from CTServer import server
from CTReport import Report

def main(args, pcap_file):
    if (args.update):
        CTCore.update_captipper()

    CTCore.pcap_file = pcap_file[0]
    print("[A] Analyzing PCAP: " + CTCore.pcap_file)

    start_ws = args.server_off # Boolean to start web server
    CTCore.PORT = args.port # Web server port
    CTCore.b_use_short_uri = args.short_url # Display short URI paths
    CTCore.b_auto_ungzip = args.ungzip

    if(args.report is not None):
        CTCore.b_auto_ungzip = True

    parse_pcap.run(CTCore.pcap_file)

    if not CTCore.conversations:
        sys.exit("No HTTP conversations were found in PCAP file")

    print(CTCore.newLine + "[+] Traffic Activity Time: "),
    try:
        print(CTCore.activity_date_time)
    except:
        print "Couldn't retrieve time"

    print("[+] Conversations Found:" + CTCore.newLine)
    CTCore.show_conversations()

    if (start_ws and args.dump is None and args.report is None):
        try:
            CTCore.web_server = server()
            CTCore.web_server.start()
            time.sleep(0.1) # Fixes graphic issues
            CTCore.web_server_turned_on = True
        except Exception,e:
            CTCore.alert_message("Error starting Web Server:", CTCore.msg_type.ERROR)

            if str(e).find("Errno 1004") > 0 or str(e).find("Errno 98") > 0:
                print " Port " + str(CTCore.PORT) + " is already taken."
                print " Change the port using 'CapTipper.py <pcap_file> -p <port=80>' or use '-s' to disable web server"
                print " Proceeding without starting the web server..." + CTCore.newLine
            else:
                print " " + str(e)

    # If chosen just to dump files and exit
    if (args.dump is not None):
        try:
            CTCore.ungzip_all()
            CTCore.dump_all_files(args.dump[0],True)
        except Exception, e:
            print e
    # If chosen to create a report
    elif (args.report is not None):
        report = Report(CTCore.hosts, CTCore.conversations, CTCore.VERSION + " b" + CTCore.BUILD)
        report.CreateReport(args.report[0])
    else:
        try:
            interpreter = console()
            interpreter.cmdloop()
        except:
            print (CTCore.newLine + 'Exiting CapTipper')
            if (CTCore.web_server_turned_on):
                CTCore.web_server.shutdown()

if __name__ == "__main__":
    try:
        print CTCore.ABOUT
        colorama.init()

        parser = argparse.ArgumentParser(usage=CTCore.USAGE, add_help=False)
        parser.add_argument("-h", "--help", action='help', help='Print this help message and exit')
        parser.add_argument('-p','--port', metavar='PORT', help='Set web server port', required=False, default=80, type=int)
        parser.add_argument('-d','--dump', nargs=1, metavar='FOLDER PATH', help='Dump all files and exit', required=False)
        parser.add_argument('-s','--server-off',action="store_false", help='Disable web server', required=False)
        parser.add_argument('-short','--short-url',action="store_true", help='Display shortened URI paths', required=False)
        parser.add_argument('-r','--report', nargs=1, metavar='FOLDER PATH', help='Create JSON & HTML report', required=False)
        parser.add_argument('-g','--ungzip',action="store_true", help='Automatically ungzip responses', required=False)
        parser.add_argument('-u','--update',action="store_true", help='Update CapTipper to newest version', required=False)

        args, pcap_file = parser.parse_known_args()

        if len(pcap_file) != 1 and not args.update:
            parser.print_help()
        else:
            main(args, pcap_file)

    except (KeyboardInterrupt, EOFError):
        print (CTCore.newLine + 'Exiting CapTipper')
    except Exception,e:
        print str(e)

