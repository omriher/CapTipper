import socket

from CTPlugin import ConsolePlugin

class check_host(ConsolePlugin):

    description = "Checks if a given id's host is alive"
    author = "omriher"

    def run(self, args):
        if len(args) > 0:
            # Gets the conversation ID
            id = int(args[0])

            # Check if id number is a valid conversation
            if self.is_valid_id(id):

                # Get necessary information
                host = self.conversations[id].host
                ip, port = self.conversations[id].server_ip_port.split(":")

                # Logging
                print "Checking host {}".format(host)
                print "IP:PORT = {}:{}".format(ip,port)

                # Establishing connection
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.connect((ip, int(port)))
                    result = "[+] Server is alive !"
                except:
                    result = "[-] Server is dead"
                s.close()

                return result
            else:
                print "Invalid conversation ID {}".format(str(id))
        else:
            return "No arguments given"
