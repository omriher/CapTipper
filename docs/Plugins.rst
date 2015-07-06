=======
Plugins
=======

CapTipper supports external plugins for easy use through the CapTipper
console.

Getting Started
===============

All plugin modules must be placed inside the directory plugins/ The
modules are loaded by CapTipper dynamically when launched. The

Plugins are python modules who implements the ConsolePlugin interface. A
CapTipper plugin must import the ConsolePlugin class and inherint it.

The run() function is the EntryPoint CapTipper will use to launch the
plugin. Also, The class implementing the ConsolePlugin must have the
same name as the py file.

Basic example:

my\_first\_plugin.py

.. code-block:: python

    from CTPlugin import ConsolePlugin

    class my_first_plugin(ConsolePlugin):
        
        author = "Omri Herscovici"
        description = "Prints Hello World"

        def run(self, args):
            print "Hello World"

The plugin result can be printed through the plugin using "print", or
returned from the RUN function; if run() result is different than None,
the information will be printed to the screen.

Global Structurs
================

CapTipper hold 3 main Data Structures conainting all information. 1.
Conversations 2. Objects 3. Hosts

All of which, are accessible from the plugin class using


.. code-block:: python

    self.conversations
    self.objects
    self.hosts

Internal Functions
==================

The ConsolePlugin interface contains some function for more convient
use: get\_name\_by\_id - Returns response object name (e.g "index.html")
of a given conversation id get\_body\_by\_id - Returns the raw response
body of a given convesation get\_plaintext\_body\_by\_id - Returns
plaintext response body (e.g ungzipped in case needed) is\_valid\_id -
Checks if id sent to the plugin is a valid one

It is easy to import other function from the CapTipper Core.

For example:

.. code-block:: python

    from CTPlugin import ConsolePlugin
    from CTCore import ungzip

    class print_body(ConsolePlugin):

        description = "Prints the body of a conversation and ungzip if needed"
        author = "omriher"

        def run(self, args):
            id = int(args[0])
            if self.is_valid_id(id):
                if id < len(self.conversations) and self.conversations[id].magic_ext == "GZ":
                    data, name = ungzip(id) # Ungzip imported from CTCore
                else:
                    data = self.get_body_by_id(id)
            else:
                print "invalid id"

You can also see here the use of the conversations internal variable
"magic\_ext" Best practice for ungzip would be to use the
get\_plaintext\_body\_by\_id() Function.

Example #1
==========

The following plugin imports the srcHTMLParser from CTCore, and searches
external javascript referenced in a given conversation

.. code-block:: python

    from CTPlugin import ConsolePlugin
    from CTCore import srcHTMLParser

    class find_scripts(ConsolePlugin):

        description = "Finds external scripts included in the object body"
        author = "omriher"

        def run(self, args):
            if len(args) > 0:
                # Get the conversation ID
                id = int(args[0])
                if self.is_valid_id(id):
                    name = self.get_name_by_id(id)
                    print "[.] Searching for external scripts in object {} ({})...".format(str(id),name)

                    # Get response body as text even in case it was Gzipped
                    response_body = self.get_plaintext_body_by_id(id)

                    # Create Parser instance and search for <script src="...
                    parser = srcHTMLParser("script")
                    parser.feed(response_body)
                    parser.print_objects()
                else:
                    print "Invalid conversation ID {}".format(str(id))
            else:
                return "No arguments given"

Example #2
==========

The following plugin checks if the host involved in a given conversation
is still connectable using the stored IP and Port

.. code-block:: python

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
