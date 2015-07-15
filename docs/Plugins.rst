=======
Plugins
=======

CapTipper is also a framework who supports plugins as extensions for the console.
If you have an idea for a plugin, you should implement it and send it to me or make a PULL request to the GitHub repository.

Getting Started
===============

All plugin modules must be placed inside the ``plugins/`` directory.
The modules are loaded by CapTipper automatically when launched.

A CapTipper plugin must import the ``ConsolePlugin`` interface from ``CTPlugin``, inherent and implement it.
The class implementing the ``ConsolePlugin`` must have the same name as the ``.py`` file.

The ``run(self, args)`` function is the entry point CapTipper will use to launch the plugin.

Hello World example (``my_first_plugin.py``):

.. code-block:: python

    from CTPlugin import ConsolePlugin

    class my_first_plugin(ConsolePlugin):
        
        author = "Omri Herscovici"
        description = "Prints Hello World"

        def run(self, args):
            print "Hello World"

The plugin result can be printed out using the command ``print``, or returned from the ``run`` function.

Global Structurs
================

CapTipper hold 3 main data structures containing all information:

1. Conversations
2. Objects
3. Hosts

- See :doc:`Core` chapter for more information about the data sets.

All of which, are accessible from the plugin class using:

.. code-block:: python

    self.conversations
    self.objects
    self.hosts

Internal Functions
==================

The ``ConsolePlugin`` interface contains important function that should be used when accessing relevant information:

* ``get_name_by_id(obj_id)`` - Returns response object name (e.g "index.html") of a given conversation id
* ``get_body_by_id(obj_id)`` - Returns the raw response body of a given convesation
* ``get_plaintext_body_by_id(obj_id)`` - Returns plaintext response body (e.g ungzipped in case needed)
* ``is_valid_id(obj_id)`` - Checks if id sent to the plugin is a valid one

It is also easy to import other function from the CapTipper Core.

Let's take a look at an example importing the ``ungzip`` function from ``CTCore``:

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

You can also see the use of the conversation internal variable ``magic_ext``.

The best practice for getting the conversation body is by using the
``get_plaintext_body_by_id()`` function which will also ungzip the data if necessary.

Example #1
==========

The following plugin imports the srcHTMLParser from CTCore, and searches external javascript referenced in a given conversation

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

                # Checks if id is value
                if self.is_valid_id(id):

                    # Gets conversation name
                    name = self.get_name_by_id(id)
                    print "[.] Searching for external scripts in object {} ({})...".format(str(id),name)

                    # Get response body as text even in case it was Gzipped
                    response_body = self.get_plaintext_body_by_id(id)

                    # Create Parser instance and search for <script src="...
                    parser = srcHTMLParser("script")
                    parser.feed(response_body)

                    # Prints results
                    parser.print_objects()
                else:
                    print "Invalid conversation ID {}".format(str(id))
            else:
                return "No arguments given"

Example #2
==========

The following plugin checks if the host involved in a given conversation is still alive, using a socket object and the conversations stored IP and Port.

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
