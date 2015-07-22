=========
Webserver
=========

CapTipper launches a local pseudo-webserver listening on all interfaces (``0.0.0.0``) and behaves exactly like the web server(s) involved in the PCAP file.

The server is not a real web server and doesnt use any python webserver libraries.
Instead, it uses the SocketServer library and the request parsing and responses are made using raw socket.

The reason for that, is because I didn't want the files included in the PCAP to be stored on the file system
in order to avoid from endangering the researchers machine in case the tool is used on a working station.
In this way, there is also no concern for any AntiViruses to pop up while messing with the files since they are only
stored in CapTippers memory datasets (Described in :doc:`Core`).

The default webserver configurations can be found in ``CTCore.py`` in the following variables:

::

    HOST = "0.0.0.0"
    PORT = 80

The port can be changed using the ``-p`` argument when launching CapTipper.

In case the webserver could not have been launched due to any reason (Port in use, Permission denied, etc...),
an error will be displayed and the console will be prompted normally.

Every request to the webserver is logged to ``CTCore.request_logs`` list object and is viewable at any time using the command ``log`` from CapTippers console.

The structure of each conversation url is as such:

.. code:: python

    http://<captipper_server>/<host>/<uri>

for example:


.. code:: python

    http://localhost/example.com/index.html

