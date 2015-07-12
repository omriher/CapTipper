Welcome to CapTipper's documentation!
=====================================

**Documentation is under construction**

What is CapTipper?
------------------

CapTipper_ is a python tool to analyze, explore and revive HTTP malicious traffic.
CapTipper sets up a web server that acts exactly as the server in the PCAP file,
and contains internal tools, with a powerful interactive console, for analysis and inspection of the hosts, objects and conversations found.

The tool provides the security researcher with easy access to the files and the understanding of the network flow,
and is useful when trying to research exploits, pre-conditions, versions, obfuscations, plugins and shellcodes.

Feeding CapTipper with a drive-by traffic capture (e.g of an exploit kit) displays the user with the requests URI's that were sent and responses meta-data.
The user can at this point browse to http://127.0.0.1/[URI] and receive the response back to the browser.
In addition, an interactive shell is launched for deeper investigation using various commands such as: hosts, hexdump, info, ungzip, body, client, dump and more...

CapTipper is released under the GPLv3_ license and is copyrighted by `Omri Herscovici`_.
The source code is available on `GitHub`__.

Contents:

.. toctree::
   :maxdepth: 2

   Usage
   Core
   Plugins
   Reporting
   Webserver

.. _CapTipper: https://github.com/omriher/CapTipper
__ CapTipper_
.. _GPLv3: http://www.gnu.org/licenses/gpl-3.0.en.html
.. _Omri Herscovici: https://twitter.com/omriher