Home
-=-=-=-=
Written by Omri Herscovici
http://omriher.com
@omriher

Dependencies
-=-=-=-=-=-=-=-
No libraries needed for download

Python 2.7.x Only

Included Modules: 
pcap_parser - https://github.com/xiaxiaocao/pcap-parser (Dong Liu)
colorama - https://pypi.python.org/pypi/colorama (Jonathan Hartley)
pescanner - https://code.google.com/p/malwarecookbook/source/browse/trunk/3/8/pescanner.py (Michael Ligh)
pefile / peutil - https://code.google.com/p/pefile/ (Ero Carrera)
jsbeautify - http://jsbeautifier.org/ (Einar Lielmanis)
(Thanks to all the developers !!)


Installation
-=-=-=-=-=-
No Installation needed


Execution
-=-=-=-=-=-=-=
Basic usage: ./CapTipper.py <pcap_file> [-p] [web_server_port=80]

License
-=-=-=-=
GPLv3

Hints
-=-=-=
- open
     Opens the URI in browser

- hosts
     Displays URI's per host

- convs
     Displays the found conversations

- body <obj> [size=256]
     Shows body of object

- head <obj> [size=256]
     Shows head of object

- hexdump <obj> [size=256]
     Shows Hex of object

- dump <obj> <path>
     Dumps the file to given location

- peinfo <obj> [-p]
     Display PE info of the file

- find <obj / all> <regex expression>
    Search for a regular expression in all or specific object

- More...
> help

Bugs
-=-=-=
Please send me bugs and feedback :)
via mail omriher@gmail.com

Thanks!
