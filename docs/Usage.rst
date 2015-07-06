=======
Usage
=======

CapTipper was written in Python, there for it is multi-platform and was
tested on Windows, Linux & Mac. The Python version needed must be 2.7.
CapTipper doesn't require any installation, and every pre-requisits it
might need is bundled into its project folder.

The most basic usage of CapTipper is simply providing a PCAP file to it:

.. code:: sh

    ./CapTipper.py <PCAP_file> 

It can also accept command line arguments:

--dump FOLDERPATH Automatically dump all files from the PCAP. This was
mainly made for people using Cuckoo Sandbox that want to fetch the HTML
files created along with other new files.

I have taken the liberty to write a basic Cuckoo processing module that
dumps all files from the PCAP and outputs to the Cuckoo log if an EXE
file was found. It can be found here: CapTipper Cuckoo processing module

--ungzip Automatically ungzip all objects, no need to manually ungzip
each object anymore. The generated web-server still responds with the
original response in case it was gzipped.

--port set a differnet port for webserver

--short-url On some cases the URI paths were very long, making the
console view a bit more difficult to inspect. This feature displays the
URI paths in a shortened convenient version.

--report FOLDERPATH This is a new and exciting feature for creating HTML
& JSON reports. The command will produce both .html and .json files in a
given folder. I will elaborate more on this in the following section.

--update Update CapTipper to the current version available on GitHub.

Console
=======

The Initialization of CapTipper outputs the conversations found between
the client and the server in the following format:

[ID] : REQUEST URI -> SERVER RESPONSE TYPE (FILENAME) [SIZE IN BYTES]
(Magic: $Whatype)

ID: An assigned Id to the specific conversation REQUEST URI: The URI
that was sent to the server in the GET request SERVER RESPONSE TYPE: The
content-type returned in the server response header FILENAME: The
filename can be a few things: 1) Filename attribute given in the
response header 2) Derived from the URI 3) Assigned by CapTipper if
couldn't find any of the above SIZE IN BYTES: Response body size MAGIC:
The file format as identifiy by the Whatype library

After Initalization, 2 things occur: 1. CapTipper creates a pseudo-web
server that behaves like the web server in the pcap 2. An Interpreter is
launched

The interpreter contains internal tools for further investigation of the
objects in the pcap. Opening a URI in the browser is simply by typing
'open' along with the object id

For more information on the WebServer please see

The commands available in CapTipper console:

convs
=====

convs will display all conversation in the form they were displayed when
CapTipper was launched

Hosts
=====

The Hosts commands allows us to take a bird-eye-view on the hosts and
URIs involved in the traffic. The output is in the form of:

::

    www.magmedia.com.au
     ├-- / [0]
     ├-- /wp-includes/js/jquery/jquery.js?ver=1.7.2 [1]

head
====

Head gets the Conversation id as an argument It outputs the Response
header

body
====

body gets the conversation id as an argument It outputs the Response
body "body" can also accept a second argument which indicates the amount
of bytes from the response body to be displayed. it can also accept
"all" as the second argument, which will return the entire body

req
===

body gets the Conversation id as an argument It outputs the request
header

info
====

SERVER IP : 108.61.196.84:80 HOST : pixeltouchstudios.tk URI :
/seedadmin17.html REFERER : http://www.magmedia.com.au/ RESULT NUM : 302
Found RESULT TYPE : text/html FILE NAME : seedadmin17.html LENGTH : 354
B

ungzip
======

ungzip gets the conversation id as an argument it creates a new object
with the ungzipped form of the object the new object created can be seen
using the "objects" commands

iframes
=======

iframes gets the conversation id as an argument

client
======

Display all data collected on the client seen in the PCAP

dump
====

Dumps the object file to the file system. It can also dump all the
objects found in the PCAP, and can refrain from dumping executables by
using the '-e' argument

Usage: dump <-e>

Example: dump 4 c:.html Dumps object 4 to given path

Example: dump all c:Dumps all files to folder by their found name

Example: dump all c:-e Dumps all files to folder by their found name,
without EXE files

find
====

Search for a regular expression in all or a specific object

Usage: find

Output data is displayed as follows:

([Line number] , [Offset from begining of file]) : [Found string]
