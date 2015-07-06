====
Core
====

At initialization of CapTipper,
The PCAP file is being parsed by the pcap_parser.py library which was originally written by ... and was further modified to suit with the CapTipper.

There are three main datasets handled in CapTipper Core:
Conversations
Objects
Hosts

Conversations
===============
The parsing poplulates a data structure called CTCore.Conversations.
A 'Conversation' is defined as Request and a Response.
Conversations is a list of named tuples, each named tuple consists of the following values:
id - Conversation ID
server_ip_port - Server ip and port in the form of IP:PORT
uri - Relative object on the host (e.g "/images/cat.jpg")
req - Raw Request data
res_body - Response raw body
res_head - Response Header
res_num - HTTP response number (e.g "200 OK")
res_type - HTTP response type (e.g "application/octet-stream")
host - Server Host name
referer - Referer URL
filename - Response object name (e.g "cat.jpg")
method - Rquest method (GET/POST/etc..)
redirect_to -
req_microsec - Request microsec time
res_len - Response size
magic_name - Filetype as identified by Whatype (e.g "Windows executable file")
magic_ext - Filetype extension as identified by Whatype (e.g "EXE")

 ['id','server_ip','uri','req','res_body','res_head','res_num','res_type','host','referer', 'filename','method','redirect_to','req_microsec', 'res_len','magic_name', 'magic_ext']))

A conversation is added to the list during the parsing process upon parsing the response packet.

the function responsible for adding the conversation is finish_conversations(self) in CTCore.py.
as part of the function, a refernce to the Whatype library (Read more) is called.

A conversation may sometimes be refered as object, while object is meant to describe only the response.
The file name set for each conversation is created with this priority:
1. Filename given to the object from the server with "Content Disposition: filename=<file>"
2. The last part of the URI, diregarding arguments.
3. Number of object + ".html"

Objects
=========
Object is a much thinner representation of the Conversations dataset, and contains only the following information:

type 
value
conv_id
name

all conversations are stored in objects list with the 'type' of 'body'
'value' contains the response body of each conversation
'conv_id' is as reference for objects that were created from conversations (e.g ungzip)
'name' will be the filename that was given to the conversation, except for the dynamically created objects, 
for example in case of ungzip, the name will be "ungzip-[filename]"

Hosts
=========
The hosts data set is a dictionary with the key beind a tuple of (host, ip) and the value for each key is a live of the URIs.
for example:
[(google.com, )]

The conversations list
=================
- Colors

Update
============
The update process check for a version difference between the local project to the github repository.
In case such a difference exists, it downloads the master branch and expands it to the local path and overwrites current .py files.

Send To VirusTotal
=====================

