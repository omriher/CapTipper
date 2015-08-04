====
Core
====

CapTipper is using a modified version of the pcap_parser library in order to parse the PCAP file.
The CapTipper Core class implements most of the functions executed by the CapTipper console and is in charge of creating and storing all of the PCAP information.
There are three main datasets handled by CapTippers core:

* Conversations
* Objects
* Hosts

Conversations
===============
As part of the PCAP parsing process, a data structure ``CTCore.Conversations`` is being populated.
A 'Conversation' is defined as Request and a Response.
Conversations is a list of named tuples, each tuple consists of the following values:

* id - Conversation ID
* server_ip_port - Server ip and port in the form of IP:PORT
* uri - Relative object on the host (e.g "/images/cat.jpg")
* req - Raw Request data
* res_body - Response raw body
* res_head - Response Header
* res_num - HTTP response number (e.g "200 OK")
* res_type - HTTP response type (e.g "application/octet-stream")
* host - Server Host name
* referer - Request referrer URL
* filename - Response object name (e.g "cat.jpg")
* method - Rquest method (GET/POST/etc..)
* redirect_to - The URL will be redirected to in case the ``location`` response header exists
* req_microsec - Request microsec time
* res_len - Response size
* magic_name - File type as identified by Whatype (e.g "Windows executable file")
* magic_ext - File type extension as identified by Whatype (e.g "EXE")

A conversation is added to the list during the parsing process upon parsing the response packet.

The function responsible for adding the conversation is ``finish_conversations(self)`` in CTCore.py.
As part of the function, a reference to the :doc:`Whatype` library is called for file type identification.

The file name set for each conversation is created by this order:

 1. Filename given to the object from the server with "Content Disposition: filename=<file>"
 2. The final part of the URI (ignoring arguments)
 3. Number of object + ".html"

When requesting to display the conversation using the command ``convs``,
a unique color is given to different conversations based on the type received in the responses ``content_type``:

- RED - PDF Files
- BLUE - JavaScript Files
- GREEN - Images
- YELLOW - Generic binary files


Objects
=========
Object is a much thinner representation of the conversations dataset, and contains only the following information:

* id - Object ID
* type - Object type  [body / ungzip / jsbeautify] (default: 'body')
* value - Object content
* conv_id - Associated conversation id (alias: CID)
* name - File name

All initial conversations are stored in the objects list with the string 'body' as ``type`` and ``value`` containing the the response data.
``id`` is unique to each object and objects that are also conversations have the same id.
``conv_id`` is a reference for objects that were created from conversations (e.g ungzip).
``name`` will be the filename that was given to the conversation;
dynamically created objects will have a prefix of how they were created,
for example in case of ungzip, the name will be "ungzip-[filename]"

Objects list example (using the command ``objects``):

::

    ID   CID     TYPE          NAME
    ---- -----  -----------   --------
      0 | 0   | body        | 0.html
      1 | 1   | body        | jquery.js
      2 | 2   | body        | logo.jpg
      3 | 3   | body        | kitty.png
      4 | 0   | ungzip      | ungzip-0.html

Hosts
=========
The hosts data set is a dictionary with the key being a tuple of (host, ip) and the value for each key is a list of the domains URIs.

for example:
::

     (
        ('www.example.com','93.184.216.34:80'),
          ['/   [0]',
          '/js/jquery.js?ver=1.7.3   [2]',
          '/images/logo.jpg   [4]',
          '/images/kitty.png   [5]']
     )


Update
=======
The update process checks for a version difference between the local project to the github repository.
In case such a difference exists, it downloads the master branch and expands it to the local path and overwrites current .py files.

