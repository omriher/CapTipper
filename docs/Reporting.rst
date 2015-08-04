==========
Reporting
==========

CapTipper supports producing HTML reports for convenient view and sharing,
and JSON report for post-analysis information gathering by a third party.

An example HTML report of the Nuclear Exploit Kit PCAP we analyzed in the `first blog post`_, can be found here: `CapTipper HTML Nuclear Report`_.
The HTML report includes full flow details, client information, interesting binary data and more…

The report is expected to expand and include more information along with the development of CapTippers new abilities.

JSON report
-----------
The JSON file is made of 4 main parts:

* Browsing Flow
* PCAP Metadata
* Client information
* Conversations

**Browsing Flow** contains every redirection made to each page or file, this is later displayed visually in the HTML report.
It is saved under the key ``flow``:

::

    "flow": {
            "hosts": {
                "name": "Client", // First Node
                "children": [
                    {
                        // Recursive structure of "name" and "children"
                        ...
                    }
                ]
            },
            "size": <graph height for HTML page>
    }

**PCAP Metadata** is saved under the key ``info``:
::

    "info": {
        "pcap_file": <pcap file path>,
        "analysis_time": <time of analysis>,
        "captipper_version": <CapTipper Version>,
        "traffic_time": <Time of first packet>
    }

**Client information** contains information collected on the client such as: IP, MAC, USER-AGENT and more interesting data if sent (such as: X-FLASH-VERSION).
it is saved under the key ``client``:
::

    "client": {
        "IP": <IP>,
        "MAC": <MAC>,
        "USER-AGENT": <User-Agent>
    }

**Coversations** are stored under the key ``conversations``:
::

    "conversations": [
            {
                "name": <host domain name>,
                "ip": <IP:Port>,
                "uris": [ // List of all URIs
                    {
                        "id": <conversation id>,
                        "uri": <URI>,
                        "short_uri": <Short representation of the URI>,
                        "req_head": <Request>
                        "res_body": <Response body>,
                        "res_base64": <Response in Base64>,
                        "respeek": <256 bytes of the Response>,
                        "magic_name": <File type>,
                        "magic_ext": <File extension>,
                        "res_head": <Response Header>,
                        "res_num": <Response Number>,
                        "res_type": <Response Content type>,
                        "referer": <referrer>,
                        "filename": <File name>,
                        "method": <Request Method>,
                        "epochtime": <Date Time>,
                        "res_len": <Response size>,
                        "md5": <MD5>,
                        "sha256": <SHA256>
                    }
                ]
                ...

HTML report
-----------
Every HTML report is based on the ``CapTipperTemplate.html`` stored in the ``jsontemplate\`` directory.
In order to be able to display the report while offline - the HTML stores the content of ``bootstrap.js``, ``jquery.js``, ``bootstrap.css`` and part of ``d3.js``.

The browsing flow graph is created using the *d3* library and displayed from left to right.

The HTML report is a ``bootstrap`` based page containing all 4 information blocks from the JSON file.

The page shows all the conversations in each domain, where suspicious URIs colored Yellow, and Executables colored Red.

Each conversation is expandable and displays all the data relevant to that conversation.

All of the conversations response body are stored in the HTML as well in a Base64 form (does not alarm AntiViruses).
each conversation has a **Download** button which allows the extraction of the file from the HTML into the file system.



.. _first blog post: http://www.omriher.com/2015/01/captipper-malicious-http-traffic.html

.. _CapTipper HTML Nuclear Report: https://www.googledrive.com/host/0B2SG9QbrDHc-RHBUeDZOWHA0cTg
