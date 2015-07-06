=========
Webserver
=========

By Default, CapTipper launches a pseudo-web server that behavaes exactly like the web servers involved in the PCAP file.

The server is not a real web server and doesnt use any python webserver libraries.
Instead, it uses the SocketServer library and the parsing are made with raw text.

The reason for that is I didn't want the files included in the PCAP to be stored on the file system to refrain from endangering the researchers computer in case the tool is used on his working computer.
In this way, there is also no concern for any AntiVirus to pop up while messing with the files since they are only stored in CapTipper datasets.

Every request to the webserver is logged to the CTCore.request_logs list object and is viewable at any time using the command 'log' from CapTipper's console.


