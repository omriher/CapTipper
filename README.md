##CapTipper v0.2

CapTipper v0.2: http://www.omriher.com/2015/03/captipper-02-released.html  
CapTipper v0.1: http://www.omriher.com/2015/01/captipper-malicious-http-traffic.html  

CapTipper is a python tool to analyze, explore and revive HTTP malicious traffic.  
CapTipper sets up a web server that acts exactly as the server in the PCAP file,  
and contains internal tools, with a powerful interactive console, for analysis and inspection of the hosts, objects and conversations found.

The tool provides the security researcher with easy access to the files and the understanding of the network flow,  
and is useful when trying to research exploits, pre-conditions, versions, obfuscations, plugins and shellcodes.

Feeding CapTipper with a drive-by traffic capture (e.g of an exploit kit) displays the user with the requests URI's that were sent and responses meta-data.  
The user can at this point browse to http://127.0.0.1/[URI] and receive the response back to the browser.  
In addition, an interactive shell is launched for deeper investigation using various commands such as: hosts, hexdump, info, ungzip, body, client, dump and more...

[ScreenShot]: http://3.bp.blogspot.com/-7XrSKP1BHzE/VLRGBR3cQ0I/AAAAAAAAZso/3FpWTRi8rYU/s1600/CapTipperScreenShot.png

![ScreenShot]
***
###Analysis Example

```sh
Usage: ./CapTipper.py <PCAP_file> [-p] [web_server_port=80]
```
Let's analyze the following Nuclear EK drive-by infection PCAP [2014-11-06-Nuclear-EK-traffic.pcap](http://www.malware-traffic-analysis.net/2014/11/06/2014-11-06-Nuclear-EK-traffic.pcap)
```sh
C:\CapTipper> CapTipper.py "C:\NuclearFiles\2014-11-06-Nuclear-EK-traffic.pcap"

CapTipper v0.1 - Malicious HTTP traffic explorer tool
Copyright 2015 Omri Herscovici <omriher@gmail.com>

[A] Analyzing PCAP: C:\NuclearFiles\2014-11-06-Nuclear-EK-traffic.pcap

[+] Traffic Activity Time: Thu, 11/06/14 17:02:35
[+] Conversations Found:

0: / -> text/html (0.html) [5509 B]
1: /wp-includes/js/jquery/jquery.js?ver=1.7.2 -> application/javascript (jquery.js) [39562 B]
2: /seedadmin17.html -> text/html (seedadmin17.html) [354 B]
3: /15c0b14drr9f_1_08282d03fb0251bbd75ff6dc6e317bd9.html -> text/html (15c0b14drr9f_1_08282d03fb0251bbd75ff6dc6e317bd9.html) [113149 B]
4: /wp-content/uploads/2014/01/MetroWest_COVER_Issue2_Feb2014.jpg -> image/jpeg (MetroWest_COVER_Issue2_Feb2014.jpg) [350008 B]
5: /images/footer/3000melbourne.png -> image/png (3000melbourne.png) [2965 B]
6: /images/footer/3207portmelbourne.png -> image/png (3207portmelbourne.png) [3092 B]
7: /wp-content/uploads/2012/09/background1.jpg -> image/jpeg (background1.jpg) [33112 B]
8: /00015d76d9b2rr9f/1415286120 -> application/octet-stream (00015d76.swf) [31579 B]
9: /00015d766423rr9f/1415286120 -> application/pdf (XykpdWhZZ2.pdf) [9940 B]
10: /00015d76rr9f/1415286120/5/x00809070554515d565b010b03510053535c0505;1;6 -> application/octet-stream (5.exe) [139264 B]
11: /00015d76rr9f/1415286120/5/x00809070554515d565b010b03510053535c0505;1;6;1 -> application/octet-stream (5.exe) [139264 B]
12: /00015d76rr9f/1415286120/7 -> application/octet-stream (7.exe) [139264 B]
13: /00015d761709rr9f/1415286120 -> application/octet-stream (00015d76.swf) [8064 B]
14: /00015d76rr9f/1415286120/8 -> application/octet-stream (8.exe) [139264 B]


[+] Started Web Server on http://localhost:80
[+] Listening to requests...

CapTipper Interpreter
Type 'open <conversation id>' to open address in browser
type 'hosts' to view traffic flow
Type 'help' for more options

CT>
```
The Initialization outputs the conversations found between the client and the server in the following format:

**[ID] : REQUEST URI -> SERVER RESPONSE TYPE (FILENAME) [SIZE IN BYTES]**

**ID**: An assigned Id to the specific conversation  
**REQUEST URI**: The URI that was sent to the server in the GET request  
**SERVER RESPONSE TYPE**: The content-type returned in the server response header  
**FILENAME**: The filename can be a few things:  
  1. Filename attribute given in the response header
  2. Derived from the URI
  3. Assigned by CapTipper if couldn't find any of the above
  
**SIZE IN BYTES**: Response body size

After Initalization, 2 things occur:  
  1. CapTipper creates a pseudo-web server that behaves like the web server in the pcap
  2. An Interpreter is launched
  
The interpreter contains internal tools for further investigation of the objects in the pcap.

Opening a URI in the browser is simply by typing 'open' along with the object id
```sh
CT> open 0
CT> log
[2015-01-09T18:01:28.878000] 127.0.0.1 : GET / HTTP/1.1
```
* None of the commands (Except 'open') actually requires the server to be running. You can turn off the server by typing 'server off' or by adding -s when calling CapTipper.  

Let's see what can we find out without using the browser.  
First, we'll take a bird's-eye view on the traffic by using the command 'hosts'
```sh
CT> hosts
Found Hosts:

 www.magmedia.com.au
 ├-- /   [0]
 ├-- /wp-includes/js/jquery/jquery.js?ver=1.7.2   [1]
 ├-- /wp-content/uploads/2014/01/MetroWest_COVER_Issue2_Feb2014.jpg   [4]
 ├-- /images/footer/3000melbourne.png   [5]
 ├-- /images/footer/3207portmelbourne.png   [6]
 └-- /wp-content/uploads/2012/09/background1.jpg   [7]


 pixeltouchstudios.tk
 └-- /seedadmin17.html   [2]


 grannityrektonaver.co.vu
 ├-- /15c0b14drr9f_1_08282d03fb0251bbd75ff6dc6e317bd9.html   [3]
 ├-- /00015d76d9b2rr9f/1415286120   [8]
 ├-- /00015d766423rr9f/1415286120   [9]
 ├-- /00015d76rr9f/1415286120/5/x00809070554515d565b010b03510053535c0505;1;6   [10]
 ├-- /00015d76rr9f/1415286120/5/x00809070554515d565b010b03510053535c0505;1;6;1   [11]
 ├-- /00015d76rr9f/1415286120/7   [12]
 ├-- /00015d761709rr9f/1415286120   [13]
 └-- /00015d76rr9f/1415286120/8   [14]
```
It seems that **www.magmedia.com.au** is the compromised site.

By crossing this information and the file types we got in the conversations list, it looks like **grannityrektonaver.co.vu** is the infecting host.

Then what is **pixeltouchstudios.tk** ?

Well, knowing how exploit-kits usually work, this is probably the TDS (Traffic Distribution System) server.  
Let's take a closer look.

We can print the header and the body of the page by typing 'head' and 'body':
```sh
CT> head 2
Displaying header of object 2 (seedadmin17.html):

HTTP/1.1 302 Found
Server: nginx
Date: Thu, 06 Nov 2014 15:02:38 GMT
Content-Type: text/html; charset=iso-8859-1
Content-Length: 354
Connection: keep-alive
Set-Cookie: ehihm=_YocADE3AAIAAgCvjVtU__.vjVtUQAABAAAAr41bVAA-; expires=Fri, 06-Nov-2015 15:03:11 GMT; path=/; domain=pixeltouchstudios.tk
Location: http://grannityrektonaver.co.vu/15c0b14drr9f_1_08282d03fb0251bbd75ff6dc6e317bd9.html

CT> body 2
Displaying body of object 2 (seedadmin17.html) [256 bytes]:

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>302 Found</title>
</head><body>
<h1>Found</h1>
<p>The document has moved <a href="http://grannityrektonaver.co.vu/15c0b14drr9f_1_08282d03fb0251bbd75ff6dc6e317bd9.html">here</a>.</p>
<hr
```
* By deafult, the body command returns the first 256 byte, you can change it by typing body 2 1000 - this will print the first 1000 bytes

We see that object 2, returns a *302 redirection* to the infecting host.  
So our hypothesis was probably true.

Let's get more information on object 2 by typing 'info':
```sh
CT> info 2
Info of conversation 2:

 SERVER IP   : 108.61.196.84:80
 HOST        : pixeltouchstudios.tk
 URI         : /seedadmin17.html
 REFERER     : http://www.magmedia.com.au/
 RESULT NUM  : 302 Found
 RESULT TYPE : text/html
 FILE NAME   : seedadmin17.html
 LENGTH      : 354 B
```
The referrer to that page was of course **magmedia.co.au**, but what exactly redirected us?

By looking at the conversations it was probably either the index page or the javascript file.  
Let's have a quick peek at the javascript file (object 1)
```sh
CT> body 1 
Displaying body of object 1 (jquery.js) [256 bytes]:

▼     ♦♥─╜i{#╟ס╢√}~♣X╓t♥═"HJצg♀░→o½%Y▓╡ם║m┘CR║
@a!▒P ╪כ        ╬o?≈‼╣TJ≥£≈\g╞jó╢\"#cן╚πg ÷ry≤~5↔O6םµ╦Vπ├ףף h|╛*ך╞½σh≤6_§ם╧ק╖כa╛ש.↨iπ╦┼á▌רl67¥ππ╤z╘^«╞╟ ÷∞°▀F╖כב▐hלכ═╦σ≥zZ4≤╓▌¢|╒Φg├σαv^,6φב=h╧≤═`╥\¶o
←▀↨π╧▐▌4ףf»≤π╢█h%חy{U▄╠≥A╤<n₧_┤?Φ=█▐▌_4/Z↨τ↨ק↨↨↨╟↨ח?^╢מ╟irq±┴i
```
Hmm... What's going on? Let's look at the header
```sh
CT> head 1
Displaying header of object 1 (jquery.js):

HTTP/1.1 200 OK
Content-Encoding: gzip
Vary: Accept-Encoding
Date: Thu, 06 Nov 2014 15:03:41 GMT
Server: LiteSpeed
Accept-Ranges: bytes
Connection: Keep-Alive
Keep-Alive: timeout=5, max=100
Last-Modified: Mon, 10 Feb 2014 12:34:10 GMT
Content-Type: application/javascript
Content-Length: 39562
Cache-Control: public, max-age=604800
Expires: Thu, 13 Nov 2014 15:03:41 GMT
```
The response is gzipped.  
Let's ungzip it:
```sh
CT> ungzip 1
 GZIP Decompression of object 1 (jquery.js) successful!
 New object created: 15
```
Great. a new object was created (15).  
Let's look at it.
```sh
CT> body 15
Displaying body of object 15 (ungzip-jquery.js) [256 bytes]:

/*
Copyright (C) 2007 Free Software Foundation, Inc. http://fsf.org/
*/
function getCookie(a){var b=document.cookie.match(new RegExp("(?:^|; )"+a.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g,"\\$1")+"=([^;]*)"));return b?decodeU
RIComponent(b[1]):undefined}(funct
```
So this is the ungzipped version of the JS file.  
Remember, we want to find out what redirected us to the TDS,  
Safe to assume it was an iframe, so let's search for iframes in the new object using the command 'iframes'
```sh
CT> iframes 15
Searching for iframes in object 15 (ungzip-jquery.js)...
 1 Iframe(s) Found!

 [I] 1 : http://pixeltouchstudios.tk/seedadmin17.html
```
There you go, the attacker planted/altered this javascript and made it send the users to the TDS.

Now let's take a look at the files from the infecting server.  
typing 'convs' again will display the conversations:
```sh
CT> convs
Conversations Found:

0: / -> text/html (0.html) [5509 B]
1: /wp-includes/js/jquery/jquery.js?ver=1.7.2 -> application/javascript (jquery.js) [39562 B]
2: /seedadmin17.html -> text/html (seedadmin17.html) [354 B]
3: /15c0b14drr9f_1_08282d03fb0251bbd75ff6dc6e317bd9.html -> text/html (15c0b14drr9f_1_08282d03fb0251bbd75ff6dc6e317bd9.html) [113149 B]
4: /wp-content/uploads/2014/01/MetroWest_COVER_Issue2_Feb2014.jpg -> image/jpeg (MetroWest_COVER_Issue2_Feb2014.jpg) [350008 B]
5: /images/footer/3000melbourne.png -> image/png (3000melbourne.png) [2965 B]
6: /images/footer/3207portmelbourne.png -> image/png (3207portmelbourne.png) [3092 B]
7: /wp-content/uploads/2012/09/background1.jpg -> image/jpeg (background1.jpg) [33112 B]
8: /00015d76d9b2rr9f/1415286120 -> application/octet-stream (00015d76.swf) [31579 B]
9: /00015d766423rr9f/1415286120 -> application/pdf (XykpdWhZZ2.pdf) [9940 B]
10: /00015d76rr9f/1415286120/5/x00809070554515d565b010b03510053535c0505;1;6 -> application/octet-stream (5.exe) [139264 B]
11: /00015d76rr9f/1415286120/5/x00809070554515d565b010b03510053535c0505;1;6;1 -> application/octet-stream (5.exe) [139264 B]
12: /00015d76rr9f/1415286120/7 -> application/octet-stream (7.exe) [139264 B]
13: /00015d761709rr9f/1415286120 -> application/octet-stream (00015d76.swf) [8064 B]
14: /00015d76rr9f/1415286120/8 -> application/octet-stream (8.exe) [139264 B]
```
So what do we have here...  
looks like we have 1 PDF file, 2 SWF files, and 4 EXE files that were probably downloaded by the shellcode.

We can dump all the files to a folder for deeper inspection using the 'dump' function, we can add '-e' to refrain from dumping the EXE files, so we won't accidentally launch them.
```sh
CT> dump all c:\NuclearFiles -e
 Object 0 written to c:\NuclearFiles\0-0.html
 Object 1 written to c:\NuclearFiles\1-jquery.js
 Object 2 written to c:\NuclearFiles\2-seedadmin17.html
 Object 3 written to c:\NuclearFiles\3-15c0b14drr9f_1_08282d03fb0251bbd75ff6dc6e317bd9.html
 Object 4 written to c:\NuclearFiles\4-MetroWest_COVER_Issue2_Feb2014.jpg
 Object 5 written to c:\NuclearFiles\5-3000melbourne.png
 Object 6 written to c:\NuclearFiles\6-3207portmelbourne.png
 Object 7 written to c:\NuclearFiles\7-background1.jpg
 Object 8 written to c:\NuclearFiles\8-00015d76.swf
 Object 9 written to c:\NuclearFiles\9-XykpdWhZZ2.pdf
 Object 13 written to c:\NuclearFiles\13-00015d76.swf
 Object 15 written to c:\NuclearFiles\15-ungzip-jquery.js
```
As you can see, it also dumps the newly created ungzipped javascript file.

We can also examing the files using CapTipper.  
Let's take a look at the first SWF file using 'hexdump'.
```sh
CT> hexdump 8
Displaying hexdump of object 8 (00015d76.swf) body [256 bytes]:

0000   5A 57 53 17 E4 1B 01 01 4A 7B 00 00 5D 00 00 00    ZWS.....J{..]...
0010   01 00 3B FF FC 8E 19 FA DF E7 66 08 A0 3D 3E 85    ..;.......f..=>.
0020   F5 75 6F D2 74 6B 7F 7F 31 2C 92 04 FD 10 0A EE    .uo.tk..1,......
0030   E2 C5 C2 C9 4C 83 91 74 AE C8 7C 80 F6 31 A6 CE    ....L..t..|..1..
0040   C0 15 CB 62 8D 76 42 8B 28 96 D3 83 FE 20 DE 57    ...b.vB.(.... .W
0050   7B E4 D2 F1 D8 BC E6 45 CF DC 7B 79 38 41 60 1F    {......E..{y8A`.
0060   0A E9 E4 10 8B F8 DA 0D A6 32 CF E1 E6 E9 78 AB    .........2....x.
0070   8B A7 8A C5 62 8F 0B 31 84 41 10 75 B1 33 35 9D    ....b..1.A.u.35.
0080   6E BA 30 B8 AE EB 78 33 31 67 36 42 01 36 4A A3    n.0...x31g6B.6J.
0090   C8 CB 29 B5 36 6E BF A7 D2 3B 9F 5C 6B A8 4A 9F    ..).6n...;.\k.J.
00A0   A5 59 5F 7F 43 98 39 43 E8 90 69 C7 9D 84 3A 9C    .Y_.C.9C..i...:.
00B0   36 1D E6 12 F8 EB 03 EA F4 59 2A FD 71 9F 15 DB    6........Y*.q...
00C0   4B F3 C3 C4 4C 70 11 A1 19 25 C8 79 6E 4A 5E 4C    K...Lp...%.ynJ^L
00D0   10 F5 A2 F9 1A E0 18 42 9D 87 9D 39 12 39 57 89    .......B...9.9W.
00E0   CF EF 41 78 2E 57 88 C9 A5 BA F2 0E FC E0 5E B5    ..Ax.W........^.
00F0   66 0C B4 7E A2 0B C4 D7 65 F8 12 57 98 58 16 16    f..~....e..W.X..
```
Now let's take a look at the second one:
```sh
CT> hexdump 13
Displaying hexdump of object 13 (00015d76.swf) body [256 bytes]:

0000   50 4B 03 04 14 00 00 08 08 00 81 7A 5D 45 6F 8B    PK.........z]Eo.
0010   BE 6C D2 00 00 00 6B 01 00 00 10 00 00 00 41 70    .l....k.......Ap
0020   70 4D 61 6E 69 66 65 73 74 2E 78 61 6D 6C 85 8F    pManifest.xaml..
0030   C1 4A 03 31 10 86 EF 42 DF 21 E4 01 92 50 6A 95    .J.1...B.!...Pj.
0040   C5 2D 14 F4 2A A5 8A F7 98 9D DA 60 66 12 32 69    .-..*......`f.2i
0050   9B 7D 36 0F 3E 92 AF E0 D6 A2 EC 61 C1 EB 37 FF    .}6.>......a..7.
0060   C7 C7 7C 7D 7C DE DD 43 0A B1 47 A0 22 2A 06 E2    ..|}|..C..G."*..
0070   56 EE 4B 49 8D D6 EC F6 80 96 15 7A 97 23 C7 5D    V.KI.......z.#.]
0080   51 2E A2 76 C1 0F 53 3D 37 E6 46 77 7F AA BC B8    Q..v..S=7.Fw....
0090   4D FD C7 3E 79 DA D5 B3 BC D4 D5 62 90 E2 81 4A    M..>y......b...J
00A0   EE 37 D1 53 59 33 03 BE 86 BE 95 15 F2 D1 A2 25    .7.SY3.........%
00B0   48 B0 00 7A F7 E3 D5 73 9F A0 95 96 BB 37 EE D4    H..z...s.....7..
00C0   3A 25 29 B6 07 2A 1E E1 05 32 FB 48 AD 5C 28 A3    :%)..*...2.H.\(.
00D0   AE CD ED 7C A9 8C 5C CD AE 84 18 7D A8 36 36 17    ...|..\....}.66.
00E0   FE A1 03 FF 2D 9E A1 A8 CD A3 45 98 8A 3F C5 43    ....-.....E..?.C
00F0   76 13 17 D5 85 E1 01 7D 69 E8 89 C8 18 AE BE 01    v......}i.......
```
Interesting... This file starts with the 'PK' magic bytes, meaning it's actually a zip file, which can be a few things.

Let's take a look at the files inside the zip using the command 'ziplist'
```sh
CT> ziplist 13
 2 Files found in zip object 13 (00015d76.swf):

 [Z] 1 : AppManifest.xaml
 [Z] 2 : xervamanepe4enki.dll
```
Well it seems that this is actually a Silverlight exploit.  
Now we can dump it with it's real extension:
```sh
CT> dump 13 c:\NuclearFiles\Silver_exp.xap
 Object 13 written to c:\NuclearFiles\Silver_exp.xap
```
We can also send the file's md5 hash to VirusTotal to see if it is recognized by any of the Anti-Virus providers, using the command 'vt'.  
These requires a VirusTotal public API key.  
(The file itself isn't sent to VT, only the hash of the file is sent!)
```sh
CT> vt 13
 VirusTotal result for object 13 (00015d76.swf):

 Detection: 37/56
 Last Analysis Date: 2014-12-11 13:15:33
 Report Link: https://www.virustotal.com/file/5bcb20f506ce854eb3191ca87a14c5777cdcb0f96ffec0b6...

 Scan Result:
        MicroWorld-eScan        Trojan.GenericKD.1962112        12.0.250.0      20141211
        nProtect        Trojan.GenericKD.1962112        2014-12-11.01   20141211
        CAT-QuickHeal   Trojan.Generic.r3       14.00   20141210
        McAfee  RDN/Generic Exploit!1ns 6.0.5.614       20141211
        Malwarebytes    Trojan.Agent    1.75.0.1        20141211
        VIPRE   Trojan.Win32.Generic!BT 35624   20141211
        K7AntiVirus     Exploit ( 004b06661 )   9.186.14309     20141211
        K7GW    Exploit ( 004b06661 )   9.186.14308     20141211
        Agnitum Exploit.CVE-2013-0074!  5.5.1.3 20141210
        F-Prot  W32/CVE130074.I 4.7.1.166       20141211
        Symantec        Trojan.Gen.2    20141.1.0.330   20141211
        Norman  CVE-2013-0074.D 7.04.04 20141211
        TotalDefense    Win32/Tnega.DPSQOR      37.0.11324      20141211
        TrendMicro-HouseCall    Suspicious_GEN.F47V1112 9.700.0.1001    20141211
        Avast   Win32:Malware-gen       8.0.1489.320    20141211
        ClamAV  SILVERLIGHT.Exploit.Nuclear     0.98.5.0        20141211
        BitDefender     Trojan.GenericKD.1962112        7.2     20141211
        NANO-Antivirus  Exploit.Win32.CVE20130074.dikfyh        0.28.6.63850    20141211
        Ad-Aware        Trojan.GenericKD.1962112        12.0.163.0      20141211
        Sophos  Mal/Generic-S   4.98.0  20141211
        Comodo  UnclassifiedMalware     20333   20141211
        F-Secure        Trojan.GenericKD.1962112        11.0.19100.45   20141211
        DrWeb   Exploit.CVE2013-0074.36 7.0.10.8210     20141211
        McAfee-GW-Edition       RDN/Generic Exploit!1ns v2014.2 20141211
        Emsisoft        Trojan.GenericKD.1962112 (B)    3.0.0.600       20141211
        Cyren   W32/CVE130074.MCZQ-2806 5.4.1.7 20141211
        Avira   EXP/Silverlight.Gen2    7.11.194.74     20141211
        Antiy-AVL       Trojan/Win32.SGeneric   1.0.0.1 20141211
        Microsoft       Exploit:MSIL/CVE-2013-0074.F    1.11202 20141211
        GData   Trojan.GenericKD.1962112        24      20141211
        ALYac   Exploit.CVE-2013-0074   1.0.1.4 20141211
        AVware  Trojan.Win32.Generic!BT 1.5.0.21        20141211
        Panda   Exploit/CVE-2013-0074   4.6.4.2 20141211
        ESET-NOD32      a variant of Win32/Exploit.CVE-2013-0074.BZ     10861   20141211
        Ikarus  Exploit.CVE-2013-0074   T3.1.8.5.0      20141211
        AVG     Exploit_c.ABKR  15.0.0.4235     20141211
        Baidu-International     Trojan.Win32.CVE-2013-0074.bBZ  3.5.1.41473     20141211
```
We notice that most of the Anti-Viruses detected this file as malicious, while some even provided the exploit CVE (2013-0074).  
* If you don't have a VirusTotal public API key, you can use the command 'hashes', and manually send the hash to VirusTotal.

***
###Info

Written By Omri Herscovici

Please open an issue for bugs.  
I would be happy to accept suggestions and feedback to my mail :)  

CapTipper: http://www.omriher.com/2015/01/captipper-malicious-http-traffic.html  
Email: [omriher@gmail.com](mailto:omriher@gmail.com?Subject=CapTipper feedback)  
Twitter: [@omriher](https://twitter.com/omriher)




