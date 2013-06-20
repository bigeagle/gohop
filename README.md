GoHop
=====
GoHop is a VPN implemented in golang, with encryption and obfuscation built in nature. The goal of this project is to escape from censorship and intellegent package inspection.

This is also my network forencics course project.


Why Reinvent the Wheel?
------
There're already lots of VPN solutions like OpenVPN, L2TP with IPSec, PPTP and other commercial VPNs. 
But one key problem of these VPNs are that they're only built for anti-censorship instead of anti-GFW, of course, because their developers are not Chinese.

In the past, encrypting packets is enough to get through GFW, but around Nov. 2012, with the upgrading of GFW, where DPI(deep packet inspection) and Macheine Learning was introduced, although they cannot decrypt the packets and see the contents, they can still detect there're HTTP packets encrypted inside VPN packets, thus both OpenVPN and SSH tunnel was blocked in China.

How to Escape from DPI
------
There's no silver bullet to escape from the intelligent GFW, except for revolution :). All what i'm going to do are temporal solutions.

First, OpenVPN and SSH are both built on top of SSL, which has distinct handshake character and can be easily detected by GFW. Second, all present VPN solutions are single-port or single-protocol, thus the flow can be captured easily and with the help of machine learning, new protocols can be inspected, too.

So I'm going to implement a VPN with these features:

1. Pre-shared key based authentication, randomly generated key for encryption. NO SSL, maybe a reinvented SSL :).
2. "Frequency hopping"-like port and protocol hopping, both handshake and packet transmission will be acctually done in random port and protocol.
3. Flow obfuscation to hide HTTP characters.

Implemention
-------
This project will be implemented in golang, a fast, static typed and human-friendly language developed by google. VPN connection will be build on top of Linux's `tun/tap` device. I have no plan to port it to windows or OS X.

