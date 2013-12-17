GoHop
=====
GoHop is a VPN implemented in golang, with innate encryption and obfuscation. The goal of this project is to escape from censorship and intelligent package inspection.

Why Reinvent the Wheel?
------
There're already lots of VPN solutions like OpenVPN, L2TP with IPSec, PPTP and other commercial VPNs. 
But one key problem of these VPNs are that they're only built for anti-censorship instead of anti-GFW, of course, because their developers are not Chinese.

In the past, encrypting packets is enough to get through GFW, but around Nov. 2012, with the upgrading of GFW, where DPI(deep packet inspection) and Machine Learning was introduced, although they cannot decrypt the packets and see the contents, they can still detect there're HTTP packets encrypted inside VPN packets, thus both OpenVPN and SSH tunnel was blocked in China.

How to Escape from DPI
------
There's no silver bullet to escape from the intelligent GFW, except for revolution :). All what I'm going to do are temporal solutions.

First, OpenVPN and SSH are both built on top of SSL, which has distinct handshake character and can be easily detected by GFW. Second, all present VPN solutions are single-port or single-protocol, thus the flow can be captured easily and with the help of machine learning, new protocols can be inspected, too.

So I'm going to implement a VPN with these features:

1. Pre-shared key based authentication, randomly generated key for encryption. NO SSL, maybe a reinvented SSL :).
2. "Frequency hopping"-like port and protocol hopping, both handshake and packet transmission will be actually done in random port and protocol.
3. Traffic shaping to hide protocol's statistical properties.

Notice
-------
GoHop is built on top of Linux's `tun/tap` device. **Currently it does neither support Windows nor OS X**

I think it would not be very difficult to port it to OS X. However, I'm not able to develop a OS X edition as I'm not a mac owner. If u wanna help, please fork and send me pull requests, I'd appreciate it.

How To Use
------
### Download
You can get updated release from https://github.com/bigeagle/gohop/releases , go programs are static-linked, so it's very likely that my pre-built releases can run on your box.

### Build and Install
**Building GoHop needs Go 1.1 or higher.**

First get dependency libraries and gohop source code.

```
go get github.com/bigeagle/go-logging
go get github.com/bigeagle/water
go get code.google.com/p/gcfg
go get github.com/bigeagle/gohop
```

build and install:

```
go install github.com/bigeagle/gohop
```

### Config and Run

On the server, if u are using it for anti-GFW internet access, ip forwarding is needed:

```
sysctl net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -j MASQUERADE
```

edit `server.ini` as your server's config file. Run
```
gohop server.ini
```

at client side, edit `client.ini` as your config file, custom routes is supported so that in-china network packets will not go through gohop. Run
```
gohop client.ini
```
wait until u see `Connection Initialized`, pay attention to your DNS config, if u are using a Chinese DNS server, u're still unable to access blocked websites.

now try to ping `twitter.com` and cheers :).


LICENSE
------
```
Copyright (c) 2013 Justin Wong <justin.w.xd@gmail.com>

This program is free software: you can redistribute it and/or modify    
it under the terms of the GNU General Public License as published by    
the Free Software Foundation, either version 3 of the License, or    
(at your option) any later version.    

This program is distributed in the hope that it will be useful,    
but WITHOUT ANY WARRANTY; without even the implied warranty of    
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    
GNU General Public License for more details.    

You should have received a copy of the GNU General Public License    
along with this program.  If not, see <http://www.gnu.org/licenses/>.
```
