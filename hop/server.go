/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Justin Wong <justin.w.xd@gmail.com>
 *
 */

package hop

import (
    "github.com/bigeagle/water"
    "github.com/bigeagle/water/waterutil"
    "net"
)

// a udpPacket
type udpPacket struct {
    // client's addr
    addr *net.UDPAddr
    // data
    data []byte
}

type HopServer struct {
    // config
    cfg HopServerConfig
    // interface
    iface *water.Interface
    // client peers, key is the mac address, value is a HopPeer record
    peers map[uint32]*HopPeer

    // channel to put in packets read from udpsocket
    fromNet chan *udpPacket
    // channel to put packets to send through udpsocket
    toNet chan *udpPacket
    // channel to put frames read from tun/tap device
    fromIface chan []byte
}


func NewServer(cfg HopServerConfig) error {
    var err error
    logger.Debug("%v", cfg)

    cipher, err = newHopCipher([]byte(cfg.Key))
    if err != nil {
        return err
    }

    hopServer := new(HopServer)
    hopServer.fromNet = make(chan *udpPacket, 32)
    hopServer.fromIface = make(chan []byte, 32)
    hopServer.peers = make(map[uint32]*HopPeer)
    hopServer.cfg = cfg
    hopServer.toNet = make(chan *udpPacket, 32)

    iface, err := newTun("", cfg.Addr)
    if err != nil {
        return err
    }
    hopServer.iface = iface

    // forward device frames to socket and socket packets to device
    go hopServer.forwardFrames()

    // serve for multiple ports
   go hopServer.listenAndServe(cfg.Port)

    logger.Debug("Recieving iface frames")

    buf := make([]byte, MTU)
    for {
        n, err := iface.Read(buf)
        if err != nil {
            return err
        }

        frame := make([]byte, n)
        copy(frame, buf[0:n])
        hopServer.fromIface <- frame
    }

}

func (srv *HopServer) listenAndServe(port string) {
    udpAddr, err := net.ResolveUDPAddr("udp", port)
    if err != nil {
        logger.Error("Invalid port: %s", port)
        return
    }
    udpConn, err := net.ListenUDP("udp", udpAddr)
    if err != nil {
        logger.Error("Failed to listen udp port %s: %s", port, err.Error())
        return
    }

    go func() {
        for {
            packet := <-srv.toNet
            logger.Debug("client addr: %v", packet.addr)
            udpConn.WriteTo(packet.data, packet.addr)
        }
    }()

    for {
        var plen int
        packet := new(udpPacket)
        buf := make([]byte, IFACE_BUFSIZE)
        plen, packet.addr, err = udpConn.ReadFromUDP(buf)

        packet.data = buf[:plen]
        if err != nil {
            logger.Error(err.Error())
            return
        }

        srv.fromNet <- packet
    }

}

func (srv *HopServer) forwardFrames() {
    for {
        select {
        case pack := <-srv.fromIface:
            // logger.Debug("New iface Frame")
            // first byte is left for opcode
            dest := waterutil.IPv4Destination(pack)
            mkey := ip4_uint32(dest)

            logger.Debug("ip dest: %v", dest)
            if hpeer, found := srv.peers[mkey]; found {
                hp := new(HopPacket)
                hp.Seq = hpeer.seq
                hp.payload = pack
                hpeer.seq += 1

                if !hpeer.inited {
                    hpeer.inited = true
                    hp.Flag = HOP_FLG_ACK
                }


                // logger.Debug("Peer: %v", hpeer)
                if addr, ok := hpeer.addr(); ok {
                    upacket := &udpPacket{addr, hp.Pack()}
                    srv.toNet <- upacket
                }
            }

        case packet := <-srv.fromNet:
            logger.Debug("New UDP Packet from: %v", packet.addr)

            hPack, _ := unpackHopPacket(packet.data)
            // logger.Debug("%v", hPack)
            ipPack := hPack.payload

            ipSrc := waterutil.IPv4Source(ipPack)
            logger.Debug("IP Source: %v, flag: %x", ipSrc, hPack.Flag)
            key := ip4_uint32(ipSrc)

            if hPack.Flag == HOP_FLG_PSH {
                hp := newHopPeer(key, packet.addr)
                srv.peers[key] = hp
            }

            if peer, ok := srv.peers[key]; ok {
                peer.insertAddr(packet.addr)
            }
            srv.iface.Write(ipPack)
        }

    }
}
