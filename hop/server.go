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
    "encoding/json"
    "errors"
    "github.com/bigeagle/water"
    "github.com/bigeagle/water/waterutil"
    "io/ioutil"
    "net"
    "os"
)

// config for hopserver
type hopServerConfig struct {
    ports []string
    key   string
    addr  string
    // dev string
}

// a udpPacket
type udpPacket struct {
    // client's addr
    addr *net.UDPAddr
    // data
    data []byte
    // channel index
    channel int
}

type HopServer struct {
    // config
    config *hopServerConfig
    // interface
    iface *water.Interface
    // client peers, key is the mac address, value is a HopPeer record
    peers map[uint32]*HopPeer

    // channel to put in packets read from udpsocket
    fromNet chan *udpPacket
    // channels to put packets to send through udpsocket
    toNet []chan *udpPacket
    // channel to put frames read from tun/tap device
    fromIface chan []byte
}

// read and parse config file
func serverParseConfig(cfgFile string) (*hopServerConfig, error) {

    file, err := os.Open(cfgFile)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    jsonBuf, err := ioutil.ReadAll(file)

    // logger.Debug("%s", string(jsonBuf))

    var icfg interface{}
    err = json.Unmarshal(jsonBuf, &icfg)

    if err != nil {
        return nil, err
    }

    srvConfig := new(hopServerConfig)

    cfg, ok := icfg.(map[string]interface{})

    if ok {
        // logger.Debug("%v", cfg)

        if iports, found := cfg["ports"]; found {
            srvConfig.ports = make([]string, 0)
            switch ports := iports.(type) {
            case string:
                srvConfig.ports = append(srvConfig.ports, ports)
            case []interface{}:
                for _, v := range ports {
                    if port, ok := v.(string); ok {
                        srvConfig.ports = append(srvConfig.ports, port)
                    } else {
                        return nil, errors.New("Invalid port config")
                    }
                }
            default:
                return nil, errors.New("Invalid port config")
            }
        } else {
            return nil, errors.New("Port not found")
        }

        if ikey, found := cfg["key"]; found {
            if key, ok := ikey.(string); ok {
                srvConfig.key = key
            } else {
                return nil, errors.New("Invalid Key config")
            }
        } else {
            return nil, errors.New("Key not found")
        }

        if iaddr, found := cfg["addr"]; found {
            if addr, ok := iaddr.(string); ok {
                srvConfig.addr = addr
            } else {
                return nil, errors.New("Invalid Addr config")
            }
        } else {
            return nil, errors.New("Addr config not found")
        }

    }

    return srvConfig, nil
}

func NewServer(cfgFile string) error {
    srvConfig, err := serverParseConfig(cfgFile)
    if err != nil {
        return err
    }
    logger.Debug("%v", srvConfig)
    cipher, err = newHopCipher([]byte(srvConfig.key))
    if err != nil {
        return err
    }

    hopServer := new(HopServer)
    hopServer.fromNet = make(chan *udpPacket, 32)
    hopServer.fromIface = make(chan []byte, 32)
    hopServer.peers = make(map[uint32]*HopPeer)
    hopServer.config = srvConfig
    hopServer.toNet = make([]chan *udpPacket, len(srvConfig.ports))

    iface, err := newTun("", srvConfig.addr)
    if err != nil {
        return err
    }
    hopServer.iface = iface

    // forward device frames to socket and socket packets to device
    go hopServer.forwardFrames()

    // serve for multiple ports
    for i, port := range srvConfig.ports {
        go hopServer.listenAndServe(port, i)
    }

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

func (srv *HopServer) listenAndServe(port string, idx int) {
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

    netOutput := make(chan *udpPacket, 32)
    srv.toNet[idx] = netOutput

    go func() {
        for {
            packet := <-netOutput
            logger.Debug("client addr: %v", packet.addr)
            udpConn.WriteTo(packet.data, packet.addr)
        }
    }()

    for {
        var plen int
        packet := new(udpPacket)
        packet.channel = idx
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
                if addr, idx, ok := hpeer.addr(); ok {
                    upacket := &udpPacket{addr, hp.Pack(), idx}
                    srv.toNet[idx] <- upacket
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
                hp := newHopPeer(key, packet.addr, packet.channel)
                srv.peers[key] = hp
            }

            if peer, ok := srv.peers[key]; ok {
                peer.insertAddr(packet.addr, packet.channel)
            }
            srv.iface.Write(ipPack)
        }

    }
}
