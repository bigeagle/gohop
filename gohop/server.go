package gohop

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
    addr    net.Addr
    // data
    data    []byte
    // channel index
    channel int
}

type HopServer struct {
    // config
    config *hopServerConfig
    // interface
    iface  *water.Interface
    // client peers, key is the mac address, value is a HopPeer record
    peers map[uint32]*HopPeer

    // channel to put in packets read from udpsocket
    netInput   chan *udpPacket
    // channels to put packets to send through udpsocket
    netOutputs []chan *udpPacket
    // channel to put frames read from tun/tap device
    ifaceInput chan []byte
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
    hopServer.netInput = make(chan *udpPacket, 32)
    hopServer.ifaceInput = make(chan []byte, 32)
    hopServer.peers = make(map[uint32]*HopPeer)
    hopServer.config = srvConfig
    hopServer.netOutputs = make([]chan *udpPacket, len(srvConfig.ports))

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

    buf := make([]byte, TAPBUFSIZE)
    for {
        n, err := iface.Read(buf)
        if err != nil {
            return err
        }

        // leave one byte for opcode
        frame := make([]byte, n)
        copy(frame, buf[0:n])
        hopServer.ifaceInput <- frame
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
    srv.netOutputs[idx] = netOutput

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
        buf := make([]byte, TAPBUFSIZE)
        plen, packet.addr, err = udpConn.ReadFrom(buf)

        packet.data = buf[:plen]
        if err != nil {
            logger.Error(err.Error())
            return
        }

        srv.netInput <- packet
    }

}

func (srv *HopServer) forwardFrames() {
    for {
        select {
        case pack := <-srv.ifaceInput:
            // logger.Debug("New iface Frame")
            // first byte is left for opcode
            dest := waterutil.IPv4Destination(pack)
            mkey := ip4_uint32(dest)

            // logger.Debug("mac dest: %v", dest)
            if hpeer, found := srv.peers[mkey]; found {
                opcode := HOP_DAT
                if ! hpeer.inited {
                    hpeer.inited = true
                    opcode = HOP_ACK
                }

                hp := &HopPacket{opcode, pack}

                // logger.Debug("Peer: %v", hpeer)
                if addr, idx, ok := hpeer.addr(); ok {
                    upacket := &udpPacket{addr, hp.Pack(), idx}
                    srv.netOutputs[idx] <- upacket
                }
            }

        case packet := <-srv.netInput:
            logger.Debug("New UDP Packet from: %v", packet.addr)

            hPack, _ := unpackHopPacket(packet.data)
            ipPack := hPack.frame

            ipSrc := waterutil.IPv4Source(ipPack)
            logger.Debug("IP Source: %v, opcode: %x", ipSrc, hPack.opcode)
            key := ip4_uint32(ipSrc)

            if hPack.opcode == HOP_REQ {
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
