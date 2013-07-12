package gohop

import (
    "net"
    "os"
    "errors"
    "io/ioutil"
    "encoding/json"
    "encoding/binary"
    "github.com/bigeagle/water"
    "github.com/bigeagle/water/waterutil"
)

type hopServerConfig struct {
    ports []string
    key string
    addr string
    // dev string
}

type udpPacket struct {
    addr net.Addr
    data []byte
    channel int
}

type HopServer struct {
    // udpConn *net.UDPConn
    config *hopServerConfig
    iface *water.Interface

    netInput chan *udpPacket
    netOutputs []chan *udpPacket
    ifaceInput chan []byte

    clientChannel map[net.Addr] int
    natTable map[uint32] net.Addr
    macTable map[uint64] net.Addr
}


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

    cfg, ok := icfg.(map[string] interface{})

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

    hopServer := new(HopServer)
    hopServer.netInput = make(chan *udpPacket, 32)
    hopServer.ifaceInput = make(chan []byte, 32)
    hopServer.clientChannel = make(map[net.Addr] int)
    hopServer.natTable = make(map[uint32] net.Addr)
    hopServer.macTable = make(map[uint64] net.Addr)

    srvConfig, err := serverParseConfig(cfgFile)
    if err != nil {
        return err
    }

    logger.Debug("%v", srvConfig)
    hopServer.config = srvConfig
    hopServer.netOutputs = make([]chan *udpPacket, len(srvConfig.ports))

    iface, err := newTap("", srvConfig.addr)
    if err != nil {
        return err
    }
    hopServer.iface = iface

    go hopServer.forwardFrames()

    for i, port := range(srvConfig.ports) {
        go hopServer.listenAndServe(port, i)
    }

    logger.Debug("Recieving iface frames")

    buf := make([]byte, TAPBUFSIZE)
    for {
        n, err := iface.Read(buf)
        // logger.Debug("New iface Frame")
        if err != nil {
            return err
        }

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
        packet := new(udpPacket)
        packet.channel = idx
        packet.data = make([]byte, TAPBUFSIZE)
        _, packet.addr, err = udpConn.ReadFrom(packet.data)
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
        case frame := <-srv.ifaceInput:
            ethertype := waterutil.MACEthertype(frame)
            logger.Debug("New frame from channel")

            switch ethertype {
            case waterutil.IPv4:
                packet := waterutil.MACPayload(frame)

                if waterutil.IsIPv4(packet) {

                    vaddr := waterutil.IPv4Destination(packet)
                    key := binary.BigEndian.Uint32(([]byte)(vaddr))
                    if raddr, ok := srv.natTable[key]; ok {
                        if idx, ok := srv.clientChannel[raddr]; ok {
                            uPacket := &udpPacket{raddr, frame, idx}
                            srv.netOutputs[idx] <- uPacket
                        }
                    }
                    logger.Debug("Source:      %v [%v]", waterutil.MACSource(frame), waterutil.IPv4Source(packet))
                    logger.Debug("Destination: %v [%v]", waterutil.MACDestination(frame), waterutil.IPv4Destination(packet))
                    logger.Debug("Protocol:    %v\n", waterutil.IPv4Protocol(packet))
                }
            case waterutil.ARP:
                dest := waterutil.MACDestination(frame)
                logger.Debug("Mac Destionation: %v", dest)
                key := mac2uint64(dest)
                if raddr, ok := srv.macTable[key]; ok {
                    if idx, ok := srv.clientChannel[raddr]; ok {
                        uPacket := &udpPacket{raddr, frame, idx}
                        srv.netOutputs[idx] <- uPacket
                    }
                }

            }

        case packet:= <-srv.netInput:
            logger.Debug("New UDP Packet from: %v", packet.addr)
            srv.clientChannel[packet.addr] = packet.channel
            srv.iface.Write(packet.data)

            frame := packet.data
            ethertype := waterutil.MACEthertype(frame)

            macSrc := waterutil.MACSource(frame)
            logger.Debug("Mac Source: %v", macSrc)
            key := mac2uint64(macSrc)
            srv.macTable[key]  = packet.addr

            if ethertype == waterutil.IPv4 {
                ipPack := waterutil.MACPayload(frame)
                vaddr := waterutil.IPv4Source(ipPack)
                key := binary.BigEndian.Uint32(([]byte)(vaddr))
                srv.natTable[key] = packet.addr

                if waterutil.IsIPv4(ipPack) {
                    logger.Debug("Source:      %v [%v]", waterutil.MACSource(frame), waterutil.IPv4Source(ipPack))
                    logger.Debug("Destination: %v [%v]", waterutil.MACDestination(frame), waterutil.IPv4Destination(ipPack))
                }
            }

        }

    }
}

// func (srv *HopServer)

//func initUDPServer() {
//
//
//}
