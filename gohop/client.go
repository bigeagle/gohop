package gohop

import (
    "encoding/json"
    "errors"
    "io/ioutil"
    "net"
    "os"
    //    "encoding/binary"
    "github.com/bigeagle/water"

//    "github.com/bigeagle/water/waterutil"
)

type hopClientConfig struct {
    servers []string
    key     string
    addr    string
}

type HopClient struct {
    config *hopClientConfig
    iface  *water.Interface

    ifaceIn  chan []byte
    ifaceOut chan []byte

    netIn  chan []byte
    netOut chan []byte
}

func clientParseConfig(cfgFile string) (*hopClientConfig, error) {
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

    cltConfig := new(hopClientConfig)

    cfg, ok := icfg.(map[string]interface{})

    if ok {
        // logger.Debug("%v", cfg)

        if iservers, found := cfg["servers"]; found {
            cltConfig.servers = make([]string, 0)
            switch servers := iservers.(type) {
            case string:
                cltConfig.servers = append(cltConfig.servers, servers)
            case []interface{}:
                for _, v := range servers {
                    if server, ok := v.(string); ok {
                        cltConfig.servers = append(cltConfig.servers, server)
                    } else {
                        return nil, errors.New("Invalid server config")
                    }
                }
            default:
                return nil, errors.New("Invalid server config")
            }
        } else {
            return nil, errors.New("Servers not found")
        }

        if ikey, found := cfg["key"]; found {
            if key, ok := ikey.(string); ok {
                cltConfig.key = key
            } else {
                return nil, errors.New("Invalid Key config")
            }
        } else {
            return nil, errors.New("Key not found")
        }

        if iaddr, found := cfg["addr"]; found {
            if addr, ok := iaddr.(string); ok {
                cltConfig.addr = addr
            } else {
                return nil, errors.New("Invalid Addr config")
            }
        } else {
            return nil, errors.New("Addr config not found")
        }

    }

    return cltConfig, nil
}

func NewClient(cfgFile string) error {
    hopClient := new(HopClient)
    hopClient.ifaceIn = make(chan []byte, 32)
    hopClient.ifaceOut = make(chan []byte, 32)
    hopClient.netIn = make(chan []byte, 32)
    hopClient.netOut = make(chan []byte, 32)

    cltConfig, err := clientParseConfig(cfgFile)
    if err != nil {
        return err
    }

    logger.Debug("%v", cltConfig)
    hopClient.config = cltConfig

    iface, err := newTap("", cltConfig.addr)
    if err != nil {
        return err
    }

    hopClient.iface = iface
    go hopClient.handleInterface()

    for i, server := range cltConfig.servers {
        go hopClient.handleUDP(server, i)
    }

    for {
        // forward
        select {
        case frame := <-hopClient.ifaceIn:
            hopClient.netOut <- frame
        case packet := <-hopClient.netIn:
            hopClient.ifaceOut <- packet
        }
    }
    return nil
}

func (clt *HopClient) handleInterface() {
    // network packet to interface
    go func() {
        for {
            frame := <-clt.ifaceOut
            logger.Debug("New Net packet to device")
            n, err := clt.iface.Write(frame)
            logger.Debug("n: %d, len: %d", n, len(frame))
            if err != nil {
                logger.Error(err.Error())
                return
            }
        }
    }()

    buf := make([]byte, TAPBUFSIZE)
    for {
        n, err := clt.iface.Read(buf)
        if err != nil {
            logger.Error(err.Error())
            return
        }
        frame := make([]byte, n+1)
        copy(frame[1:], buf[0:n])

        // frame -> ifaceIn -> netOut
        clt.ifaceIn <- frame
    }
}

func (clt *HopClient) handleUDP(server string, idx int) {
    udpAddr, _ := net.ResolveUDPAddr("udp", server)
    udpConn, _ := net.DialUDP("udp", nil, udpAddr)

    opcode := HOP_REQ

    // forward iface frames to network
    go func() {
        for {
            frame := <-clt.netOut
            frame[0] = opcode
            udpConn.Write(frame)
        }
    }()

    buf := make([]byte, TAPBUFSIZE)

    for {
        n, err := udpConn.Read(buf)
        logger.Debug("New UDP Packet")
        if err != nil {
            logger.Error(err.Error())
            return
        }

        hp, _ := unpackHopPacket(buf[:n])
        pack := make([]byte, n-1)

        if hp.opcode == HOP_ACK {
            opcode = HOP_DAT
            logger.Info("Connection Initialized")
        }

        copy(pack, hp.frame)

        // pack -> netIn -> ifaceOut
        clt.netIn <- pack
    }
}
