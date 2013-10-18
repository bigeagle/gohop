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
    "io/ioutil"
    "net"
    "os"
    "os/signal"
    "syscall"
    "time"
    //    "encoding/binary"
    "github.com/bigeagle/water"

//    "github.com/bigeagle/water/waterutil"
)

var net_gateway, net_nic string

type route struct {
    dest, nextHop, iface string
}

type hopClientConfig struct {
    servers []string
    key     string
    addr    string
    // redirect gateway
    regw   bool
    routes []*route
}

type HopClient struct {
    config *hopClientConfig
    iface  *water.Interface

    fromIface  chan []byte
    toIface chan *HopPacket

    fromNet  chan *HopPacket
    toNet chan []byte
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

        if iregw, found := cfg["redirect_gateway"]; found {
            if regw, ok := iregw.(bool); ok {
                cltConfig.regw = regw
            } else {
                return nil, errors.New("Invalid Gateway Redirect Config")
            }
        } else {
            cltConfig.regw = false
        }

        net_gateway, net_nic, err = getNetGateway()
        logger.Debug("Net Gateway: %s %s", net_gateway, net_nic)
        if err != nil {
            return nil, err
        }

        if iroutes, found := cfg["net_gateway"]; found {
            cltConfig.routes = make([]*route, 0)
            if routes, ok := iroutes.([]interface{}); ok {
                for _, v := range routes {
                    if destNet, ok := v.(string); ok {
                        r := &route{destNet, net_gateway, net_nic}
                        cltConfig.routes = append(cltConfig.routes, r)
                    } else {
                        return nil, errors.New("Invalid Route config")
                    }
                }

            }
        }
    }

    return cltConfig, nil
}

func NewClient(cfgFile string) error {
    cltConfig, err := clientParseConfig(cfgFile)
    if err != nil {
        return err
    }
    logger.Debug("%v", cltConfig)
    cipher, err = newHopCipher([]byte(cltConfig.key))
    if err != nil {
        return err
    }

    hopClient := new(HopClient)
    hopClient.fromIface = make(chan []byte, 32)
    hopClient.toIface = make(chan *HopPacket, 32)
    hopClient.fromNet = make(chan *HopPacket, 32)
    hopClient.toNet = make(chan []byte, 32)
    hopClient.config = cltConfig

    iface, err := newTun("", cltConfig.addr)
    if err != nil {
        return err
    }

    hopClient.iface = iface
    go hopClient.handleInterface()

    for i, server := range cltConfig.servers {
        go hopClient.handleUDP(server, i)
    }

    go func() {
        defer hopClient.cleanUp()
        for _, route := range cltConfig.routes {
            addRoute(route.dest, route.nextHop, route.iface)
        }
    }()

    if cltConfig.regw {
        go func() {
            time.Sleep(2 * time.Second)
            err = redirectGateway(iface.Name(), tun_peer.String())
            if err != nil {
                logger.Error(err.Error())
                return
            }
        }()
    }

    hpBuf := newHopPacketBuffer()

    go func() {
        ticker := time.NewTicker(10 * time.Millisecond)
        for {
            <-ticker.C
            hpBuf.flushToChan(hopClient.toIface)
        }
    }()

    for {
        // forward
        select {
        case frame := <-hopClient.fromIface:
            hopClient.toNet <- frame
        case packet := <-hopClient.fromNet:
            // logger.Debug("New HopPacket Seq: %d", packet.Seq)
            if err := hpBuf.push(packet); err != nil {
                logger.Debug("buffer full, flushing")
                hpBuf.flushToChan(hopClient.toIface)
            }
        }
    }

    return nil
}

func (clt *HopClient) handleInterface() {
    // network packet to interface
    go func() {
        for {
            hp := <-clt.toIface
            // logger.Debug("New Net packet to device")
            n, err := clt.iface.Write(hp.payload)
            logger.Debug("n: %d, len: %d", n, len(hp.payload))
            if err != nil {
                logger.Error(err.Error())
                return
            }
        }
    }()

    buf := make([]byte, MTU)
    for {
        n, err := clt.iface.Read(buf)
        if err != nil {
            logger.Error(err.Error())
            return
        }
        frame := make([]byte, n)
        copy(frame, buf[0:n])

        // frame -> fromIface -> toNet
        clt.fromIface <- frame
    }
}

func (clt *HopClient) handleUDP(server string, idx int) {
    udpAddr, _ := net.ResolveUDPAddr("udp", server)
    udpConn, _ := net.DialUDP("udp", nil, udpAddr)

    logger.Debug(udpConn.RemoteAddr().String())

    // add route through net gateway
    if clt.config.regw {
        if udpAddr, ok := udpConn.RemoteAddr().(*net.UDPAddr); ok {
            srvIP := udpAddr.IP.To4()
            if srvIP != nil {
                srvDest := srvIP.String() + "/32"
                addRoute(srvDest, net_gateway, net_nic)
            }
        }
    }

    status := HOP_STAT_INIT

    // forward iface frames to network
    go func() {
        for {
            frame := <-clt.toNet
            // logger.Debug("New iface frame")
            // dest := waterutil.IPv4Destination(frame)
            // logger.Debug("ip dest: %v", dest)

            hp := new(HopPacket)
            switch status {
            case HOP_STAT_INIT:
                hp.Flag = HOP_FLG_PSH
            }
            hp.payload = frame
            udpConn.Write(hp.Pack())
        }
    }()

    buf := make([]byte, IFACE_BUFSIZE)

    for {
        n, err := udpConn.Read(buf)
        logger.Debug("New UDP Packet, len: %d", n)
        if err != nil {
            logger.Error(err.Error())
            return
        }

        hp, _ := unpackHopPacket(buf[:n])

        if hp.Flag == HOP_FLG_ACK {
            status = HOP_STAT_WORKING
            logger.Info("Connection Initialized")
        }

        // pack -> fromNet -> toIface
        clt.fromNet <- hp
    }
}

func (clt *HopClient) cleanUp() {
    c := make(chan os.Signal, 1)
    signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
    <-c

    for _, route := range clt.config.routes {
        delRoute(route.dest)
    }
    os.Exit(0)
}
