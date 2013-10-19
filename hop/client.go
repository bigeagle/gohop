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
    "net"
    "os"
    "os/signal"
    "syscall"
    "time"
    "fmt"
    "errors"
    "github.com/bigeagle/water"
)

var net_gateway, net_nic string

type route struct {
    dest, nextHop, iface string
}

type HopClient struct {
    cfg HopClientConfig
    iface  *water.Interface

    toIface chan *HopPacket

    fromNet  *hopPacketBuffer
    toNet chan []byte
}


func NewClient(cfg HopClientConfig) error {
    var err error

    logger.Debug("%v", cfg)
    cipher, err = newHopCipher([]byte(cfg.Key))
    if err != nil {
        return err
    }


    hopClient := new(HopClient)
    hopClient.toIface = make(chan *HopPacket, 32)
    hopClient.toNet = make(chan []byte, 32)
    hopClient.fromNet = newHopPacketBuffer()
    hopClient.cfg = cfg

    iface, err := newTun("", cfg.Addr)
    if err != nil {
        return err
    }

    hopClient.iface = iface

    idx := 0
    for port := cfg.HopStart; port <= cfg.HopEnd; port++ {
        server := fmt.Sprintf("%s:%d", cfg.Server, port)
        go hopClient.handleUDP(server, idx)
        idx += 1
    }



    net_gateway, net_nic, err = getNetGateway()
    logger.Debug("Net Gateway: %s %s", net_gateway, net_nic)
    if err != nil {
        return err
    }

    routeDone := make(chan bool)
    go func() {
        defer hopClient.cleanUp()
        for _, dest := range cfg.Net_gateway {
            addRoute(dest, net_gateway, net_nic)
        }
        routeDone <- true
    }()

    if cfg.Redirect_gateway {
        go func() {
            <-routeDone
            err = redirectGateway(iface.Name(), tun_peer.String())
            if err != nil {
                logger.Error(err.Error())
                return
            }
        }()
    }


    go func() {
        ticker := time.NewTicker(10 * time.Millisecond)
        for {
            <-ticker.C
            hopClient.fromNet.flushToChan(hopClient.toIface)
        }
    }()

    hopClient.handleInterface()

    return errors.New("Not expected to exit")
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
        clt.toNet <- frame
    }
}

func (clt *HopClient) handleUDP(server string, idx int) {
    udpAddr, _ := net.ResolveUDPAddr("udp", server)
    udpConn, _ := net.DialUDP("udp", nil, udpAddr)

    logger.Debug(udpConn.RemoteAddr().String())

    // add route through net gateway
    if clt.cfg.Redirect_gateway {
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

        // logger.Debug("New HopPacket Seq: %d", packet.Seq)
        if err := clt.fromNet.push(hp); err != nil {
            logger.Debug("buffer full, flushing")
            clt.fromNet.flushToChan(clt.toIface)
        }
    }
}

func (clt *HopClient) cleanUp() {
    c := make(chan os.Signal, 1)
    signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
    <-c

    for _, dest := range clt.cfg.Net_gateway {
        delRoute(dest)
    }
    os.Exit(0)
}
