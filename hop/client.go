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
    "crypto/rand"
    mrand "math/rand"
    "github.com/bigeagle/water"
    "sync/atomic"
)

var net_gateway, net_nic string

type route struct {
    dest, nextHop, iface string
}

type HopClient struct {
    // config
    cfg HopClientConfig
    // interface
    iface  *water.Interface
    // ip addr
    ip net.IP

    // session id
    sid [4]byte
    // session state
    state int32

    // net to interface
    toIface chan *HopPacket
    // buffer for packets from net
    recvBuf  *hopPacketBuffer
    // channel to send frames to net
    toNet chan *HopPacket

    handshakeDone chan byte
    finishAck chan byte
    // state variable to ensure serverRoute added
    srvRoute int32
    // routes need to be clean in the end
    routes []string
    // sequence number
    seq uint32
}


func NewClient(cfg HopClientConfig) error {
    var err error

    logger.Debug("%v", cfg)
    cipher, err = newHopCipher([]byte(cfg.Key))
    if err != nil {
        return err
    }


    hopClient := new(HopClient)
    rand.Read(hopClient.sid[:])
    hopClient.toIface = make(chan *HopPacket, 32)
    hopClient.toNet = make(chan *HopPacket, 32)
    hopClient.recvBuf = newHopPacketBuffer(hopClient.toIface, bufferTimeout)
    hopClient.cfg = cfg
    hopClient.state = HOP_STAT_INIT
    hopClient.handshakeDone = make(chan byte)
    hopClient.finishAck = make(chan byte)
    hopClient.srvRoute = 0
    hopClient.routes = make([]string, 0, 1024)

    switch cfg.MorphMethod {
    case "randsize":
        m := newRandMorpher(MTU)
        hopFrager = newHopFragmenter(m)
        logger.Info("Using RandomSize Morpher")
    default:
        logger.Info("No Traffic Morphing")
    }

    go hopClient.cleanUp()

    iface, err := newTun("")
    if err != nil {
        return err
    }
    hopClient.iface = iface

    net_gateway, net_nic, err = getNetGateway()
    logger.Debug("Net Gateway: %s %s", net_gateway, net_nic)
    if err != nil {
        return err
    }

    for port := cfg.HopStart; port <= cfg.HopEnd; port++ {
        server := fmt.Sprintf("%s:%d", cfg.Server, port)
        go hopClient.handleUDP(server)
    }


    // wait until handshake done
    res := <-hopClient.handshakeDone
    if res == 0 {
        return errors.New("Handshake Fail")
    }

    routeDone := make(chan bool)
    go func() {
        for _, dest := range cfg.Net_gateway {
            addRoute(dest, net_gateway, net_nic)
            hopClient.routes = append(hopClient.routes, dest)
        }
        if cfg.Redirect_gateway {
            routeDone <- true
        }
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

    hopClient.handleInterface()

    return errors.New("Not expected to exit")
}

func (clt *HopClient) handleInterface() {
    // network packet to interface
    go func() {
        for {
            hp := <-clt.toIface
            // logger.Debug("New Net packet to device")
            _, err := clt.iface.Write(hp.payload)
            // logger.Debug("n: %d, len: %d", n, len(hp.payload))
            if err != nil {
                logger.Error(err.Error())
                return
            }
        }
    }()

    frame := make([]byte, MTU)
    for {
        n, err := clt.iface.Read(frame)
        if err != nil {
            logger.Error(err.Error())
            return
        }

        buf := make([]byte, n+HOP_HDR_LEN)
        copy(buf[HOP_HDR_LEN:], frame[:n])
        if hopFrager == nil {
            // if no traffic morphing
            // Hack to reduce memcopy
            hp := new(HopPacket)
            hp.payload = buf[HOP_HDR_LEN:]
            hp.buf = buf
            hp.Seq = clt.Seq()
            clt.toNet <- hp

        } else {
            // with traffic morphing
            packets := hopFrager.Fragmentate(clt, buf[HOP_HDR_LEN:])
            for _, hp := range(packets) {
                clt.toNet <- hp
            }
        }

    }
}

func (clt *HopClient) handleUDP(server string) {
    udpAddr, _ := net.ResolveUDPAddr("udp", server)
    udpConn, _ := net.DialUDP("udp", nil, udpAddr)

    logger.Debug(udpConn.RemoteAddr().String())

    // packet map
    pktHandle := map[byte](func(*net.UDPConn, *HopPacket)){
        HOP_FLG_HSH | HOP_FLG_ACK: clt.handleHandshakeAck,
        HOP_FLG_HSH | HOP_FLG_FIN: clt.handleHandshakeError,
        HOP_FLG_DAT: clt.handleDataPacket,
        HOP_FLG_DAT | HOP_FLG_MFR: clt.handleDataPacket,
        HOP_FLG_FIN | HOP_FLG_ACK: clt.handleFinishAck,
    }

    clt.knock(udpConn)
    go func() {
        n := mrand.Intn(1000)
        time.Sleep(time.Duration(n) * time.Millisecond)
        clt.handeshake(udpConn)
    }()

    // add route through net gateway
    if clt.cfg.Redirect_gateway {
        if atomic.CompareAndSwapInt32(&clt.srvRoute, 0, 1) {
            if udpAddr, ok := udpConn.RemoteAddr().(*net.UDPAddr); ok {
                srvIP := udpAddr.IP.To4()
                if srvIP != nil {
                    srvDest := srvIP.String() + "/32"
                    addRoute(srvDest, net_gateway, net_nic)
                    clt.routes = append(clt.routes, srvDest)
                }
            }
        }
    }

    // forward iface frames to network
    go func() {
        for {
            hp := <-clt.toNet
            hp.setSid(clt.sid)
            // logger.Debug("New iface frame")
            // dest := waterutil.IPv4Destination(frame)
            // logger.Debug("ip dest: %v", dest)

            udpConn.Write(hp.Pack())
        }
    }()


    buf := make([]byte, IFACE_BUFSIZE)
    for {
        n, err := udpConn.Read(buf)
        // logger.Debug("New UDP Packet, len: %d", n)
        if err != nil {
            logger.Error(err.Error())
            return
        }

        hp, err := unpackHopPacket(buf[:n])
        if err != nil {
            continue
        }
        if handle_func, ok := pktHandle[hp.Flag]; ok {
            handle_func(udpConn, hp)
        } else {
            logger.Error("Unkown flag: %x", hp.Flag)
        }
    }
}

func (clt *HopClient) Seq() uint32 {
    return atomic.AddUint32(&clt.seq, 1)
}

func (clt *HopClient) toServer(u *net.UDPConn, flag byte, payload []byte, noise bool) {
    hp := new(HopPacket)
    hp.Flag = flag
    hp.Seq = clt.Seq()
    hp.setPayload(payload)
    if noise {
        hp.addNoise(mrand.Intn(MTU-64-len(payload)))
    }
    u.Write(hp.Pack())
}

// knock server port
func (clt *HopClient) knock(u *net.UDPConn) {
    clt.toServer(u, HOP_FLG_PSH, clt.sid[:], true)
}

// handshake with server
func (clt *HopClient) handeshake(u *net.UDPConn) {
    res := atomic.CompareAndSwapInt32(&clt.state, HOP_STAT_INIT, HOP_STAT_HANDSHAKE)
    // logger.Debug("raced for handshake: %v", res)

    if res {
        logger.Info("start handeshaking")
        clt.toServer(u, HOP_FLG_HSH, clt.sid[:], true)
    }
}

// finish session
func (clt *HopClient) finishSession() {
    logger.Info("Finishing Session")
    atomic.StoreInt32(&clt.state, HOP_STAT_FIN)
    hp := new(HopPacket)
    hp.Flag = HOP_FLG_FIN
    hp.setPayload(clt.sid[:])
    hp.Seq = clt.Seq()
    clt.toNet <- hp
    clt.toNet <- hp
    clt.toNet <- hp
}


// handle handeshake ack
func (clt *HopClient) handleHandshakeAck(u *net.UDPConn, hp *HopPacket) {
    if atomic.LoadInt32(&clt.state) == HOP_STAT_HANDSHAKE {
        _ip, _net, _mask := make([]byte, 4), make([]byte, 4), make([]byte, 4)
        copy(_ip, hp.payload[:4])
        copy(_net, hp.payload[:4])
        copy(_mask, hp.payload[4:8])
        logger.Debug("%v", hp.payload)
        _net[3] = 0

        ip := net.IP(_ip)
        subnet := &net.IPNet{_net, _mask}
        setTunIP(clt.iface, ip, subnet)

        res := atomic.CompareAndSwapInt32(&clt.state, HOP_STAT_HANDSHAKE, HOP_STAT_WORKING)
        if !res {
            logger.Error("Client state not expected: %d", clt.state)
        }
        logger.Info("Session Initialized")
        clt.handshakeDone <- 1
    }

    logger.Debug("Handshake Ack to Server")
    clt.toServer(u, HOP_FLG_HSH | HOP_FLG_ACK, clt.sid[:], true)
}

// handle handshake fail
func (clt *HopClient) handleHandshakeError(u *net.UDPConn, hp *HopPacket) {
    clt.handshakeDone <- 0
}


// handle data packet
func (clt *HopClient) handleDataPacket(u *net.UDPConn, hp *HopPacket) {
    // logger.Debug("New HopPacket Seq: %d", packet.Seq)
    clt.recvBuf.Push(hp)
}

// handle finish ack
func (clt *HopClient) handleFinishAck(u *net.UDPConn, hp *HopPacket) {
    clt.finishAck <- byte(1)
}


func (clt *HopClient) cleanUp() {
    c := make(chan os.Signal, 1)
    signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
    <-c
    logger.Info("Cleaning Up")

    if clt.cfg.Redirect_gateway {
        delRoute("0.0.0.0/1")
        delRoute("128.0.0.0/1")
    }

    timeout := time.After(5 * time.Second)
    if clt.state != HOP_STAT_INIT {
        clt.finishSession()
    }

    select {
    case <-clt.finishAck:
        logger.Info("Finish Acknowledged")
    case <-timeout:
        logger.Info("Timeout, give up")
    }

    for _, dest := range clt.routes {
        delRoute(dest)
    }

    os.Exit(0)
}
