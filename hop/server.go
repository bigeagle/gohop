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
    "bytes"
    "encoding/binary"
    "fmt"
    "github.com/bigeagle/water"
    "github.com/bigeagle/water/waterutil"
    "net"
    "os"
    "os/signal"
    "sync"
    "sync/atomic"
    "syscall"
    "time"
)

// a udpPacket
type udpPacket struct {
    // client's addr
    addr *net.UDPAddr
    // data
    data []byte
    // channel
    channel int
}

type HopServer struct {
    // config
    cfg *HopServerConfig
    // interface
    iface *water.Interface
    // subnet
    ipnet *net.IPNet
    // IP Pool
    ippool *hopIPPool
    // client peers, key is the mac address, value is a HopPeer record
    peers map[uint64]*HopPeer

    // channel to put in packets read from udpsocket
    fromNet chan *udpPacket
    // channel to put packets to send through udpsocket
    toNet []chan *udpPacket
    // channel to put frames read from tun/tap device
    fromIface    chan []byte
    toIface      chan *HopPacket
    _lock        sync.RWMutex
    _chanBufSize int
}

func NewServer(cfg *HopServerConfig) error {
    var err error
    logger.Debug("%v", cfg)

    if len(cfg.Key) > 0 {
        cipher, err = newHopCipher([]byte(cfg.Key))
        if err != nil {
            return err
        }
    }

    if cfg.MTU != 0 {
        MTU = cfg.MTU
    }

    hopServer := new(HopServer)
    hopServer._chanBufSize = 256
    hopServer.fromNet = make(chan *udpPacket, hopServer._chanBufSize)
    hopServer.fromIface = make(chan []byte, hopServer._chanBufSize)
    hopServer.toIface = make(chan *HopPacket, hopServer._chanBufSize)
    hopServer.peers = make(map[uint64]*HopPeer)
    hopServer.cfg = cfg
    hopServer.toNet = make([]chan *udpPacket, (cfg.HopEnd - cfg.HopStart + 1))
    hopServer.ippool = new(hopIPPool)

    iface, err := newTun("")
    if err != nil {
        return err
    }
    hopServer.iface = iface
    ip, subnet, err := net.ParseCIDR(cfg.Addr)
    err = setTunIP(iface, ip, subnet)
    if err != nil {
        return err
    }
    hopServer.ipnet = &net.IPNet{ip, subnet.Mask}
    hopServer.ippool.subnet = subnet

    if cfg.FixMSS {
        fixMSS(iface.Name(), true)
    }

    // traffic morpher
    switch cfg.MorphMethod {
    case "randsize":
        m := newRandMorpher(MTU)
        hopFrager = newHopFragmenter(m)
        logger.Info("Using RandomSize Morpher")
    default:
        logger.Info("No Traffic Morphing")
    }

    // forward device frames to socket and socket packets to device
    go hopServer.forwardFrames()

    // go func() {
    //     defer hopServer.cleanUp()
    //     redirectPort(cfg.HopRange, cfg.Port)
    // }()
    go hopServer.cleanUp()

    // serve for multiple ports
    for idx, port := 0, cfg.HopStart; port <= cfg.HopEnd; port++ {
        go hopServer.listenAndServe(cfg.ListenAddr, fmt.Sprintf("%d", port), idx)
        idx++
    }

    // peer Timeout Watcher
    go hopServer.peerTimeoutWatcher()

    logger.Info("Recieving iface frames")

    // handle interface

    go func() {
        for {
            hp := <-hopServer.toIface
            // logger.Debug("New Net packet to device")
            // logger.Debug("toIface : %v", hp.payload)
            _, err := iface.Write(hp.payload)
            // logger.Debug("n: %d, len: %d", n, len(hp.payload))
            if err != nil {
                logger.Error(err.Error())
                return
            }
        }
    }()

    buf := make([]byte, IFACE_BUFSIZE)
    for {
        n, err := iface.Read(buf)
        if err != nil {
            return err
        }

        hpbuf := make([]byte, n+HOP_HDR_LEN)
        copy(hpbuf[HOP_HDR_LEN:], buf[:n])
        hopServer.fromIface <- hpbuf
    }

}

func (srv *HopServer) listenAndServe(addr string, port string, idx int) {
    port = addr + ":" + port
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

    toNet := make(chan *udpPacket, srv._chanBufSize)

    go func() {
        defer srv._lock.Unlock()
        srv._lock.Lock()
        srv.toNet[idx] = toNet
        // logger.Debug("Listening on port %s", port)
    }()

    go func() {
        for {
            packet := <-toNet
            // logger.Debug("index: %d, port: %s", idx, port)
            // logger.Debug("toClient: %v", packet.data)
            _, err := udpConn.WriteTo(packet.data, packet.addr)
            if err != nil {
                logger.Error("ToNet Err: %v", err)
            }
        }
    }()

    for {
        func() {
            defer func() {
                if _err := recover(); _err != nil {
                    logger.Error("ReadFromUDP failed: %v", _err)
                }
            }()
            var plen int
            packet := new(udpPacket)
            packet.channel = idx
            buf := make([]byte, IFACE_BUFSIZE)
            // logger.Debug("Recieving packet %s", port)
            plen, packet.addr, err = udpConn.ReadFromUDP(buf)
            // logger.Debug("New UDP Packet from: %v", packet.addr)

            packet.data = buf[:plen]
            if err != nil {
                logger.Error(err.Error())
                return
            }

            srv.fromNet <- packet
        }()
    }

}

func (srv *HopServer) forwardFrames() {

    // packet map
    pktHandle := map[byte](func(*udpPacket, *HopPacket)){
        HOP_FLG_PSH:               srv.handleKnock,
        HOP_FLG_HSH:               srv.handleHandshake,
        HOP_FLG_HSH | HOP_FLG_ACK: srv.handleHandshakeAck,
        HOP_FLG_DAT:               srv.handleDataPacket,
        HOP_FLG_DAT | HOP_FLG_MFR: srv.handleDataPacket,
        HOP_FLG_FIN:               srv.handleFinish,
    }

    for {
        select {
        case pack := <-srv.fromIface:
            // logger.Debug("New iface Frame")
            // first byte is left for opcode
            frame := pack[HOP_HDR_LEN:]
            dest := waterutil.IPv4Destination(frame).To4()
            mkey := ip4_uint64(dest)

            // logger.Debug("fromIfc: ip dest: %v, data:%v", dest, frame)
            if hpeer, found := srv.peers[mkey]; found {
                srv.bufferToClient(hpeer, pack)
            } else {
                // logger.Debug("fromIface : client peer with key %d not found", mkey)
            }

        case packet := <-srv.fromNet:
            packet.handleFunction(pktHandle)
        }
    }
}

func (packet *udpPacket) handleFunction(pktHandle map[byte](func(*udpPacket, *HopPacket))) {

    defer func() {
        if err := recover(); err != nil {
            logger.Error("handleFunction failed: %v, packet addr:%v", err, packet.addr)
        }
    }()

    // logger.Debug("Receive data[%d]:%v", len(packet.data), packet.data)

    hPack, err := unpackHopPacket(packet.data) //协议包拆包
    if err == nil {
        // logger.Debug("fromClient: %v", hPack.String())
        if hPack.Flag != 0 {
            logger.Debug("New UDP Packet [%v] from: %v", hPack.Flag, packet.addr)
        }

        if handle_func, ok := pktHandle[hPack.Flag]; ok {
            handle_func(packet, hPack) //事件处理
        } else {
            logger.Error("Unkown flag: %x", hPack.Flag)
        }
    } else {
        logger.Error(err.Error())
    }
}

func (srv *HopServer) toClient(peer *HopPeer, flag byte, payload []byte, noise bool) {
    hp := new(HopPacket)
    hp.Seq = peer.Seq()
    hp.Flag = flag
    hp.payload = payload

    if addr, idx, ok := peer.addr(); ok {
        // logger.Debug("toClient ： peer: %v", addr)
        upacket := &udpPacket{addr, hp.Pack(), idx}
        peer.bytes_down += uint32(len(upacket.data))
        srv.toNet[idx] <- upacket
    } else {
        logger.Debug("toClient ： peer not found sid:%d, uid:%d, ip:%d", peer.id>>32, peer.uid, peer.ip)
    }
}

func (srv *HopServer) bufferToClient(peer *HopPeer, buf []byte) {
    if hopFrager == nil {
        // if no traffic morphing
        hp := new(HopPacket)
        hp.Flag = HOP_FLG_DAT
        hp.buf = buf
        hp.payload = buf[HOP_HDR_LEN:]
        hp.Seq = peer.Seq()

        if addr, idx, ok := peer.addr(); ok {
            // logger.Debug("bufferToClient ： peer: %v", addr)
            upacket := &udpPacket{addr, hp.Pack(), idx}
            peer.bytes_down += uint32(len(upacket.data))
            srv.toNet[idx] <- upacket
        }
    } else {
        // with traffic morphing
        frame := buf[HOP_HDR_LEN:]
        packets := hopFrager.Fragmentate(peer, frame)
        for _, hp := range packets {
            if addr, idx, ok := peer.addr(); ok {
                upacket := &udpPacket{addr, hp.Pack(), idx}
                peer.bytes_down += uint32(len(upacket.data))
                srv.toNet[idx] <- upacket
            }
        }
    }
}

func (srv *HopServer) handleKnock(u *udpPacket, hp *HopPacket) {
    sid := uint64(binary.BigEndian.Uint32(hp.payload[:4]))
    sid = (sid << 32) & uint64(0xFFFFFFFF00000000)
    hpeer, ok := srv.peers[sid]
    if !ok {
        hpeer = newHopPeer(sid, srv, u.addr, u.channel)
        srv.peers[sid] = hpeer
    } else {
        hpeer.insertAddr(u.addr, u.channel)
        logger.Debug("[knock] from client %v, sid:%d, uid:%d, gid:%d", u.addr, sid>>32, hpeer.uid, hpeer.gmid)
        if hpeer.state == HOP_STAT_WORKING {
            srv.toClient(hpeer, HOP_FLG_PSH, []byte{0}, true)
        }
    }
    hpeer.bytes_up += uint32(len(u.data))
    hpeer.lastConnTime = time.Now()
}

func (srv *HopServer) handleHandshake(u *udpPacket, hp *HopPacket) {
    tms := []uint32{0, 0, 0}
    for i := 0; i*4+4 <= int(hp.Dlen); i++ {
        tms[i] = binary.BigEndian.Uint32(hp.payload[i*4 : i*4+4])
    }
    sid := uint64(tms[0])
    gmid := tms[1]
    uid := tms[2]

    logger.Debug("[handshake] from client %v, sid:%d, uid:%d, gmid:%d", u.addr, sid, uid, gmid)
    sid = (sid << 32) & uint64(0xFFFFFFFF00000000)

    hpeer, ok := srv.peers[sid]
    if !ok {
        hpeer = newHopPeer(sid, srv, u.addr, u.channel)
        srv.peers[sid] = hpeer
    } else {
        hpeer.insertAddr(u.addr, u.channel)
    }

    hpeer.gmid = gmid
    hpeer.uid = uid
    hpeer.bytes_up += uint32(len(u.data))
    hpeer.lastConnTime = time.Now()

    cltIP, err := srv.ippool.next()
    if err != nil {
        msg := fmt.Sprintf("%s", err.Error())
        srv.toClient(hpeer, HOP_FLG_HSH|HOP_FLG_FIN, []byte(msg), true)
        delete(srv.peers, sid)
        logger.Error("Have no IP to allocation")
    } else {
        hpeer.ip = cltIP.IP.To4()
        buf := bytes.NewBuffer(make([]byte, 0, 5))
        //set client ip
        buf.Write([]byte(hpeer.ip))
        siz, _ := cltIP.Mask.Size()
        // buf.Write([]byte(cltIP.Mask))
        buf.WriteByte(byte(siz))

        //set client dns
        for i := 0; i < 2; i++ {
            if ip, _, err := net.ParseCIDR(srv.cfg.DNS[i]); err != nil {
                buf.Write([]byte{0, 0, 0, 0, 0})
            } else {
                ip = ip.To4()
                buf.Write([]byte(ip))
                buf.WriteByte(0)
            }
        }

        //set client route
        routes := srv.routeList(gmid)
        for i := 0; i < len(routes) && i <= 256; i++ {
            buf.Write(routes[i][:])
        }

        key := ip4_uint64(hpeer.ip)

        logger.Debug("assign address %s route; sid:%d, uid:%d, gid:%d", cltIP, hpeer.id>>32, hpeer.uid, hpeer.gmid)
        srv.peers[key] = hpeer
        atomic.StoreInt32(&hpeer.state, HOP_STAT_HANDSHAKE)
        srv.toClient(hpeer, HOP_FLG_HSH|HOP_FLG_ACK, buf.Bytes(), true)
        hpeer.hsDone = make(chan byte)
        go func() {
            for i := 0; i < 5; i++ {
                select {
                case <-hpeer.hsDone:
                    logger.Debug("hperr.hsDone; sid:%d, uid:%d, gid:%d", hpeer.id>>32, hpeer.uid, hpeer.gmid)
                    // hpeer.state = HOP_STAT_WORKING
                    return
                case <-time.After(2 * time.Second):
                    logger.Debug("Client Handshake Timeout; sid:%d, uid:%d, gid:%d", hpeer.id>>32, hpeer.uid, hpeer.gmid)
                    srv.toClient(hpeer, HOP_FLG_HSH|HOP_FLG_ACK, buf.Bytes(), true)
                }
            }
            // timeout,  kick
            srv.toClient(hpeer, HOP_FLG_HSH|HOP_FLG_FIN, []byte{0}, true)
            srv.toClient(hpeer, HOP_FLG_HSH|HOP_FLG_FIN, []byte{0}, true)
            srv.toClient(hpeer, HOP_FLG_HSH|HOP_FLG_FIN, []byte{0}, true)

            srv.ippool.relase(hpeer.ip)
            delete(srv.peers, sid)
            delete(srv.peers, key)

        }()
    }

}

func (srv *HopServer) handleHandshakeAck(u *udpPacket, hp *HopPacket) {
    sid := uint64(binary.BigEndian.Uint32(hp.payload[:4]))
    sid = (sid << 32) & uint64(0xFFFFFFFF00000000)
    hpeer, ok := srv.peers[sid]
    if !ok {
        return
    }
    hpeer.bytes_up += uint32(len(u.data))
    hpeer.lastConnTime = time.Now()
    logger.Info("Client sid:%d, uid:%d, gid:%d, ip %v Connected. DHCP:%v", sid>>32, hpeer.uid, hpeer.gmid, u.addr, hpeer.ip)

    if ok = atomic.CompareAndSwapInt32(&hpeer.state, HOP_STAT_HANDSHAKE, HOP_STAT_WORKING); ok {
        hpeer.hsDone <- 1
    }
}

func (srv *HopServer) handleDataPacket(u *udpPacket, hp *HopPacket) {
    sid := uint64(hp.Sid)
    sid = (sid << 32) & uint64(0xFFFFFFFF00000000)

    if hpeer, ok := srv.peers[sid]; ok && hpeer.state == HOP_STAT_WORKING {
        // logger.Debug("n hpeer addrs: %v", len(hpeer._addrs_lst))
        // hpeer.insertAddr(u.addr, u.channel)
        if ok, ip := srv.routeMatch(hpeer, hp); ok {
            hpeer.lastConnTime = time.Now()
            hpeer.recvBuffer.Push(hp)
        } else {
            logger.Info("DataPacket not routed to %v", ip)
        }
        hpeer.bytes_up += uint32(len(u.data))
    } else {
        peer := newHopPeer(sid, srv, u.addr, u.channel)
        srv.toClient(peer, HOP_FLG_FIN|HOP_FLG_ACK, []byte{0}, false)
    }

}

func (srv *HopServer) handleFinish(u *udpPacket, hp *HopPacket) {
    sid := uint64(binary.BigEndian.Uint32(hp.payload[:4]))
    logger.Info("releasing client %v, sid:%d", u.addr, sid)
    sid = (sid << 32) & uint64(0xFFFFFFFF00000000)

    srv.deletePeer(sid)
}

func (srv *HopServer) deletePeer(sid uint64) {
    hpeer, ok := srv.peers[sid]
    if !ok {
        return
    }
    srv.toClient(hpeer, HOP_FLG_FIN|HOP_FLG_ACK, []byte{0}, false)
    key := ip4_uint64(hpeer.ip)
    srv.ippool.relase(hpeer.ip)

    // log user info
    if sid>>32 > 0 {
        logger.Info("UserBytes sid:%d, uid:%d, gid:%d, up:%d, down:%d", hpeer.id>>32, hpeer.uid, hpeer.gmid, hpeer.bytes_up, hpeer.bytes_down)
    }
    delete(srv.peers, sid)
    delete(srv.peers, key)
}

func (srv *HopServer) cleanUp() {
    c := make(chan os.Signal, 1)
    signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
    <-c

    clearMSS(srv.iface.Name(), true)
    os.Exit(0)
}

func (srv *HopServer) routeList(gmid uint32) [][5]byte {
    var routes [][5]byte = make([][5]byte, 0, 5)
    for _, k := range []uint32{1, gmid} {
        if list, ok := srv.cfg.RouteList[k]; ok {
            routes = append(routes, list...)
        }
    }
    if len(routes) == 0 {
        routes = [][5]byte{[5]byte{254, 254, 254, 254, 32}}
    }
    return routes
}

func (srv *HopServer) routeMatch(peer *HopPeer, hp *HopPacket) (bool, net.IP) {
    ip := waterutil.IPv4Destination(hp.payload).To4()
    list := srv.routeList(peer.gmid)
    intip := binary.BigEndian.Uint32([]byte(ip))
    for _, l := range list {
        routeIp := binary.BigEndian.Uint32(l[:4])
        mask := 32 - l[4]
        if intip >= routeIp && (intip>>mask) == (routeIp>>mask) {
            return true, ip
        }
    }

    return false, ip
}

func (srv *HopServer) peerTimeoutWatcher() {
    for {
        if srv.cfg.PeerTimeout <= 0 {
            return
        }
        time.Sleep(time.Minute)
        count := 0
        timeout := time.Second * time.Duration(srv.cfg.PeerTimeout)
        for sid, hpeer := range srv.peers {
            // logger.Debug("watch:%v", hpeer.lastConnTime)
            if sid>>32 > 0 {
                count++
            }
            conntime := time.Since(hpeer.lastConnTime)
            // logger.Debug("watch:%v %v", conntime.Seconds(), timeout.Seconds())
            if conntime > timeout {
                go srv.deletePeer(sid)
            }
        }
        logger.Info("Ulinks:%d", count)
    }
}
