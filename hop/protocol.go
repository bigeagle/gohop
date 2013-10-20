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

// gohop packet format and session protocols

package hop

import (
    "net"
    "bytes"
    "encoding/binary"
    "crypto/rand"
)

const (
    HOP_REQ uint8 = 0x20
    HOP_ACK uint8 = 0xAC
    HOP_DAT uint8 = 0xDA

    HOP_FLG_PSH byte = 0x80  // port knocking and heartbeat
    HOP_FLG_HSH byte = 0x60  // handshaking
    HOP_FLG_FIN byte = 0x40  // finish session
    HOP_FLG_MFR byte = 0x20  // more fragments
    HOP_FLG_ACK byte = 0x08  // acknowledge
    HOP_FLG_DAT byte = 0x00  // acknowledge

    HOP_STAT_INIT int32 = iota  // initing
    HOP_STAT_HANDSHAKE          // handeshaking
    HOP_STAT_WORKING            // working
    HOP_STAT_FIN                // finishing

    HOP_HDR_LEN int = 8
)

type hopPacketHeader struct {
    Flag byte
    Seq  uint32
    Frag uint8
    Dlen uint16
}

type HopPacket struct {
    hopPacketHeader
    payload  []byte
    noise []byte
    buf []byte
}

var cipher *hopCipher

func (p *HopPacket) Pack() []byte {
    p.Dlen = uint16(len(p.payload))
    var buf *bytes.Buffer
    if p.buf != nil {
        // reduce memcopy
        buf = bytes.NewBuffer(p.buf[:0])
        binary.Write(buf, binary.BigEndian, p.hopPacketHeader)
    } else {
        buf = bytes.NewBuffer(make([]byte, 0, HOP_HDR_LEN+len(p.payload)+len(p.noise)))
        binary.Write(buf, binary.BigEndian, p.hopPacketHeader)
        buf.Write(p.payload)
        buf.Write(p.noise)
        p.buf = buf.Bytes()
    }
    return cipher.encrypt(p.buf)
}

func (p *HopPacket) setPayload(d []byte) {
    p.payload = d
}

func (p *HopPacket) addNoise(n int) {
    p.noise = make([]byte, n)
    rand.Read(p.noise)
}

func unpackHopPacket(b []byte) (*HopPacket, error) {
    iv := b[:cipherBlockSize]
    ctext := b[cipherBlockSize:]
    buf := bytes.NewBuffer(cipher.decrypt(iv, ctext))

    p := new(HopPacket)
    binary.Read(buf, binary.BigEndian, &p.hopPacketHeader)
    p.payload = make([]byte, p.Dlen)
    buf.Read(p.payload)
    return p, nil
}


func udpAddrHash(a *net.UDPAddr) [6]byte{
    var b [6]byte
    copy(b[:4], []byte(a.IP)[:4])
    p := uint16(a.Port)
    b[4] = byte((p >> 8) & 0xFF)
    b[5] = byte(p & 0xFF)
    return b
}

type hUDPAddr struct {
    u *net.UDPAddr
    hash [6]byte
}

func newhUDPAddr(a *net.UDPAddr) *hUDPAddr {
    return &hUDPAddr{a, udpAddrHash(a)}
}

// gohop Peer is a record of a peer's available UDP addrs
type HopPeer struct {
    id         uint64
    ip         net.IP
    addrs      map[[6]byte]int
    _addrs_lst []*hUDPAddr // i know it's ugly!
    seq        uint32
    state      int32
    hsDone     chan byte
}

func newHopPeer(id uint64, addr *net.UDPAddr) *HopPeer {
    hp := new(HopPeer)
    hp.id = id
    hp._addrs_lst = make([]*hUDPAddr, 0)
    hp.addrs = make(map[[6]byte]int)
    hp.state = HOP_STAT_INIT
    hp.seq = 0

    a := newhUDPAddr(addr)
    hp._addrs_lst = append(hp._addrs_lst, a)
    hp.addrs[a.hash] = 1

    return hp
}

func (h *HopPeer) addr() (*net.UDPAddr, bool) {
    addr := randAddr(h._addrs_lst)
    _, ok := h.addrs[addr.hash]

    return addr.u, ok
}

func (h *HopPeer) insertAddr(addr *net.UDPAddr) {
    a := newhUDPAddr(addr)
    if _, found := h.addrs[a.hash]; !found {
        h.addrs[a.hash] = 1
        h._addrs_lst = append(h._addrs_lst, a)
        //logger.Info("%v %d", addr, len(h._addrs_lst))
    }
}
