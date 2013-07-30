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
)

const (
    HOP_REQ uint8 = 0x20
    HOP_ACK uint8 = 0xAC
    HOP_DAT uint8 = 0xDA
)

type HopPacket struct {
    opcode uint8
    frame  []byte
}

var cipher *hopCipher

func (p *HopPacket) Pack() []byte {
    packet := append(p.frame, byte(p.opcode))
    return cipher.encrypt(packet)
}

func unpackHopPacket(b []byte) (*HopPacket, error) {
    iv := b[:cipherBlockSize]
    ctext := b[cipherBlockSize:]
    buf := cipher.decrypt(iv, ctext)

    p := new(HopPacket)
    lst := len(buf) - 1
    p.opcode = uint8(buf[lst])
    p.frame = buf[:lst]
    buf = nil
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
    id         uint32
    addrs      map[[6]byte]int
    _addrs_lst []*hUDPAddr // i know it's ugly!
    inited     bool       // whether a connection is initialized
}

func newHopPeer(id uint32, addr *net.UDPAddr, idx int) *HopPeer {
    hp := new(HopPeer)
    hp.id = id
    hp._addrs_lst = make([]*hUDPAddr, 0)
    hp.addrs = make(map[[6]byte]int)
    hp.inited = false

    a := newhUDPAddr(addr)
    hp._addrs_lst = append(hp._addrs_lst, a)
    hp.addrs[a.hash] = idx

    return hp
}

func (h *HopPeer) addr() (*net.UDPAddr, int, bool) {
    addr := randAddr(h._addrs_lst)
    idx, ok := h.addrs[addr.hash]

    return addr.u, idx, ok
}

func (h *HopPeer) insertAddr(addr *net.UDPAddr, idx int) {
    a := newhUDPAddr(addr)
    if _, found := h.addrs[a.hash]; !found {
        h.addrs[a.hash] = idx
        h._addrs_lst = append(h._addrs_lst, a)
        //logger.Info("%v %d", addr, len(h._addrs_lst))
    }
}
