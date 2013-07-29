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

// gohop Peer is a record of a peer's available UDP addrs
type HopPeer struct {
    id         uint32
    addrs      map[string]int
    _addrs_lst []net.Addr // i know it's ugly!
    inited     bool       // whether a connection is initialized
}

func newHopPeer(id uint32, addr net.Addr, idx int) *HopPeer {
    hp := new(HopPeer)
    hp.id = id
    hp._addrs_lst = make([]net.Addr, 0)
    hp.addrs = make(map[string]int)
    hp.inited = false

    hp._addrs_lst = append(hp._addrs_lst, addr)
    hp.addrs[addr.String()] = idx

    return hp
}

func (h *HopPeer) addr() (net.Addr, int, bool) {
    addr := randAddr(h._addrs_lst)
    idx, ok := h.addrs[addr.String()]

    return addr, idx, ok
}

func (h *HopPeer) insertAddr(addr net.Addr, idx int) {
    k := addr.String()
    if _, found := h.addrs[k]; !found {
        h.addrs[k] = idx
        h._addrs_lst = append(h._addrs_lst, addr)
        //logger.Info("%v %d", addr, len(h._addrs_lst))
    }
}
