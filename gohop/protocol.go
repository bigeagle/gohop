// gohop packet format and session protocols

package gohop

import (
    "bytes"
    "encoding/binary"
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

func (p *HopPacket) Pack() []byte {
    buf := bytes.NewBuffer(make([]byte, 0, len(p.frame)+1))
    binary.Write(buf, binary.BigEndian, p.opcode)
    buf.Write(p.frame)
    return buf.Bytes()
}

func unpackHopPacket(b []byte) (*HopPacket, error) {
    p := new(HopPacket)
    p.opcode = uint8(b[0])
    p.frame = b[1:]
    return p, nil
}

// gohop Peer is a record of a peer's available UDP addrs
type HopPeer struct {
    id         uint64
    addrs      map[net.Addr]int
    _addrs_lst []net.Addr   // i know it's ugly!
    inited     bool         // whether a connection is initialized
}

func newHopPeer(id uint64, addr net.Addr, idx int) *HopPeer {
    hp := new(HopPeer)
    hp.id = id
    hp._addrs_lst = make([]net.Addr, 0)
    hp.addrs = make(map[net.Addr]int)
    hp.inited = false

    hp._addrs_lst = append(hp._addrs_lst, addr)
    hp.addrs[addr] = idx

    return hp
}

func (h *HopPeer) addr() (net.Addr, int, bool) {

    addr := randAddr(h._addrs_lst)
    idx, ok := h.addrs[addr]

    return addr, idx, ok
}

func (h *HopPeer) insertAddr(addr net.Addr, idx int) {
    if _, found := h.addrs[addr]; !found {
        h.addrs[addr] = idx
        h._addrs_lst = append(h._addrs_lst, addr)
    }
}
