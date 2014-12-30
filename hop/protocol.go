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
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	HOP_REQ uint8 = 0x20
	HOP_ACK uint8 = 0xAC
	HOP_DAT uint8 = 0xDA

	HOP_FLG_PSH byte = 0x80 // port knocking and heartbeat
	HOP_FLG_HSH byte = 0x40 // handshaking
	HOP_FLG_FIN byte = 0x20 // finish session
	HOP_FLG_MFR byte = 0x08 // more fragments
	HOP_FLG_ACK byte = 0x04 // acknowledge
	HOP_FLG_DAT byte = 0x00 // acknowledge

	HOP_STAT_INIT      int32 = iota // initing
	HOP_STAT_HANDSHAKE              // handeshaking
	HOP_STAT_WORKING                // working
	HOP_STAT_FIN                    // finishing

	HOP_HDR_LEN int = 16

	HOP_PROTO_VERSION byte = 0x01 // protocol version
)

type hopPacketHeader struct {
	Flag       byte
	Seq        uint32
	Plen       uint16
	FragPrefix uint16
	Frag       uint8
	Sid        uint32
	Dlen       uint16
}

func (p hopPacketHeader) String() string {
	flag := make([]string, 0, 8)
	if (p.Flag^HOP_FLG_MFR == 0) || (p.Flag == 0) {
		flag = append(flag, "DAT")
	}
	if p.Flag&HOP_FLG_PSH != 0 {
		flag = append(flag, "PSH")
	}
	if p.Flag&HOP_FLG_HSH != 0 {
		flag = append(flag, "HSH")
	}
	if p.Flag&HOP_FLG_FIN != 0 {
		flag = append(flag, "FIN")
	}
	if p.Flag&HOP_FLG_ACK != 0 {
		flag = append(flag, "ACK")
	}
	if p.Flag&HOP_FLG_MFR != 0 {
		flag = append(flag, "MFR")
	}

	sflag := strings.Join(flag, " | ")
	return fmt.Sprintf(
		"{Flag: %s, Seq: %d, Plen: %d, Prefix: %d, Frag: %d, Dlen: %d}",
		sflag, p.Seq, p.Plen, p.FragPrefix, p.Frag, p.Dlen,
	)
}

type HopPacket struct {
	hopPacketHeader
	payload []byte
	noise   []byte
	buf     []byte
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
		buf = bytes.NewBuffer(make([]byte, 0, p.Size()))
		binary.Write(buf, binary.BigEndian, p.hopPacketHeader)
		buf.Write(p.payload)
		buf.Write(p.noise)
		p.buf = buf.Bytes()
	}
	return cipher.encrypt(p.buf)
}

func (p *HopPacket) Size() int {
	return HOP_HDR_LEN + len(p.payload) + len(p.noise)
}

func (p *HopPacket) setPayload(d []byte) {
	p.payload = d
	p.Dlen = uint16(len(p.payload))
}

func (p *HopPacket) addNoise(n int) {
	if p.buf != nil {
		s := HOP_HDR_LEN + len(p.payload)
		p.noise = p.buf[s:len(p.buf)]
	} else {
		p.noise = make([]byte, n)
	}
	rand.Read(p.noise)
}

func (p *HopPacket) setSid(sid [4]byte) {
	p.Sid = binary.BigEndian.Uint32(sid[:])
}

func (p *HopPacket) String() string {
	return fmt.Sprintf(
		"{%v, Payload: %v, Noise: %v}",
		p.hopPacketHeader, p.payload, p.noise,
	)
}

func unpackHopPacket(b []byte) (*HopPacket, error) {
	iv := b[:cipherBlockSize]
	ctext := b[cipherBlockSize:]
	if frame := cipher.decrypt(iv, ctext); frame != nil {
		buf := bytes.NewBuffer(frame)

		p := new(HopPacket)
		binary.Read(buf, binary.BigEndian, &p.hopPacketHeader)
		p.payload = make([]byte, p.Dlen)
		buf.Read(p.payload)
		return p, nil
	} else {
		return nil, errors.New("Decrypt Packet Error")
	}

}

func udpAddrHash(a *net.UDPAddr) [6]byte {
	var b [6]byte
	copy(b[:4], []byte(a.IP)[:4])
	p := uint16(a.Port)
	b[4] = byte((p >> 8) & 0xFF)
	b[5] = byte(p & 0xFF)
	return b
}

type hUDPAddr struct {
	u    *net.UDPAddr
	hash [6]byte
}

func newhUDPAddr(a *net.UDPAddr) *hUDPAddr {
	return &hUDPAddr{a, udpAddrHash(a)}
}

// gohop Peer is a record of a peer's available UDP addrs
type HopPeer struct {
	id           uint64
	ip           net.IP
	addrs        map[[6]byte]int
	_addrs_lst   []*hUDPAddr // i know it's ugly!
	seq          uint32
	state        int32
	hsDone       chan byte			// Handshake done
	recvBuffer   *hopPacketBuffer
	srv          *HopServer
	_lock        sync.RWMutex
	lastSeenTime time.Time
}

func newHopPeer(id uint64, srv *HopServer, addr *net.UDPAddr, idx int) *HopPeer {
	hp := new(HopPeer)
	hp.id = id
	hp._addrs_lst = make([]*hUDPAddr, 0)
	hp.addrs = make(map[[6]byte]int)
	hp.state = HOP_STAT_INIT
	hp.seq = 0
	hp.srv = srv
	hp.recvBuffer = newHopPacketBuffer(srv.toIface)
	// logger.Debug("%v, %v", hp.recvBuffer, hp.srv)

	a := newhUDPAddr(addr)
	hp._addrs_lst = append(hp._addrs_lst, a)
	hp.addrs[a.hash] = idx

	return hp
}

func (h *HopPeer) Seq() uint32 {
	return atomic.AddUint32(&h.seq, 1)
}

func (h *HopPeer) addr() (*net.UDPAddr, int, bool) {
	defer h._lock.RUnlock()
	h._lock.RLock()
	addr := randAddr(h._addrs_lst)
	// addr := h._addrs_lst[0]
	idx, ok := h.addrs[addr.hash]

	return addr.u, idx, ok
}

func (h *HopPeer) insertAddr(addr *net.UDPAddr, idx int) {
	defer h._lock.Unlock()
	h._lock.Lock()
	a := newhUDPAddr(addr)
	if _, found := h.addrs[a.hash]; !found {
		h.addrs[a.hash] = idx
		h._addrs_lst = append(h._addrs_lst, a)
		//logger.Info("%v %d", addr, len(h._addrs_lst))
	}
}
