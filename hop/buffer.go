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

// buffer maintaining for goHop's udp packets

package hop

import (
    "sort"
    "errors"
    "sync"
)

const hpBufSize = 64

type hopPacketBuffer struct {
    buf [hpBufSize]*HopPacket
    failAss []*HopPacket
    count int
    mutex sync.Mutex
}

var bufFull = errors.New("Buffer Full")

func newHopPacketBuffer() *hopPacketBuffer {
    hb := new(hopPacketBuffer)
    hb.failAss = make([]*HopPacket, 0)
    hb.count = 0
    return hb
}

func (hb *hopPacketBuffer) push(p *HopPacket) error {
    defer hb.mutex.Unlock()
    hb.mutex.Lock()
    hb.buf[hb.count] = p
    hb.count += 1
    if hb.count == hpBufSize {
        return bufFull
    } else {
        return nil
    }
}

func (hb *hopPacketBuffer) Len() int { return hb.count }

func (hb *hopPacketBuffer) Less(i, j int) bool {
    a, b := hb.buf[i], hb.buf[j]
    if a.Seq == b.Seq {
        return a.Frag < b.Frag
    }
    return a.Seq < b.Seq
}

func (hb *hopPacketBuffer) Swap(i, j int) {
    hb.buf[i], hb.buf[j] = hb.buf[j], hb.buf[i]
}

func (hb *hopPacketBuffer) flushToChan(c chan *HopPacket) {
    defer hb.mutex.Unlock()
    hb.mutex.Lock()
    sort.Sort(hb)

    if hopFrager != nil {
        assembled, failures := hopFrager.assemble(hb.buf[:hb.count], hb.failAss)

        for _, p := range(assembled) {
            c <- p
        }

        hb.failAss = failures
        for i, p := range(failures) {
            hb.buf[i] = p
        }
        hb.count = len(failures)
        if hb.count > 0 {
            logger.Debug("failures: %d",  len(failures))
        }
    } else {
        for i:=0; i<hb.count; i++ {
            c <- hb.buf[i]
        }
        hb.count = 0
    }
}





