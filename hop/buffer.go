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
    "errors"
    "sort"
    "sync"
    "time"
)

const (
    hpBufSize     = 384
    bufferTimeout = 20 * time.Millisecond
)

type hopPacketBuffer struct {
    buf       [hpBufSize]*HopPacket
    outQueue  []*HopPacket
    count     int
    timer     *time.Timer
    timeout   time.Duration
    flushChan chan *HopPacket
    mutex     sync.Mutex
}

var bufFull = errors.New("Buffer Full")

func newHopPacketBuffer(flushChan chan *HopPacket, timeout time.Duration) *hopPacketBuffer {
    hb := new(hopPacketBuffer)
    hb.count = 0
    hb.timer = time.NewTimer(1000 * time.Second)
    hb.timer.Stop()
    hb.flushChan = flushChan
    hb.timeout = timeout
    go func() {
        for {
            <-hb.timer.C
            hb.FlushToChan(hb.flushChan)
            hb.timer.Reset(hb.timeout)
        }
    }()
    return hb
}

func (hb *hopPacketBuffer) Push(p *HopPacket) {
    defer hb.mutex.Unlock()
    hb.mutex.Lock()

    hb.timer.Reset(hb.timeout)

    hb.buf[hb.count] = p
    hb.count += 1
    if hb.count >= hpBufSize {
        // logger.Warning("buffer full, flushing")
        hb._flush()
    }
}

func (hb *hopPacketBuffer) Len() int { return len(hb.outQueue) }

func (hb *hopPacketBuffer) Less(i, j int) bool {
    a, b := hb.outQueue[i], hb.outQueue[j]
    return a.Seq < b.Seq
}

func (hb *hopPacketBuffer) Swap(i, j int) {
    hb.outQueue[i], hb.outQueue[j] = hb.outQueue[j], hb.outQueue[i]
}

func (hb *hopPacketBuffer) Flush() {
    defer hb.mutex.Unlock()
    hb.mutex.Lock()
    hb._flushToChan(hb.flushChan)
}

func (hb *hopPacketBuffer) _flush() {
    hb._flushToChan(hb.flushChan)
}

func (hb *hopPacketBuffer) _flushToChan(c chan *HopPacket) {
    if hopFrager != nil {
        hb.outQueue = hopFrager.reAssemble(hb.buf[:hb.count])
    } else {
        hb.outQueue = hb.buf[:hb.count]
    }

    sort.Sort(hb)
    for _, p := range hb.outQueue {
        c <- p
    }
    hb.count = 0
}

func (hb *hopPacketBuffer) FlushToChan(c chan *HopPacket) {
    defer hb.mutex.Unlock()
    hb.mutex.Lock()
    hb._flushToChan(c)
}
