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
    "sync"
    // "runtime"
    "container/list"
)

type hopPacketBuffer struct {
    buf *list.List
    outQueue []*HopPacket
    flushChan chan *HopPacket
    mutex sync.Mutex
    newPack chan bool
}

var bufFull = errors.New("Buffer Full")

func newHopPacketBuffer(flushChan chan *HopPacket) *hopPacketBuffer {
    hb := new(hopPacketBuffer)
    hb.buf = list.New()
    // hb.timer = time.NewTimer(1000*time.Second)
    // hb.timer.Stop()
    hb.flushChan = flushChan
    // hb.timeout = timeout
    hb.newPack = make(chan bool, 32)
    // go func() {
    //     for {
    //         <-hb.newPack
    //         p := hb.Pop()
    //         if p != nil {
    //             hb.flushChan <- p
    //         }
    //         // <-hb.timer.C
    //         // hb.FlushToChan(hb.flushChan)
    //         // hb.timer.Reset(hb.timeout)
    //     }
    // }()
    return hb
}

func (hb *hopPacketBuffer) Push(p *HopPacket) {
    // defer hb.mutex.Unlock()
    // hb.mutex.Lock()

    // if hb.buf.Len() > 0 {
    //     for e := hb.buf.Back(); e != nil; e = e.Prev() {
    //         ep := e.Value.(*HopPacket)
    //         if ep.Seq <= p.Seq {
    //             hb.buf.InsertAfter(p, e)
    //             break
    //         }
    //     }
    // } else {
    //     hb.buf.PushBack(p)
    // }
    // hb.newPack <- true
    hb.flushChan <- p
}

func (hb *hopPacketBuffer) Pop() *HopPacket {
    defer hb.mutex.Unlock()
    hb.mutex.Lock()

    if hb.buf.Len() == 0 {
        return nil
    }
    return hb.buf.Remove(hb.buf.Front()).(*HopPacket)
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
    // if hopFrager != nil {
    //     //hb.outQueue = hopFrager.reAssemble(hb.buf[:hb.count])
    //     buf := make([]*HopPacket, 0, hb.buf.Len())
    //     for e := hb.buf.Front(); e != nil; e = e.Next() {
    //         buf = append(buf, e.Value.(*HopPacket))
    //     }
    //     for _, p := range(hopFrager.reAssemble(buf)) {
    //         c <- p
    //     }
    //     hb.buf.Init()
    // } else {
    // }

    for e := hb.buf.Front(); e != nil; e = e.Next() {
        c <- e.Value.(*HopPacket)
    }
    hb.buf.Init()
}

func (hb *hopPacketBuffer) FlushToChan(c chan *HopPacket) {
    defer hb.mutex.Unlock()
    hb.mutex.Lock()
    hb._flushToChan(c)
}
