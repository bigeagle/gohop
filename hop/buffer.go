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
	"sync/atomic"
	"time"
)

type hopPacketBuffer struct {
	buf       *bufferList
	rate      int32
	mutex     sync.Mutex
	flushChan chan *HopPacket
	newPack   chan struct{}
}

var bufFull = errors.New("Buffer Full")

func newHopPacketBuffer(flushChan chan *HopPacket) *hopPacketBuffer {
	hb := new(hopPacketBuffer)
	hb.buf = newBufferList()
	hb.flushChan = flushChan
	hb.newPack = make(chan struct{}, 9184)
	go func() {
		for {
			p := hb.Pop()
			if p != nil {
				hb.flushChan <- p
			}
		}
	}()
	return hb
}

func (hb *hopPacketBuffer) Push(p *HopPacket) {
	atomic.AddInt32(&hb.rate, 1)
	hb.buf.Push(int64(p.Seq), p)
	hb.newPack <- struct{}{}
}

func (hb *hopPacketBuffer) Pop() *HopPacket {
	<-hb.newPack
	r := int(hb.rate & 0x10)
	if hb.buf.count < 8+r {
		time.Sleep(time.Duration(r*20+50) * time.Microsecond)
		hb.rate = hb.rate >> 1
	}
	p := hb.buf.Pop().(*HopPacket)
	return p
}

type bufferElem struct {
	p    interface{}
	key  int64
	next *bufferElem
	prev *bufferElem
}

type bufferList struct {
	count       int
	head        *bufferElem
	mutex       sync.Mutex
	_lastpopped int64
}

func newBufferList() *bufferList {
	l := new(bufferList)
	l.count = 0
	l._lastpopped = -1
	l.head = new(bufferElem)
	l.head.p = nil
	l.head.next = l.head
	l.head.prev = l.head
	return l
}

func (l *bufferList) Push(key int64, p interface{}) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	elem := &bufferElem{p, key, nil, nil}

	uninserted := true
	i := 0
	for cur := l.head.prev; cur != l.head; cur = cur.prev {
		// if i > 0 {
		//     logger.Debug("%d/%d", i, l.count)
		// }
		if cur.key < key {
			uninserted = false
			elem.next = cur.next
			elem.prev = cur
			cur.next = elem
			elem.next.prev = elem
			break
		}
		i++
	}

	if uninserted {
		elem.next = l.head.next
		elem.prev = l.head
		l.head.next = elem
		elem.next.prev = elem
	}

	l.count++
}

func (l *bufferList) Pop() interface{} {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if l.count == 0 {
		logger.Warning("Error")
		return nil
	}

	elem := l.head.next
	l.head.next = elem.next
	elem.next.prev = l.head
	l.count--
	// delta := elem.key - l._lastpopped
	// if delta < 0 {
	//     // logger.Debug("%d, %d", elem.key, l._lastpopped)
	//     ok = false
	// } else {
	//     ok = true
	// }
	// l._lastpopped = elem.key
	return elem.p
}
