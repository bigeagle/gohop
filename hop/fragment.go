package hop
// Handle HopPacket's fragmentation

import (
    "time"
    "sync"
)

const (
    // Fragment Threshold
    FRG_THRES = 32
    // Max Fragments
    MAX_FRAGS = 8
)

var hopFrager *HopFragmenter


type hopSequencer interface {
    Seq() uint32
}

type hopFragCacheRecord struct {
    ts int64
    p *HopPacket
}

type hopFragCache struct {
    cache map[uint32]*hopFragCacheRecord
    flushPeriod time.Time
    lock sync.RWMutex
}

func newHopFragCache(fp time.Duration) *hopFragCache {
    c := new(hopFragCache)
    c.cache = make(map[uint32]*hopFragCacheRecord)
    go func(){
        ticker := time.NewTicker(fp)
        for {
            <-ticker.C
            c.checkExpired()
        }
    }()
    return c
}

func (c *hopFragCache) checkExpired() {
    removeKey := func(k uint32) {
        c.lock.Lock()
        defer c.lock.Unlock()
        delete(c.cache, k)
    }
    nowts := time.Now().Unix()
    for k, v := range(c.cache) {
        if nowts - v.ts > 60 {
            removeKey(k)
        }
    }
}

func (c *hopFragCache) insert(k uint32, p *hopFragCacheRecord) {
    c.lock.Lock()
    c.cache[k] = p
    c.lock.Unlock()
}

func (c *hopFragCache) get(k uint32) (*hopFragCacheRecord, bool) {
    c.lock.RLock()
    v, found := c.cache[k]
    c.lock.RUnlock()
    return v, found
}

type HopFragmenter struct {
    morpher HopMorpher
    cache *hopFragCache
}

func newHopFragmenter(m HopMorpher) *HopFragmenter {
    hf := new(HopFragmenter)
    hf.morpher = m
    hf.cache = newHopFragCache(30*time.Second)
    return hf
}

func (hf *HopFragmenter) Fragmentate(c hopSequencer, frame []byte) []*HopPacket {
    seq := c.Seq()
    frameSize := len(frame)
    packets := make([]*HopPacket, 0, MAX_FRAGS)
    prefixes := make([]int, 0, MAX_FRAGS)
    prefix := 0
    padding := 0

    for i, restSize := 0, frameSize; i<MAX_FRAGS; i++ {
        fragSize := hf.morpher.NextPackSize()
        //logger.Debug("restSize: %d, fragSize: %d", restSize, fragSize)

        delta := restSize - fragSize

        if delta < FRG_THRES {
            if delta < -FRG_THRES {
                padding = -delta
            }
            prefix += restSize
            prefixes = append(prefixes, prefix)
            break
        } else {
            if i == MAX_FRAGS - 1 {
                prefix += restSize
            } else {
                prefix += fragSize
                restSize -= fragSize
            }
        }

        prefixes = append(prefixes, prefix)
    }

    start := 0
    for i, q := range(prefixes) {
        hp := new(HopPacket)
        hp.Seq = seq
        hp.Flag = HOP_FLG_DAT | HOP_FLG_MFR
        hp.Frag = uint8(i)
        hp.Plen = uint16(frameSize)
        hp.FragPrefix = uint16(start)
        hp.setPayload(frame[start:q])
        packets = append(packets, hp)
        start = q
    }

    // logger.Debug("%d, %d", len(prefixes), len(packets))
    last := len(packets)-1
    packets[last].Flag ^= HOP_FLG_MFR
    if padding > 0 {
        packets[last].addNoise(padding)
    }

    return packets

}


func (hf *HopFragmenter) reAssemble(packets []*HopPacket) []*HopPacket {
    rpacks := make([]*HopPacket, 0, len(packets))
    now := time.Now().Unix()

    hf.cache.lock.Lock()
    defer hf.cache.lock.Unlock()

    for _, p := range(packets) {
        // logger.Debug("frag: %v", p.hopPacketHeader)
        if p.Dlen == p.Plen {
            // logger.Debug("rpacket: %v", p.hopPacketHeader)
            rpacks = append(rpacks, p)
            continue
        }

        if r, found := hf.cache.cache[p.Seq]; found {
            rp := r.p
            // logger.Debug("plen: %d, recved: %d", rp.Plen, rp.Dlen)
            rp.Dlen += p.Dlen
            s := p.FragPrefix
            e := s + p.Dlen
            rp.Flag ^= ((p.Flag & HOP_FLG_MFR) ^ HOP_FLG_MFR)
            copy(rp.payload[s:e], p.payload)
            if rp.Dlen == rp.Plen {
                rp.Flag ^= HOP_FLG_MFR
                // logger.Debug("rpacket: %v", rp.hopPacketHeader)
                rpacks = append(rpacks, rp)
                delete(hf.cache.cache, p.Seq)
            }


        } else {
            payload := make([]byte, p.Plen)
            s := p.FragPrefix
            e := s + p.Dlen
            p.Flag = HOP_FLG_DAT ^ ((p.Flag & HOP_FLG_MFR) ^ HOP_FLG_MFR)
            p.Frag = uint8(0xFF)
            copy(payload[s:e], p.payload)
            p.payload = payload
            record := &hopFragCacheRecord{ts: now, p: p}
            hf.cache.cache[p.Seq] = record
        }
    }

    return rpacks

}
