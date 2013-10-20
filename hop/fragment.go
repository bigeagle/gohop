package hop
// Handle HopPacket's fragmentation

import (
    "bytes"
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


type HopFragmenter struct {
    morpher HopMorpher
}

func newHopFragmenter(m HopMorpher) *HopFragmenter {
    hf := new(HopFragmenter)
    hf.morpher = m
    return hf
}

func (hf *HopFragmenter) bufFragmentate(c hopSequencer, frame []byte) []*HopPacket {
    seq := c.Seq()
    frameSize := len(frame)
    packets := make([]*HopPacket, 0, MAX_FRAGS)
    prefixes := make([]int, 0, MAX_FRAGS+1)
    bufSize := 0

    padding := 0

    for i, restSize := 0, frameSize; i<MAX_FRAGS; i++ {
        fragSize := hf.morpher.NextPackSize()
        //logger.Debug("restSize: %d, fragSize: %d", restSize, fragSize)

        delta := restSize - fragSize

        prefixes = append(prefixes, bufSize - i*HOP_HDR_LEN)

        if delta < FRG_THRES {
            if delta < -FRG_THRES {
                padding = (-delta) - HOP_HDR_LEN
                //logger.Debug("padding: %d", padding)
                bufSize += (fragSize + HOP_HDR_LEN)
            } else {
                bufSize += (restSize + HOP_HDR_LEN)
            }
            break
        } else {
            if i == MAX_FRAGS - 1 {
                bufSize += (restSize + HOP_HDR_LEN)
            } else {
                bufSize += (fragSize + HOP_HDR_LEN)
                restSize -= fragSize
            }
        }
    }
    prefixes = append(prefixes, frameSize)

    buf := make([]byte, bufSize)

    for i := 0; i < len(prefixes) - 1; i++ {
        p, q := prefixes[i], prefixes[i+1]
        bs := p + (i+1)*HOP_HDR_LEN
        be := bs + (q-p)
        //logger.Debug("frame range: %d, %d", p, q)

        copy(buf[bs:be], frame[p:q])

        hp := new(HopPacket)
        hp.Seq = seq
        hp.Flag = HOP_FLG_DAT | HOP_FLG_MFR
        hp.Frag = uint8(i)
        hp.buf = buf[bs-HOP_HDR_LEN:be]
        hp.setPayload(buf[bs:be])
        packets = append(packets, hp)
    }

    last := len(packets)-1
    packets[last].Flag ^= HOP_FLG_MFR
    if padding > 0 {
        bs := prefixes[last] + last * HOP_HDR_LEN
        packets[last].buf = buf[bs:len(buf)]

        packets[last].addNoise(padding)
    }

    return packets
}


// reassemble packets in a buffer, buffer must be sorted
// packets in `prevFailures` *must* be included in `packets`
// if previous failed packet failed again, it would be ignored
func (hf *HopFragmenter) assemble(packets []*HopPacket, prevFailures []*HopPacket) (rpacks []*HopPacket, failures []*HopPacket) {
    mergePackets := func(packs []*HopPacket) *HopPacket {
        dLen := uint16(0)
        flag := HOP_FLG_DAT
        for _, p := range(packs) {
            dLen += p.Dlen
            flag ^= ((p.Flag & HOP_FLG_MFR) ^ HOP_FLG_MFR)
        }
        buf := bytes.NewBuffer(make([]byte, 0, dLen))
        for _, p := range(packs) {
            buf.Write(p.payload)
        }

        rp := new(HopPacket)
        rp.Flag = flag ^ HOP_FLG_MFR
        rp.Seq = packs[0].Seq
        rp.Frag = uint8(len(packs))
        rp.Dlen = dLen
        rp.payload = buf.Bytes()
        return rp
    }

    n := len(packets)

    if n < 2 {
        return packets, prevFailures
    }

    rpacks = make([]*HopPacket, 0, n)
    failures = make([]*HopPacket, 0, n)
    grpStart := 0
    prev := packets[0]

    for i, cur := range(packets[1:]) {
        if prev.Seq < cur.Seq {
            // logger.Debug("prev: %d, cur: %d", prev.Seq, cur.Seq)
            // merge previours packs
            s, e := grpStart, i+1
            rp := mergePackets(packets[s:e])
            if rp.Flag & HOP_FLG_MFR != 0 {
                for _, f := range(prevFailures) {
                    if rp.Seq == f.Seq {
                        goto nextloop
                    }
                }
                failures = append(failures, rp)
            } else {
                rpacks = append(rpacks, rp)
            }
            nextloop:
            grpStart = i + 1
        }
        prev = cur
    }

    rp := mergePackets(packets[grpStart:])
    if rp.Flag & HOP_FLG_MFR != 0 {
        for _, f := range(prevFailures) {
            if rp.Seq == f.Seq {
                goto _ret
            }
        }
        failures = append(failures, rp)
    } else {
        rpacks = append(rpacks, rp)
    }

    _ret:
    return rpacks, failures
}
