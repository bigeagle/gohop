package hop

import (
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
)

type hopIPPool struct {
	subnet *net.IPNet
	pool   []int32
}

var poolFull = errors.New("IP Pool Full")

func (p *hopIPPool) next() (*net.IPNet, error) {
	if len(p.pool) == 0 {
		maskint := binary.BigEndian.Uint32(p.subnet.Mask)
		maskint = ^maskint & 0xffff //最长支持 65535 IP
		p.pool = make([]int32, maskint)
	}
	for i := 3; i < len(p.pool); i++ {
		lB := i & 0xff
		if lB > 2 && lB < 255 && atomic.CompareAndSwapInt32(&p.pool[i], 0, 1) {
			ipint := binary.BigEndian.Uint32(p.subnet.IP.To4()) + uint32(i)
			ipnet := &net.IPNet{
				make([]byte, 4),
				make([]byte, 4),
			}
			binary.BigEndian.PutUint32(ipnet.IP, ipint)
			copy([]byte(ipnet.Mask), []byte(p.subnet.Mask))
			return ipnet, nil
		}
	}
	return nil, poolFull
}

func (p *hopIPPool) relase(ip net.IP) {
	defer func() {
		if err := recover(); err != nil {
			logger.Error("%v", err)
		}
	}()
	logger.Debug("releasing ip: %v", ip)

	i := binary.BigEndian.Uint32(ip.To4()) & uint32(len(p.pool))
	p.pool[i] = 0
}
