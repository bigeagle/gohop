package hop

import (
    "net"
    "errors"
    "sync/atomic"
)

type hopIPPool struct {
    subnet *net.IPNet
    pool [127]int32
}

var poolFull = errors.New("IP Pool Full")

func (p *hopIPPool) next() (*net.IPNet, error) {
    found := false
    var i int
    for i = 3; i < 255; i +=2 {
        if atomic.CompareAndSwapInt32(&p.pool[i], 0, 1) {
            found = true
            break
        }
    }
    if !found {
        return nil, poolFull
    }


    ipnet := &net.IPNet{
        make([]byte, 4),
        make([]byte, 4),
    }
    copy([]byte(ipnet.IP), []byte(p.subnet.IP))
    copy([]byte(ipnet.Mask), []byte(p.subnet.Mask))
    ipnet.IP[3] = byte(i)
    return ipnet, nil
}

func (p *hopIPPool) relase(ip net.IP) {
    defer func(){
        if err := recover(); err != nil {
            logger.Error("%v", err)
        }
    }()

    logger.Debug("releasing ip: %v", ip)
    i := ip[3]
    p.pool[i] = 0
}
