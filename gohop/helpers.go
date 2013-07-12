package gohop

import (
    "math/rand"
    "net"
)

func mac2uint64(mac net.HardwareAddr) (i uint64) {
    i = 0
    for _, a := range ([]byte)(mac) {
        i = (i << 8) + uint64(a)
    }
    return i
}

func randAddr(a []net.Addr) net.Addr {
    i := rand.Intn(len(a))
    return a[i]
}
