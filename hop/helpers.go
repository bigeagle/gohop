package hop

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

func ip4_uint32(ip net.IP) (i uint32) {
    i = 0
    for _, a := range ip {
        i = (i << 8) + uint32(a)
    }
    return i
}

func randAddr(a []net.Addr) net.Addr {
    i := rand.Intn(len(a))
    return a[i]
}
