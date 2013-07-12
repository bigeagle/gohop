package gohop

import "net"

func mac2uint64(mac net.HardwareAddr) (i uint64){
    i = 0
    for _, a := range(([]byte)(mac)) {
        i = (i << 8) + uint64(a)
    }
    return i
}
