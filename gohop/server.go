package gohop

import (
    "github.com/bigeagle/water/waterutil"
)

func NewServer(ifaceName string, addr string) error {
    iface, err := newTap(ifaceName, addr)
    if err != nil {
        return err
    }
    buf := make([]byte, TAPBUFSIZE)

    for {
        _, err := iface.Read(buf)
        if err != nil {
            return err
        }
        ethertype := waterutil.MACEthertype(buf)
        if ethertype == waterutil.IPv4 {
            packet := waterutil.MACPayload(buf)
            if waterutil.IsIPv4(packet) {
                logger.Debug("Source:      %v [%v]", waterutil.MACSource(buf), waterutil.IPv4Source(packet))
                logger.Debug("Destination: %v [%v]", waterutil.MACDestination(buf), waterutil.IPv4Destination(packet))
                logger.Debug("Protocol:    %v\n", waterutil.IPv4Protocol(packet))
            }
        }

    }

}
