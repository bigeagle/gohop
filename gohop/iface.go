// Handle virtual interfaces
// author: Justin Wong

package gohop

import (
    "os/exec"
    //    "net"
    "github.com/bigeagle/water"
)

func newTap(name string, addr string) (iface *water.Interface, err error) {
    iface, err = water.NewTAP(name)
    if err != nil {
        return nil, err
    }
    logger.Info("interface %v created", iface.Name())

    cmd := exec.Command("ip", "link", "set", "dev", iface.Name(), "up")
    err = cmd.Run()
    if err != nil {
        return nil, err
    }

    //broadcast := net.ParseIP(addr)
    //[]byte(broadcast)[3] = 255

    cmd = exec.Command("ip", "addr", "add", addr, "dev", iface.Name())
    err = cmd.Run()
    if err != nil {
        return nil, err
    }

    return iface, nil
}
