// Handle virtual interfaces
// author: Justin Wong

package hop

import (
    "net"
    "fmt"
    "strings"
    "errors"
    "os/exec"
    "github.com/bigeagle/water"
)

var invalidAddr = errors.New("Invalid device ip address")

func newTun(name string, addr string) (iface *water.Interface, err error) {

    ip, subnet, err := net.ParseCIDR(addr)
    if err != nil {
        return nil, invalidAddr
    }
    ip = ip.To4()
    if ip[3] % 2 == 0 {
        return nil, invalidAddr
    }
    peer := net.IP(make([]byte, 4))
    copy([]byte(peer), []byte(ip))
    peer[3]++


    iface, err = water.NewTUN(name)
    if err != nil {
        return nil, err
    }
    logger.Info("interface %v created", iface.Name())

    sargs := fmt.Sprintf("link set dev %s up mtu 1500", iface.Name())
    args := strings.Split(sargs, " ")
    cmd := exec.Command("ip", args...)
    logger.Info("ip %s", sargs)
    err  = cmd.Run()
    if err != nil {
        return nil, err
    }

    sargs = fmt.Sprintf("addr add dev %s local %s peer %s", iface.Name(), ip, peer)
    args = strings.Split(sargs, " ")
    cmd = exec.Command("ip", args...)
    logger.Info("ip %s", sargs)
    err  = cmd.Run()
    if err != nil {
        return nil, err
    }

    sargs = fmt.Sprintf("route add %s via %s dev %s", subnet, peer, iface.Name())
    args = strings.Split(sargs, " ")
    cmd = exec.Command("ip", args...)
    logger.Info("ip %s", sargs)
    err  = cmd.Run()
    if err != nil {
        return nil, err
    }

    return iface, nil
}
