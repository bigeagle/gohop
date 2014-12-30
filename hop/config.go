package hop

import (
    "bufio"
    "code.google.com/p/gcfg"
    "errors"
    "fmt"
    "io"
    "regexp"
    "strconv"
    "strings"
)

// Server Config
type HopServerConfig struct {
    HopStart    int
    HopEnd      int
    ListenAddr  string
    Addr        string
    DNS         []string
    PeerTimeout int
    MTU         int
    Key         string
    FixMSS      bool
    MorphMethod string
    RouteFile   string
    RouteList   map[uint32][][5]byte
}

// Client Config
type HopClientConfig struct {
    Server           string
    HopStart         int
    HopEnd           int
    Key              string
    MTU              int
    FixMSS           bool
    Local            bool
    MorphMethod      string
    Redirect_gateway bool
    Net_gateway      []string
}

type HopConfig struct {
    Default struct {
        Mode string
    }
    Server HopServerConfig
    Client HopClientConfig
}

func ParseHopConfig(filename string) (interface{}, error) {
    cfg := new(HopConfig)
    err := gcfg.ReadFileInto(cfg, filename)
    if err != nil {
        return nil, err
    }
    switch cfg.Default.Mode {
    case "server":
        return cfg.Server, nil
    case "client":
        return cfg.Client, nil
    default:
        return nil, errors.New("Wrong mode")
    }
}

func (cfg *HopServerConfig) RouteConfig(r io.Reader) {

    regCM := regexp.MustCompile(`#.*`)
    regIP := regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)`)
    regGM := regexp.MustCompile(`\[\s*(\d+)\s*\]`)
    key := uint32(0)
    ip := [5]byte{}
    cfg.RouteList = make(map[uint32][][5]byte)

    bf := bufio.NewReader(r)
    for {
        if line, err := bf.ReadString('\n'); err == nil {
            if line = regCM.ReplaceAllString(line, ""); len(strings.TrimSpace(line)) < 3 {
                continue
            }
            if ips := regIP.FindStringSubmatch(line); len(ips) == 6 {
                for k, ipt := range ips[1:] {
                    v, _ := strconv.Atoi(ipt)
                    ip[k] = byte(v)
                    if k == 5 && uint8(ip[k]) > 32 {
                        ip[k] = 32
                    }
                }
                cfg.RouteList[key] = append(cfg.RouteList[key], ip)
            } else if gms := regGM.FindStringSubmatch(line); len(gms) == 2 {
                v, _ := strconv.Atoi(gms[1])
                key = uint32(v)
            }
        } else {
            break
        }
    }
    logger.Debug(fmt.Sprintf("Route list : %v", cfg.RouteList))
}
