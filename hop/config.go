package hop

import (
    "encoding/json"
    "os"
    "errors"
    "io/ioutil"
    "code.google.com/p/gcfg"
)


type hopClientConfig struct {
    servers []string
    key     string
    addr    string
    // redirect gateway
    regw   bool
    routes []*route
}

// config for hopserver
type hopServerConfig struct {
    ports []string
    key   string
    addr  string
    // dev string
}

func clientParseConfig(cfgFile string) (*hopClientConfig, error) {
    file, err := os.Open(cfgFile)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    jsonBuf, err := ioutil.ReadAll(file)

    // logger.Debug("%s", string(jsonBuf))

    var icfg interface{}
    err = json.Unmarshal(jsonBuf, &icfg)

    if err != nil {
        return nil, err
    }

    cltConfig := new(hopClientConfig)

    cfg, ok := icfg.(map[string]interface{})

    if ok {
        // logger.Debug("%v", cfg)

        if iservers, found := cfg["servers"]; found {
            cltConfig.servers = make([]string, 0)
            switch servers := iservers.(type) {
            case string:
                cltConfig.servers = append(cltConfig.servers, servers)
            case []interface{}:
                for _, v := range servers {
                    if server, ok := v.(string); ok {
                        cltConfig.servers = append(cltConfig.servers, server)
                    } else {
                        return nil, errors.New("Invalid server config")
                    }
                }
            default:
                return nil, errors.New("Invalid server config")
            }
        } else {
            return nil, errors.New("Servers not found")
        }

        if ikey, found := cfg["key"]; found {
            if key, ok := ikey.(string); ok {
                cltConfig.key = key
            } else {
                return nil, errors.New("Invalid Key config")
            }
        } else {
            return nil, errors.New("Key not found")
        }

        if iaddr, found := cfg["addr"]; found {
            if addr, ok := iaddr.(string); ok {
                cltConfig.addr = addr
            } else {
                return nil, errors.New("Invalid Addr config")
            }
        } else {
            return nil, errors.New("Addr config not found")
        }

        if iregw, found := cfg["redirect_gateway"]; found {
            if regw, ok := iregw.(bool); ok {
                cltConfig.regw = regw
            } else {
                return nil, errors.New("Invalid Gateway Redirect Config")
            }
        } else {
            cltConfig.regw = false
        }

        net_gateway, net_nic, err = getNetGateway()
        logger.Debug("Net Gateway: %s %s", net_gateway, net_nic)
        if err != nil {
            return nil, err
        }

        if iroutes, found := cfg["net_gateway"]; found {
            cltConfig.routes = make([]*route, 0)
            if routes, ok := iroutes.([]interface{}); ok {
                for _, v := range routes {
                    if destNet, ok := v.(string); ok {
                        r := &route{destNet, net_gateway, net_nic}
                        cltConfig.routes = append(cltConfig.routes, r)
                    } else {
                        return nil, errors.New("Invalid Route config")
                    }
                }

            }
        }
    }

    return cltConfig, nil
}



// read and parse config file
func serverParseConfig(cfgFile string) (*hopServerConfig, error) {

    file, err := os.Open(cfgFile)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    jsonBuf, err := ioutil.ReadAll(file)

    // logger.Debug("%s", string(jsonBuf))

    var icfg interface{}
    err = json.Unmarshal(jsonBuf, &icfg)

    if err != nil {
        return nil, err
    }

    srvConfig := new(hopServerConfig)

    cfg, ok := icfg.(map[string]interface{})

    if ok {
        // logger.Debug("%v", cfg)

        if iports, found := cfg["ports"]; found {
            srvConfig.ports = make([]string, 0)
            switch ports := iports.(type) {
            case string:
                srvConfig.ports = append(srvConfig.ports, ports)
            case []interface{}:
                for _, v := range ports {
                    if port, ok := v.(string); ok {
                        srvConfig.ports = append(srvConfig.ports, port)
                    } else {
                        return nil, errors.New("Invalid port config")
                    }
                }
            default:
                return nil, errors.New("Invalid port config")
            }
        } else {
            return nil, errors.New("Port not found")
        }

        if ikey, found := cfg["key"]; found {
            if key, ok := ikey.(string); ok {
                srvConfig.key = key
            } else {
                return nil, errors.New("Invalid Key config")
            }
        } else {
            return nil, errors.New("Key not found")
        }

        if iaddr, found := cfg["addr"]; found {
            if addr, ok := iaddr.(string); ok {
                srvConfig.addr = addr
            } else {
                return nil, errors.New("Invalid Addr config")
            }
        } else {
            return nil, errors.New("Addr config not found")
        }

    }

    return srvConfig, nil
}

// Server Config
type HopServerConfig struct {
    Port string
    HopRange string
    Addr string
    Key string
}

// Client Config
type HopClientConfig struct {
    Server string
    HopStart int
    HopEnd int
    Key string
    MTU string
    Local bool
    Redirect_gateway bool
    Net_gateway []string
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
