package main

import (
    "flag"
    //"fmt"
    "github.com/bigeagle/gohop/logging"
    "github.com/bigeagle/gohop/gohop"
)

var srvMode, cltMode, debug bool
var cfgFile string

func main() {

    flag.BoolVar(&cltMode, "client", false, "Run in client mode")
    flag.BoolVar(&srvMode, "server", false, "Run in server mode")
    flag.BoolVar(&debug, "debug", true, "Provide debug info")
    flag.StringVar(&cfgFile, "config", "", "configfile")
    flag.Parse()

    logging.InitLogger(debug)
    logger := logging.GetLogger()

    if srvMode == cltMode {
        logger.Error("Invalid run mode")
        return
    }


    if cfgFile == "" {
        cfgFile = flag.Arg(0)
    }

    logger.Info("using config file: %v", cfgFile)

    if srvMode {
        err := gohop.NewServer(cfgFile)
        if err != nil {
            logger.Error(err.Error())
            return
        }

    }
    if cltMode {
        err := gohop.NewClient(cfgFile)
        if err != nil {
            logger.Error(err.Error())
            return
        }

    }
}
