/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Justin Wong <justin.w.xd@gmail.com>
 *
 */

package main

import (
    "./hop"
    "./logging"
    "flag"
    "fmt"
    "io"
    "os"
    "runtime"
    "time"
    "path/filepath"
)

var srvMode, cltMode, debug, getVersion bool
var cfgFile string

var VERSION = "0.3.2-dev"

func init() {
    flag.BoolVar(&getVersion, "version", false, "Get Version info")
    flag.BoolVar(&debug, "debug", false, "Provide debug info")
    flag.StringVar(&cfgFile, "config", "", "configfile")
}

func main() {
    flag.Parse()

    if getVersion {
        fmt.Println("GoHop: Yet Another VPN to Escape from Censorship")
        fmt.Printf("Version: %s\n", VERSION)
        os.Exit(0)
    }

    logging.InitLogger(debug)
    logger := logging.GetLogger()

    checkerr := func(err error) {
        if err != nil {
            logger.Error(err.Error())
            os.Exit(1)
        }
    }

    if cfgFile == "" {
        cfgFile = flag.Arg(0)
    }

    logger.Info("using config file: %v", cfgFile)

    icfg, err := hop.ParseHopConfig(cfgFile)
    //logger.Debug("%v", icfg)
    checkerr(err)

    // 设置可使用的最大核心数
    runtime.GOMAXPROCS(runtime.NumCPU() - 1)
    fmt.Printf("/** server start **/\nUse %d/%d CPU cores\n", runtime.GOMAXPROCS(-1), runtime.NumCPU())

    switch cfg := icfg.(type) {
    case hop.HopServerConfig:
        addWatchFile(cfg.RouteFile, cfg.RouteConfig, time.Second*60)
        err := hop.NewServer(&cfg)
        checkerr(err)
    case hop.HopClientConfig:
        err := hop.NewClient(&cfg)
        checkerr(err)
    default:
        logger.Error("Invalid config file")
    }
}

/*
配置文件监控方法
不能放到其他包中。避免非启动时调用。
*/
func addWatchFile(filename string, callback func(r io.Reader), st time.Duration) {
    logger := logging.GetLogger()
    modtime := int64(0)
    filename, _ = filepath.Abs(filename)
    logger.Info("addWatchFile : " + filename)
    setF := func() {
        if f, err := os.Open(filename); err != nil {
            logger.Error("config file " + filename + " error : " + err.Error())
        } else if fi, err := f.Stat(); err != nil {
            logger.Error("config file " + filename + " error : " + err.Error())
        } else if mt := fi.ModTime().Unix(); mt != modtime {
            logger.Debug("load config file : " + filename + " begin !")
            modtime = mt
            callback(f)
            logger.Debug("load config file : " + filename + " finish !")
        }
    }
    setF()
    go func() {
        for {
            time.Sleep(st)
            setF()
        }
    }()
}
