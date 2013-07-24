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
    "flag"
    //"fmt"
    "github.com/bigeagle/gohop/hop"
    "github.com/bigeagle/gohop/logging"
)

var srvMode, cltMode, debug bool
var cfgFile string

func main() {

    flag.BoolVar(&cltMode, "client", false, "Run in client mode")
    flag.BoolVar(&srvMode, "server", false, "Run in server mode")
    flag.BoolVar(&debug, "debug", false, "Provide debug info")
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
        err := hop.NewServer(cfgFile)
        if err != nil {
            logger.Error(err.Error())
            return
        }

    }
    if cltMode {
        err := hop.NewClient(cfgFile)
        if err != nil {
            logger.Error(err.Error())
            return
        }

    }
}
