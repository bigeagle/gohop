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

package logging

import (
    gologging "github.com/bigeagle/go-logging"
    stdlog "log"
    "os"
)

var _inited = false
var logger = gologging.MustGetLogger("gohop")

func InitLogger(debugMode bool) {

    _stdout := gologging.NewLogBackend(os.Stdout, "", stdlog.LstdFlags|stdlog.Lshortfile)
    _stderr := gologging.NewLogBackend(os.Stderr, "", stdlog.LstdFlags|stdlog.Lshortfile)

    stderrBackend := gologging.AddModuleLevel(_stderr)
    stdoutBackend := gologging.AddModuleLevel(_stdout)

    if debugMode {
        _stdout.Color = true
        stdoutBackend.SetLevel(gologging.DEBUG, "gohop")
    } else {
        stdoutBackend.SetLevel(gologging.INFO, "gohop")
    }
    stderrBackend.SetLevel(gologging.ERROR, "gohop")

    gologging.SetBackend(stdoutBackend, stderrBackend)
    _inited = true
}

func GetLogger() *gologging.Logger {
    if !_inited {
        InitLogger(false)
    }
    return logger
}
