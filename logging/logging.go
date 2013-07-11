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
