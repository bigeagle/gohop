package gohop

import (
	"os"

	"github.com/op/go-logging"
)

var Logger = logging.MustGetLogger("gohop")

func InitLogger(debug bool) {
	fmt_string := "\r%{color}[%{time:06-01-02 15:04:05}][%{level:.6s}]%{color:reset} %{message}"
	format := logging.MustStringFormatter(fmt_string)
	logging.SetFormatter(format)
	logging.SetBackend(logging.NewLogBackend(os.Stdout, "", 0))

	if debug {
		logging.SetLevel(logging.DEBUG, "gohop")
	} else {
		logging.SetLevel(logging.INFO, "gohop")
	}
}

func GetLogger() *logging.Logger {
	return Logger
}
