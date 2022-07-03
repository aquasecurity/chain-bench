package logger

import (
	"fmt"
	"io"
	"strings"

	"github.com/rs/zerolog"
)

var (
	normalConsoleWriter zerolog.ConsoleWriter = zerolog.ConsoleWriter{Out: io.Discard, TimeFormat: "2006-01-02 15:04:05", NoColor: false}
	normalFileWriter    zerolog.ConsoleWriter = zerolog.ConsoleWriter{Out: io.Discard, TimeFormat: "2006-01-02T15:04:05Z07:00", NoColor: true}
)

func setLogLevel(levelName LogLevel) error {
	var level zerolog.Level

	switch strings.ToUpper(levelName.String()) {
	case "TRACE":
		level = zerolog.TraceLevel
	case "DEBUG":
		level = zerolog.DebugLevel
	case "INFO":
		level = zerolog.InfoLevel
	case "WARNING":
		level = zerolog.WarnLevel
	case "ERROR":
		level = zerolog.ErrorLevel
	case "PANIC":
		level = zerolog.PanicLevel
	default:
		return fmt.Errorf("log level '%s' does not exist", levelName)
	}
	zerolog.SetGlobalLevel(level)
	return nil
}
