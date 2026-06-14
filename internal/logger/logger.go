package logger

import (
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

func Init(level, format string) zerolog.Logger {
	lvl := parseLevel(level)
	zerolog.SetGlobalLevel(lvl)
	zerolog.TimeFieldFormat = time.RFC3339Nano

	var out io.Writer = os.Stderr
	if strings.ToLower(format) == "text" {
		out = zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
	}

	return zerolog.New(out).With().Timestamp().Logger()
}

func Nop() zerolog.Logger {
	return zerolog.Nop()
}

func parseLevel(s string) zerolog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return zerolog.DebugLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}
