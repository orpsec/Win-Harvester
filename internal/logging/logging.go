// Package logging provides a leveled, thread-safe logger that writes both to a
// console and to a persistent collection.log file inside the output tree.
package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Level controls verbosity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "?"
	}
}

// Logger implements core.Logger and fans output to console + file.
type Logger struct {
	mu      sync.Mutex
	level   Level
	console io.Writer
	file    *os.File
}

// New creates a logger. If logPath is non-empty a log file is opened and all
// records are mirrored there.
func New(level Level, logPath string) (*Logger, error) {
	l := &Logger{level: level, console: os.Stderr}
	if logPath != "" {
		if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, err
		}
		l.file = f
	}
	return l, nil
}

// Close flushes and closes the underlying file.
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

func (l *Logger) log(lv Level, format string, args ...any) {
	if lv < l.level {
		return
	}
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s [%-5s] %s\n", time.Now().Format("2006-01-02T15:04:05.000Z07:00"), lv, msg)
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprint(l.console, line)
	if l.file != nil {
		_, _ = l.file.WriteString(line)
	}
}

func (l *Logger) Debugf(f string, a ...any) { l.log(LevelDebug, f, a...) }
func (l *Logger) Infof(f string, a ...any)  { l.log(LevelInfo, f, a...) }
func (l *Logger) Warnf(f string, a ...any)  { l.log(LevelWarn, f, a...) }
func (l *Logger) Errorf(f string, a ...any) { l.log(LevelError, f, a...) }
