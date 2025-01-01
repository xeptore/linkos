package log

import (
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/rs/zerolog"
)

type FileWriter struct {
	f *os.File
}

func (l *FileWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (l *FileWriter) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	return l.f.Write(p)
}

func (l *FileWriter) Close() error {
	return l.f.Close()
}

func NewFileWriter(filename string) (*FileWriter, error) {
	f, err := os.Create(filename)
	if nil != err {
		return nil, fmt.Errorf("log: failed to create log file: %v", err)
	}

	filenameW, err := syscall.UTF16PtrFromString(f.Name())
	if nil != err {
		return nil, fmt.Errorf("log: failed to convert filename to utf-16: %v", err)
	}

	if err := syscall.SetFileAttributes(filenameW, syscall.FILE_ATTRIBUTE_HIDDEN); nil != err {
		return nil, fmt.Errorf("log: failed to mark log file as hidden: %v", err)
	}

	return &FileWriter{f}, nil
}

type consoleWriteLevel struct {
	w     zerolog.ConsoleWriter
	level zerolog.Level
}

func (c consoleWriteLevel) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (c consoleWriteLevel) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	if level >= c.level {
		return c.w.Write(p)
	}
	return len(p), nil
}

func NewConsoleWriter(level zerolog.Level) io.Writer {
	return zerolog.SyncWriter(
		consoleWriteLevel{
			w: zerolog.ConsoleWriter{ //nolint:exhaustruct
				Out:        os.Stderr,
				TimeFormat: time.DateTime,
			},
			level: level,
		},
	)
}
