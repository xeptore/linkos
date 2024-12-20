package log

import (
	"bytes"
	"runtime/debug"

	"github.com/rs/zerolog"
)

func Panic(thing any) func(e *zerolog.Event) {
	return func(e *zerolog.Event) {
		dict := zerolog.Dict().Any("content", thing)
		stack := debug.Stack()
		lines := bytes.Split(stack, []byte("\n"))
		if len(lines) > 9 {
			lines = lines[9:]
		}
		dict.Bytes("stack_traces", bytes.Join(lines, []byte("\n")))
		e.Dict("panic", dict)
	}
}
