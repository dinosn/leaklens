package enum

import (
	"fmt"
	"io"
	"os"
	"sync"
)

var logOutput = struct {
	sync.RWMutex
	w io.Writer
}{
	w: os.Stderr,
}

// SetLogOutput changes enum package diagnostic output and returns a restore function.
func SetLogOutput(w io.Writer) func() {
	if w == nil {
		w = io.Discard
	}
	logOutput.Lock()
	old := logOutput.w
	logOutput.w = w
	logOutput.Unlock()
	return func() {
		logOutput.Lock()
		logOutput.w = old
		logOutput.Unlock()
	}
}

func enumStderr() io.Writer {
	logOutput.RLock()
	defer logOutput.RUnlock()
	return logOutput.w
}

func warnf(format string, args ...any) {
	logOutput.Lock()
	defer logOutput.Unlock()
	_, _ = fmt.Fprintf(logOutput.w, format, args...)
}
