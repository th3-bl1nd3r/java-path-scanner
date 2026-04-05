package output

import (
	"encoding/json"
	"io"
	"os"
	"sync"
)

// JSONLWriter writes one JSON line per finding.
type JSONLWriter struct {
	writer io.Writer
	file   *os.File
	mu     sync.Mutex
}

// NewJSONLWriter creates a JSONL writer. If path is empty, writes to stdout.
func NewJSONLWriter(path string) (*JSONLWriter, error) {
	w := &JSONLWriter{}
	if path == "" {
		w.writer = os.Stdout
	} else {
		f, err := os.Create(path)
		if err != nil {
			return nil, err
		}
		w.file = f
		w.writer = f
	}
	return w, nil
}

// OnFinding writes one JSON line per finding.
func (jw *JSONLWriter) OnFinding(f *Finding) {
	jw.mu.Lock()
	defer jw.mu.Unlock()

	data, err := json.Marshal(f)
	if err != nil {
		return
	}
	_, _ = jw.writer.Write(append(data, '\n'))
}

// OnTargetStart is a no-op for JSONL.
func (jw *JSONLWriter) OnTargetStart(_ string) {}

// OnTargetDone is a no-op for JSONL.
func (jw *JSONLWriter) OnTargetDone(_ *TargetResult) {}

// Flush closes the file if opened.
func (jw *JSONLWriter) Flush() error {
	if jw.file != nil {
		return jw.file.Close()
	}
	return nil
}
