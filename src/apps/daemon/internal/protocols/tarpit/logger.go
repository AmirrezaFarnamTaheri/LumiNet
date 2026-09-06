package tarpit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/redact"
	"go.opentelemetry.io/otel/trace"
)

// Level defines the verbosity threshold of the logger.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// Logger represents a structured logger wrapper around file/console streams.
type logger struct {
	level  Level
	output io.Writer
}

// NewLogger constructs a structured Logger with the specified level.
func newLogger(levelName string) *logger {
	level := LevelInfo
	switch strings.ToLower(levelName) {
	case "debug":
		level = LevelDebug
	case "warn", "warning":
		level = LevelWarn
	case "error":
		level = LevelError
	}
	return &logger{
		level:  level,
		output: os.Stdout,
	}
}

// SetOutput sets the output writer for the logger.
func (l *logger) SetOutput(w io.Writer) {
	l.output = w
}

type logEntry struct {
	Time    string                 `json:"time"`
	Level   string                 `json:"level"`
	Message string                 `json:"msg"`
	Fields  map[string]interface{} `json:"fields,omitempty"`
}

func (l *logger) log(ctx context.Context, level Level, levelName string, msg string, keysAndValues ...interface{}) {
	if level < l.level {
		return
	}
	entry := logEntry{
		Time:    time.Now().UTC().Format(time.RFC3339),
		Level:   levelName,
		Message: redact.String(msg),
	}
	fields := make(map[string]interface{})

	if ctx != nil {
		span := trace.SpanFromContext(ctx)
		spanCtx := span.SpanContext()
		if spanCtx.IsValid() {
			fields["trace_id"] = spanCtx.TraceID().String()
			fields["span_id"] = spanCtx.SpanID().String()
			fields["traceparent"] = fmt.Sprintf("00-%s-%s-01", spanCtx.TraceID().String(), spanCtx.SpanID().String())
		}
	}

	if len(keysAndValues) > 0 {
		for i := 0; i+1 < len(keysAndValues); i += 2 {
			key := fmt.Sprintf("%v", keysAndValues[i])
			val := keysAndValues[i+1]
			if sVal, ok := val.(string); ok {
				fields[key] = redact.String(sVal)
			} else {
				fields[key] = val
			}
		}
	}

	if len(fields) > 0 {
		entry.Fields = fields
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	fmt.Fprintln(l.output, string(data))
}

// Debug outputs message and structural details at LevelDebug.
func (l *logger) Debug(ctx context.Context, msg string, keysAndValues ...interface{}) {
	l.log(ctx, LevelDebug, "DEBUG", msg, keysAndValues...)
}

// Info outputs message and structural details at LevelInfo.
func (l *logger) Info(ctx context.Context, msg string, keysAndValues ...interface{}) {
	l.log(ctx, LevelInfo, "INFO", msg, keysAndValues...)
}

// Warn outputs message and structural details at LevelWarn.
func (l *logger) Warn(ctx context.Context, msg string, keysAndValues ...interface{}) {
	l.log(ctx, LevelWarn, "WARN", msg, keysAndValues...)
}

// Error outputs message and structural details at LevelError.
func (l *logger) Error(ctx context.Context, err error, msg string, keysAndValues ...interface{}) {
	errStr := "<nil>"
	if err != nil {
		errStr = err.Error()
	}
	kv := append(keysAndValues, "error", errStr)
	l.log(ctx, LevelError, "ERROR", msg, kv...)
}
