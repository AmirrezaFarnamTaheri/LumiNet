package system

import "fmt"

// LoggerFormatter formats log lines with optional ANSI coloring.
type LoggerFormatter struct {
	UseColor bool
}

// NewLoggerFormatter returns a new LoggerFormatter.
func NewLoggerFormatter(useColor bool) *LoggerFormatter {
	return &LoggerFormatter{UseColor: useColor}
}

// Format returns a formatted log string: "[LEVEL] message".
func (f *LoggerFormatter) Format(level, message string) string {
	return fmt.Sprintf("[%s] %s", level, message)
}
