package cli

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// logLevel defines future diagnostic verbosity for the CLI. Operator-facing
// command results remain separate from diagnostic logging and are rendered
// explicitly by the command handlers.
type logLevel string

const (
	logLevelSilent logLevel = "silent"
	logLevelError  logLevel = "error"
	logLevelWarn   logLevel = "warn"
	logLevelInfo   logLevel = "info"
	logLevelDebug  logLevel = "debug"
)

// logPhase identifies the CLI area responsible for a diagnostic line.
type logPhase string

const (
	logPhaseGeneral       logPhase = "general"
	logPhaseDiscovery     logPhase = "discovery"
	logPhaseSelection     logPhase = "selection"
	logPhasePolicy        logPhase = "policy"
	logPhaseCorrelation   logPhase = "correlation"
	logPhaseAggregate     logPhase = "aggregate"
	logPhaseTCObservation logPhase = "tc-observation"
	logPhasePlanning      logPhase = "planning"
	logPhaseExecution     logPhase = "execution"
	logPhaseCleanup       logPhase = "cleanup"
	logPhaseValidation    logPhase = "validation"
	logPhaseOutput        logPhase = "output"
)

const defaultDiagnosticLogLevel = logLevelError

// loggingModel documents the intended CLI logging contract without introducing a
// full logging implementation yet.
type loggingModel struct {
	DefaultLevel     logLevel
	ResultStream     string
	DiagnosticStream string
	JSONModeRule     string
	TextModeRule     string
	OwnerPackage     string
}

func currentLoggingModel() loggingModel {
	return loggingModel{
		DefaultLevel:     defaultDiagnosticLogLevel,
		ResultStream:     "stdout",
		DiagnosticStream: "stderr",
		JSONModeRule:     "machine-readable command results stay on stdout; diagnostics must stay off stdout",
		TextModeRule:     "operator-facing command results stay on stdout; diagnostics remain separate on stderr",
		OwnerPackage:     "internal/cli",
	}
}

func (level logLevel) valid() bool {
	switch level {
	case logLevelSilent, logLevelError, logLevelWarn, logLevelInfo, logLevelDebug:
		return true
	default:
		return false
	}
}

func (phase logPhase) valid() bool {
	switch phase {
	case logPhaseGeneral,
		logPhaseDiscovery,
		logPhaseSelection,
		logPhasePolicy,
		logPhaseCorrelation,
		logPhaseAggregate,
		logPhaseTCObservation,
		logPhasePlanning,
		logPhaseExecution,
		logPhaseCleanup,
		logPhaseValidation,
		logPhaseOutput:
		return true
	default:
		return false
	}
}

type logField struct {
	Key   string
	Value string
}

type diagnosticLogger struct {
	level logLevel
	w     io.Writer
}

type commandIO struct {
	stdout io.Writer
	stderr io.Writer
	diag   diagnosticLogger
}

func newCommandIO(stdout, stderr io.Writer, model loggingModel) commandIO {
	return commandIO{
		stdout: stdout,
		stderr: stderr,
		diag:   newDiagnosticLogger(stderr, model),
	}
}

func newDiagnosticLogger(w io.Writer, model loggingModel) diagnosticLogger {
	level := model.DefaultLevel
	if !level.valid() {
		level = defaultDiagnosticLogLevel
	}

	return diagnosticLogger{
		level: level,
		w:     w,
	}
}

func (l diagnosticLogger) Errorf(phase logPhase, format string, args ...any) {
	l.logf(logLevelError, phase, format, args...)
}

func (l diagnosticLogger) Warnf(phase logPhase, format string, args ...any) {
	l.logf(logLevelWarn, phase, format, args...)
}

func (l diagnosticLogger) Infof(phase logPhase, format string, args ...any) {
	l.logf(logLevelInfo, phase, format, args...)
}

func (l diagnosticLogger) Debugf(phase logPhase, format string, args ...any) {
	l.logf(logLevelDebug, phase, format, args...)
}

func (l diagnosticLogger) Errorw(phase logPhase, message string, fields ...logField) {
	l.log(logLevelError, phase, message, fields...)
}

func (l diagnosticLogger) Warnw(phase logPhase, message string, fields ...logField) {
	l.log(logLevelWarn, phase, message, fields...)
}

func (l diagnosticLogger) Infow(phase logPhase, message string, fields ...logField) {
	l.log(logLevelInfo, phase, message, fields...)
}

func (l diagnosticLogger) Debugw(phase logPhase, message string, fields ...logField) {
	l.log(logLevelDebug, phase, message, fields...)
}

func (l diagnosticLogger) logf(level logLevel, phase logPhase, format string, args ...any) {
	l.log(level, phase, fmt.Sprintf(format, args...))
}

func (l diagnosticLogger) log(level logLevel, phase logPhase, message string, fields ...logField) {
	if !l.enabled(level) {
		return
	}

	if !phase.valid() {
		phase = logPhaseGeneral
	}

	writeDiagnostic(l.w, level, phase, strings.TrimSpace(message), fields...)
}

func (l diagnosticLogger) enabled(level logLevel) bool {
	if l.w == nil {
		return false
	}

	return diagnosticLogLevelRank(l.level) >= diagnosticLogLevelRank(level)
}

func diagnosticLogLevelRank(level logLevel) int {
	switch level {
	case logLevelSilent:
		return 0
	case logLevelError:
		return 1
	case logLevelWarn:
		return 2
	case logLevelInfo:
		return 3
	case logLevelDebug:
		return 4
	default:
		return diagnosticLogLevelRank(defaultDiagnosticLogLevel)
	}
}

func stringLogField(key, value string) logField {
	return logField{
		Key:   strings.TrimSpace(key),
		Value: value,
	}
}

func intLogField(key string, value int) logField {
	return stringLogField(key, strconv.Itoa(value))
}

func boolLogField(key string, value bool) logField {
	return stringLogField(key, strconv.FormatBool(value))
}

func errorLogField(err error) logField {
	if err == nil {
		return logField{}
	}

	return stringLogField("error", err.Error())
}

func writeDiagnostic(w io.Writer, level logLevel, phase logPhase, message string, fields ...logField) {
	if w == nil {
		return
	}
	if !level.valid() {
		level = defaultDiagnosticLogLevel
	}
	if !phase.valid() {
		phase = logPhaseGeneral
	}
	if message == "" {
		message = "diagnostic event"
	}

	var b strings.Builder
	b.WriteString(string(level))
	b.WriteString(" ")
	b.WriteString(string(phase))
	b.WriteString(": ")
	b.WriteString(message)

	rendered := renderLogFields(fields)
	if rendered != "" {
		b.WriteString(" | ")
		b.WriteString(rendered)
	}
	b.WriteByte('\n')

	_, _ = io.WriteString(w, b.String())
}

func renderLogFields(fields []logField) string {
	if len(fields) == 0 {
		return ""
	}

	rendered := make([]string, 0, len(fields))
	for _, field := range fields {
		key := strings.TrimSpace(field.Key)
		if key == "" {
			continue
		}

		rendered = append(rendered, key+"="+formatLogFieldValue(field.Value))
	}

	return strings.Join(rendered, " ")
}

func formatLogFieldValue(value string) string {
	if value == "" {
		return `""`
	}
	if strings.ContainsAny(value, " \t\n\r\"|=") {
		return strconv.Quote(value)
	}
	return value
}

func (streams commandIO) withDiagnosticLevel(level logLevel) commandIO {
	model := currentLoggingModel()
	model.DefaultLevel = level
	streams.diag = newDiagnosticLogger(streams.stderr, model)
	return streams
}
