package cli

import (
	"bytes"
	"errors"
	"testing"
)

func TestCurrentLoggingModelDefinesCLIOutputBoundary(t *testing.T) {
	model := currentLoggingModel()

	if model.DefaultLevel != defaultDiagnosticLogLevel {
		t.Fatalf("expected default diagnostic log level %q, got %q", defaultDiagnosticLogLevel, model.DefaultLevel)
	}
	if !model.DefaultLevel.valid() {
		t.Fatalf("expected default diagnostic log level to be valid, got %q", model.DefaultLevel)
	}
	if model.ResultStream != "stdout" {
		t.Fatalf("expected result stream stdout, got %q", model.ResultStream)
	}
	if model.DiagnosticStream != "stderr" {
		t.Fatalf("expected diagnostic stream stderr, got %q", model.DiagnosticStream)
	}
	if model.OwnerPackage != "internal/cli" {
		t.Fatalf("expected logging owner package internal/cli, got %q", model.OwnerPackage)
	}
	if model.JSONModeRule == "" {
		t.Fatalf("expected JSON mode rule to be documented")
	}
	if model.TextModeRule == "" {
		t.Fatalf("expected text mode rule to be documented")
	}
}

func TestLogLevelValidRecognizesSupportedLevels(t *testing.T) {
	for _, level := range []logLevel{
		logLevelSilent,
		logLevelError,
		logLevelWarn,
		logLevelInfo,
		logLevelDebug,
	} {
		if !level.valid() {
			t.Fatalf("expected %q to be a supported diagnostic log level", level)
		}
	}

	if invalid := logLevel("trace"); invalid.valid() {
		t.Fatalf("expected %q to be rejected as a diagnostic log level", invalid)
	}
}

func TestLogPhaseValidRecognizesSupportedPhases(t *testing.T) {
	for _, phase := range []logPhase{
		logPhaseGeneral,
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
		logPhaseOutput,
	} {
		if !phase.valid() {
			t.Fatalf("expected %q to be a supported log phase", phase)
		}
	}

	if invalid := logPhase("transport"); invalid.valid() {
		t.Fatalf("expected %q to be rejected as a log phase", invalid)
	}
}

func TestNewCommandIOUsesLoggingModelDefaultLevel(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	streams := newCommandIO(&stdout, &stderr, currentLoggingModel())

	if streams.stdout != &stdout {
		t.Fatalf("expected stdout writer to be preserved")
	}
	if streams.stderr != &stderr {
		t.Fatalf("expected stderr writer to be preserved")
	}
	if streams.diag.level != defaultDiagnosticLogLevel {
		t.Fatalf("expected default diagnostic log level %q, got %q", defaultDiagnosticLogLevel, streams.diag.level)
	}
}

func TestDiagnosticLoggerErrorfWritesStructuredDiagnosticLine(t *testing.T) {
	var stderr bytes.Buffer

	logger := newDiagnosticLogger(&stderr, currentLoggingModel())
	logger.Errorf(logPhaseDiscovery, "discovery failed: %s", "backend unavailable")

	if got := stderr.String(); got != "error discovery: discovery failed: backend unavailable\n" {
		t.Fatalf("unexpected diagnostic error output: %q", got)
	}
}

func TestDiagnosticLoggerErrorwRendersOptionalFields(t *testing.T) {
	var stderr bytes.Buffer

	logger := newDiagnosticLogger(&stderr, currentLoggingModel())
	logger.Errorw(
		logPhaseSelection,
		"multiple runtime targets matched; refine the selection",
		intLogField("count", 2),
		boolLogField("provider_limitations", true),
		errorLogField(errors.New("selection remains ambiguous")),
	)

	expected := "error selection: multiple runtime targets matched; refine the selection | count=2 provider_limitations=true error=\"selection remains ambiguous\"\n"
	if got := stderr.String(); got != expected {
		t.Fatalf("unexpected structured diagnostic output: %q", got)
	}
}

func TestWriteDiagnosticFallsBackToGeneralPhaseForInvalidPhase(t *testing.T) {
	var stderr bytes.Buffer

	writeDiagnostic(&stderr, logLevelError, logPhase("transport"), "diagnostic event")

	if got := stderr.String(); got != "error general: diagnostic event\n" {
		t.Fatalf("unexpected fallback diagnostic output: %q", got)
	}
}

func TestDiagnosticLoggerSilentLevelSuppressesErrors(t *testing.T) {
	var stderr bytes.Buffer

	model := currentLoggingModel()
	model.DefaultLevel = logLevelSilent

	logger := newDiagnosticLogger(&stderr, model)
	logger.Errorf(logPhaseDiscovery, "discovery failed: %s", "backend unavailable")

	if stderr.Len() != 0 {
		t.Fatalf("expected silent diagnostic logger to suppress stderr output, got %q", stderr.String())
	}
}

func TestDiagnosticLoggerRejectsMessagesAboveCurrentLevel(t *testing.T) {
	var stderr bytes.Buffer

	logger := newDiagnosticLogger(&stderr, currentLoggingModel())
	logger.Warnf(logPhaseDiscovery, "provider limitation")

	if stderr.Len() != 0 {
		t.Fatalf("expected default error-level logger to suppress warn output, got %q", stderr.String())
	}
}

func TestWriteValidationErrorUsesValidationPhase(t *testing.T) {
	var stderr bytes.Buffer

	writeValidationError(&stderr, `unsupported output format %q`, "yaml")

	if got := stderr.String(); got != "error validation: unsupported output format \"yaml\"\n" {
		t.Fatalf("unexpected validation diagnostic output: %q", got)
	}
}
