package cli

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/tc"
)

func TestFormatLogFieldValueQuotesShellMetacharacters(t *testing.T) {
	cases := []string{
		"1.2.3.4;rm -rf /",
		"value`whoami`",
		"a$b&c",
		"x(y)z{w}",
		"ansi\x1b[31m",
		"nul\x00byte",
	}

	for _, value := range cases {
		got := formatLogFieldValue(value)
		want := strconv.Quote(value)
		if got != want {
			t.Fatalf("expected %q to be quoted as %q, got %q", value, want, got)
		}
	}

	// A benign field with no special characters must remain unquoted.
	if got := formatLogFieldValue("203.0.113.10"); got != "203.0.113.10" {
		t.Fatalf("expected a plain value to stay unquoted, got %q", got)
	}
}

func TestLimitHelpSubcommandMatchesDashH(t *testing.T) {
	app := NewApp(&stubDiscoveryService{})

	var helpWord, helpFlag bytes.Buffer
	var stderr bytes.Buffer

	if exit := app.Run([]string{"limit", "help"}, &helpWord, &stderr); exit != exitCodeSuccess {
		t.Fatalf("expected `limit help` to succeed, got exit %d", exit)
	}
	if exit := app.Run([]string{"limit", "-h"}, &helpFlag, &stderr); exit != exitCodeSuccess {
		t.Fatalf("expected `limit -h` to succeed, got exit %d", exit)
	}

	if helpWord.String() != helpFlag.String() {
		t.Fatalf("expected `limit help` to match `limit -h`:\nhelp:\n%s\n-h:\n%s", helpWord.String(), helpFlag.String())
	}
	if helpWord.Len() == 0 {
		t.Fatal("expected help output to be non-empty")
	}
}

func TestFormatCommandLineQuotesArgsWithSpaces(t *testing.T) {
	command := tc.Command{
		Path: "tc",
		Args: []string{"qdisc", "add", "dev", "eth 0", "root", "handle", "1:", "htb"},
	}

	got := formatCommandLine(command)

	if !strings.Contains(got, strconv.Quote("eth 0")) {
		t.Fatalf("expected the space-bearing argument to be quoted, got %q", got)
	}
	if strings.Contains(got, " eth 0 ") {
		t.Fatalf("expected no ambiguous unquoted space argument, got %q", got)
	}
	// Ordinary tc tokens must remain unquoted for readability.
	for _, token := range []string{"tc", "qdisc", "add", "dev", "root", "1:", "htb"} {
		if !strings.Contains(got, token) {
			t.Fatalf("expected token %q to be present, got %q", token, got)
		}
	}
}

type alwaysFailingWriter struct{}

func (alwaysFailingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write: broken pipe")
}

func TestWriteLimitReportSurfacesWriteError(t *testing.T) {
	report := limitReport{Mode: "dry-run", Operation: limitOperationApply}

	if err := writeLimitReport(alwaysFailingWriter{}, discovery.OutputFormatText, report); err == nil {
		t.Fatal("expected a closed-pipe text write to return an error")
	}
	if err := writeLimitReport(alwaysFailingWriter{}, discovery.OutputFormatJSON, report); err == nil {
		t.Fatal("expected a closed-pipe JSON write to return an error")
	}
}

func TestRunLimitResultOutputToClosedPipeFails(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	app := NewApp(service)
	app.tcInspector = &stubTCStateInspector{err: errors.New("tc unavailable")}
	app.sessionEvidence = &stubSessionEvidenceProvider{}

	var stderr bytes.Buffer
	exit := app.Run(
		[]string{"limit", "--pid", "4242", "--ip", "all", "--device", "eth0", "--direction", "upload", "--rate", "2048"},
		alwaysFailingWriter{},
		&stderr,
	)

	if exit != exitCodeFailure {
		t.Fatalf("expected a closed stdout pipe to fail the CLI, got exit %d", exit)
	}
}
