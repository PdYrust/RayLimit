package discovery

import (
	"context"
	"errors"
	"os/exec"
	"testing"
)

// Case 1: the not-installed guard error must unwrap to exec.ErrNotFound so
// callers can match the missing-binary condition with errors.Is.
func TestXrayNotInstalledIssueUnwrapsToExecErrNotFound(t *testing.T) {
	cause := &exec.Error{Name: "xray", Err: exec.ErrNotFound}
	err := xrayNotInstalledIssue("xray", cause)

	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("expected errors.Is(err, exec.ErrNotFound) to be true, got false for %v", err)
	}
}

// Case 2 (backwards-compat): the typed Unavailable classification must still be
// extractable via errors.As on the Code.
func TestXrayNotInstalledIssueRetainsTypedUnavailableCode(t *testing.T) {
	cause := &exec.Error{Name: "xray", Err: exec.ErrNotFound}
	err := xrayNotInstalledIssue("xray", cause)

	var queryErr xraySessionQueryError
	if !errors.As(err, &queryErr) {
		t.Fatalf("expected errors.As to extract xraySessionQueryError, got false for %v", err)
	}
	if queryErr.Code != SessionEvidenceIssueUnavailable {
		t.Fatalf("expected Unavailable code, got %q", queryErr.Code)
	}

	code, ok := sessionQueryErrorCode(err)
	if !ok || code != SessionEvidenceIssueUnavailable {
		t.Fatalf("expected sessionQueryErrorCode to report Unavailable, got code=%q ok=%v", code, ok)
	}
}

// Case 3: an error built without a cause must not unwrap to any underlying
// sentinel; Unwrap returns nil and errors.Is correctly returns false.
func TestNewXraySessionQueryErrorWithoutCauseDoesNotUnwrap(t *testing.T) {
	err := newXraySessionQueryError(SessionEvidenceIssueInsufficient, "no cause here")

	if errors.Is(err, exec.ErrNotFound) {
		t.Fatal("expected errors.Is to be false when no cause is recorded")
	}

	var queryErr xraySessionQueryError
	if !errors.As(err, &queryErr) || queryErr.Code != SessionEvidenceIssueInsufficient {
		t.Fatalf("expected the typed code to remain extractable, got %v", err)
	}
	if queryErr.Unwrap() != nil {
		t.Fatalf("expected Unwrap to return nil when no cause is set, got %v", queryErr.Unwrap())
	}
}

// End-to-end through the guard: a LookPath failure in defaultXrayAPICommandRunner
// must surface an error that is both matchable as exec.ErrNotFound and carries
// the Unavailable code.
func TestDefaultXrayAPICommandRunnerLookPathFailureIsMatchable(t *testing.T) {
	original := xrayLookPath
	t.Cleanup(func() { xrayLookPath = original })
	xrayLookPath = func(string) (string, error) {
		return "", &exec.Error{Name: "xray", Err: exec.ErrNotFound}
	}

	_, err := defaultXrayAPICommandRunner(context.Background(), "xray", "127.0.0.1:10085", 0, "statsgetallonlineusers")
	if err == nil {
		t.Fatal("expected a not-installed error when LookPath fails")
	}
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("expected the guard error to unwrap to exec.ErrNotFound, got %v", err)
	}
	code, ok := sessionQueryErrorCode(err)
	if !ok || code != SessionEvidenceIssueUnavailable {
		t.Fatalf("expected Unavailable classification, got code=%q ok=%v", code, ok)
	}
}
