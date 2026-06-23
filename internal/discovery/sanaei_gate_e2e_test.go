package discovery

import (
	"context"
	"testing"
	"time"
)

// forkAPIConfigWithStatsUserOnline writes an API config whose api.services list
// includes the StatsUserOnline companion service (the correctly-configured
// Sanaei case), so the capability detector observes StatsUserOnline as enabled.
func forkAPIConfigWithStatsUserOnline(t *testing.T) string {
	t.Helper()

	return writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["StatsService","StatsUserOnline"]},
  "inbounds": [{"tag":"api","listen":"127.0.0.1","port":10085}]
}`)
}

func sanaeiGateHasIssueCode(issues []SessionEvidenceIssue, code SessionEvidenceIssueCode) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}

	return false
}

// emptyOnlineUsersProvider builds an in-process evidence provider whose API
// runner returns an empty online-users result, so the StatsUserOnline gate is
// the only thing that decides between a typed not-enabled error and a genuine
// no-sessions outcome.
func emptyOnlineUsersProvider(t *testing.T, target RuntimeTarget) XraySessionEvidenceProvider {
	t.Helper()

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{Targets: []RuntimeTarget{target}},
	})
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }
	provider.RunAPICommand = func(_ context.Context, _ string, _ string, _ time.Duration, command string, _ ...string) ([]byte, error) {
		if command != "statsgetallonlineusers" {
			t.Fatalf("unexpected command %q", command)
		}
		return []byte(`{"users":[]}`), nil
	}

	return provider
}

// Case 1 + Scenario 7 (end-to-end): a Sanaei fork whose StatsUserOnline service
// is NOT enabled, returning empty online users, must surface the typed
// not-enabled issue at the TOP-LEVEL ObserveSessions entry point (the gate is
// now active, not a no-op).
func TestSanaeiGateSurfacesStatsUserOnlineNotEnabledEndToEnd(t *testing.T) {
	target := hostAPITarget(t, "/opt/sanaei/sanaei-linux-amd64", "sanaei-linux-amd64", forkAPIConfig(t))
	provider := emptyOnlineUsersProvider(t, target)

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected top-level observation to succeed, got %v", err)
	}
	if !sanaeiGateHasIssueCode(result.Issues, SessionEvidenceIssueStatsUserOnlineNotEnabled) {
		t.Fatalf("expected the typed StatsUserOnline-not-enabled issue at ObserveSessions, got %#v", result.Issues)
	}
	if len(result.Evidence) != 0 {
		t.Fatalf("expected no evidence for the misconfigured fork, got %#v", result.Evidence)
	}
}

// Case 2: a Sanaei fork WITH StatsUserOnline enabled and no online users is a
// genuine no-sessions outcome, not the typed configuration error.
func TestSanaeiGateEnabledServiceReportsGenuineNoSessions(t *testing.T) {
	target := hostAPITarget(t, "/opt/sanaei/sanaei", "sanaei", forkAPIConfigWithStatsUserOnline(t))
	provider := emptyOnlineUsersProvider(t, target)

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}
	if sanaeiGateHasIssueCode(result.Issues, SessionEvidenceIssueStatsUserOnlineNotEnabled) {
		t.Fatalf("expected NO not-enabled error when StatsUserOnline is configured, got %#v", result.Issues)
	}
	if len(result.Evidence) != 0 {
		t.Fatalf("expected genuine no-sessions (empty evidence), got %#v", result.Evidence)
	}
}

// Case 3: a vanilla "xray" runtime must NOT trigger the Sanaei-specific gate,
// even when StatsUserOnline is absent from its config (vanilla behavior
// preserved).
func TestVanillaXrayDoesNotTriggerSanaeiGate(t *testing.T) {
	target := hostAPITarget(t, "/usr/local/bin/xray", "xray", forkAPIConfig(t))
	provider := emptyOnlineUsersProvider(t, target)

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}
	if sanaeiGateHasIssueCode(result.Issues, SessionEvidenceIssueStatsUserOnlineNotEnabled) {
		t.Fatalf("expected vanilla xray to be unaffected by the Sanaei gate, got %#v", result.Issues)
	}
}

// Case 4: an unknown (empty) binary identity must default to false so the
// Sanaei-specific error is never surfaced for a runtime we could not identify.
func TestUnknownBinaryDoesNotTriggerSanaeiGate(t *testing.T) {
	target := RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: ""},
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{forkAPIConfig(t)},
		},
	}
	provider := emptyOnlineUsersProvider(t, target)

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}
	if sanaeiGateHasIssueCode(result.Issues, SessionEvidenceIssueStatsUserOnlineNotEnabled) {
		t.Fatalf("expected an unknown runtime to not surface the Sanaei error, got %#v", result.Issues)
	}
}

// Unit-level discrimination: the gate fires for Sanaei host and container
// binaries (and an exec-path fallback) but never for vanilla xray/xray-core or
// an unknown binary.
func TestRuntimeIsSanaeiForkDiscriminatesBinaries(t *testing.T) {
	cases := []struct {
		name   string
		target RuntimeTarget
		want   bool
	}{
		{"host sanaei release", RuntimeTarget{Identity: RuntimeIdentity{Binary: "sanaei-linux-amd64"}}, true},
		{"container sanaei", RuntimeTarget{Identity: RuntimeIdentity{Binary: "sanaei"}}, true},
		{"exec-path fallback", RuntimeTarget{HostProcess: &HostProcessCandidate{ExecutablePath: "/usr/local/bin/sanaei-linux-amd64"}}, true},
		{"vanilla xray", RuntimeTarget{Identity: RuntimeIdentity{Binary: "xray"}}, false},
		{"vanilla xray-core", RuntimeTarget{Identity: RuntimeIdentity{Binary: "xray-core"}}, false},
		{"xray release suffix", RuntimeTarget{Identity: RuntimeIdentity{Binary: "xray-linux-amd64"}}, false},
		{"unknown empty", RuntimeTarget{Identity: RuntimeIdentity{Binary: ""}}, false},
	}

	for _, tc := range cases {
		if got := runtimeIsSanaeiFork(tc.target); got != tc.want {
			t.Fatalf("%s: runtimeIsSanaeiFork = %v, want %v", tc.name, got, tc.want)
		}
	}
}
