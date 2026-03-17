package discovery

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type stubProvider struct {
	name   string
	source DiscoverySource
	result ProviderResult
	err    error
	calls  int
}

func (p *stubProvider) Name() string {
	return p.name
}

func (p *stubProvider) Source() DiscoverySource {
	return p.source
}

func (p *stubProvider) Discover(_ context.Context, _ Request) (ProviderResult, error) {
	p.calls++
	return p.result, p.err
}

func TestRequestAllowsSource(t *testing.T) {
	req := Request{
		Sources: []DiscoverySource{DiscoverySourceDockerContainer},
	}

	if req.Allows(DiscoverySourceHostProcess) {
		t.Fatal("expected host process source to be filtered out")
	}

	if !req.Allows(DiscoverySourceDockerContainer) {
		t.Fatal("expected docker source to be allowed")
	}
}

func TestRequestValidateRejectsInvalidSourceFilter(t *testing.T) {
	err := Request{
		Sources: []DiscoverySource{"invalid"},
	}.Validate()
	if err == nil {
		t.Fatal("expected invalid request to fail validation")
	}

	if !strings.Contains(err.Error(), "invalid discovery source filter") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServiceDiscoverAggregatesTargetsAcrossProviders(t *testing.T) {
	hostProvider := &stubProvider{
		name:   "host",
		source: DiscoverySourceHostProcess,
		result: ProviderResult{Targets: []RuntimeTarget{
			{
				Source: DiscoverySourceHostProcess,
				Identity: RuntimeIdentity{
					Name:   "edge-a",
					Binary: "xray",
				},
				HostProcess: &HostProcessCandidate{PID: 1001},
			},
		}},
	}

	dockerProvider := &stubProvider{
		name:   "docker",
		source: DiscoverySourceDockerContainer,
		result: ProviderResult{Targets: []RuntimeTarget{
			{
				Source: DiscoverySourceDockerContainer,
				Identity: RuntimeIdentity{
					Name:   "edge-b",
					Binary: "xray",
				},
				DockerContainer: &DockerContainerCandidate{ID: "container-1"},
			},
		}},
	}

	service := NewService(hostProvider, dockerProvider)

	result, err := service.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(result.Targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(result.Targets))
	}

	if result.Targets[0].Identity.Name != "edge-a" || result.Targets[1].Identity.Name != "edge-b" {
		t.Fatalf("unexpected target order: %#v", result.Targets)
	}

	if result.HasErrors() {
		t.Fatalf("expected no provider errors, got %#v", result.ProviderErrors)
	}
}

func TestServiceDiscoverReturnsEmptyResultWhenProvidersReturnNothing(t *testing.T) {
	service := NewService(&stubProvider{
		name:   "host",
		source: DiscoverySourceHostProcess,
		result: ProviderResult{},
	})

	result, err := service.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(result.Targets) != 0 {
		t.Fatalf("expected no targets, got %d", len(result.Targets))
	}

	if result.HasErrors() {
		t.Fatalf("expected no provider errors, got %#v", result.ProviderErrors)
	}
}

func TestServiceDiscoverCapturesProviderErrorsAndPreservesPartialResults(t *testing.T) {
	hostProvider := &stubProvider{
		name:   "host",
		source: DiscoverySourceHostProcess,
		result: ProviderResult{Targets: []RuntimeTarget{
			{
				Source:      DiscoverySourceHostProcess,
				Identity:    RuntimeIdentity{Name: "edge-a", Binary: "xray"},
				HostProcess: &HostProcessCandidate{PID: 2001},
			},
		}},
	}

	dockerProvider := &stubProvider{
		name:   "docker",
		source: DiscoverySourceDockerContainer,
		result: ProviderResult{
			Issues: []ProviderError{
				{
					Code:       ProviderErrorCodeUnavailable,
					Message:    "Docker daemon is unavailable.",
					Hint:       "Start Docker or check the active Docker context.",
					Restricted: true,
				},
			},
		},
	}

	service := NewService(hostProvider, dockerProvider)

	result, err := service.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(result.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(result.Targets))
	}

	if len(result.ProviderErrors) != 1 {
		t.Fatalf("expected 1 provider error, got %d", len(result.ProviderErrors))
	}

	if result.ProviderErrors[0].Provider != "docker" {
		t.Fatalf("expected docker provider error, got %#v", result.ProviderErrors[0])
	}

	if !strings.Contains(result.ProviderErrors[0].Message, "Docker daemon is unavailable") {
		t.Fatalf("unexpected provider error message: %#v", result.ProviderErrors[0])
	}

	if result.HasFatalErrors() {
		t.Fatalf("expected docker availability issue to remain non-fatal, got %#v", result.ProviderErrors)
	}

	if !result.HasLimitations() {
		t.Fatalf("expected docker availability issue to be treated as a limitation, got %#v", result.ProviderErrors)
	}
}

func TestServiceDiscoverWrapsGenericProviderErrorsAsFatalExecutionFailures(t *testing.T) {
	service := NewService(&stubProvider{
		name:   "docker",
		source: DiscoverySourceDockerContainer,
		err:    errors.New("docker backend crashed"),
	})

	result, err := service.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(result.ProviderErrors) != 1 {
		t.Fatalf("expected 1 provider error, got %d", len(result.ProviderErrors))
	}

	if result.ProviderErrors[0].Code != ProviderErrorCodeExecutionFailed {
		t.Fatalf("expected execution_failed provider error, got %#v", result.ProviderErrors[0])
	}

	if !result.HasFatalErrors() {
		t.Fatalf("expected generic provider error to be fatal, got %#v", result.ProviderErrors)
	}

	if result.HasLimitations() {
		t.Fatalf("expected generic provider error not to be treated as a limitation, got %#v", result.ProviderErrors)
	}
}

func TestServiceDiscoverPreservesStructuredProviderErrorReturnedAsError(t *testing.T) {
	service := NewService(&stubProvider{
		name:   "docker",
		source: DiscoverySourceDockerContainer,
		err: ProviderError{
			Code:       ProviderErrorCodePermissionDenied,
			Message:    "Docker access was denied.",
			Hint:       "Run RayLimit as root or add the current user to the docker group.",
			Restricted: true,
		},
	})

	result, err := service.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(result.ProviderErrors) != 1 {
		t.Fatalf("expected 1 provider error, got %d", len(result.ProviderErrors))
	}

	if result.ProviderErrors[0].Code != ProviderErrorCodePermissionDenied {
		t.Fatalf("expected permission_denied provider error, got %#v", result.ProviderErrors[0])
	}

	if !result.HasLimitations() {
		t.Fatalf("expected structured provider error to be treated as a limitation, got %#v", result.ProviderErrors)
	}

	if result.HasFatalErrors() {
		t.Fatalf("expected structured limitation to remain non-fatal, got %#v", result.ProviderErrors)
	}
}

func TestServiceDiscoverNormalizesStructuredIssueProviderMetadata(t *testing.T) {
	service := NewService(&stubProvider{
		name:   "host",
		source: DiscoverySourceHostProcess,
		result: ProviderResult{
			Issues: []ProviderError{
				{
					Code:    ProviderErrorCodePartialAccess,
					Message: "Host process metadata was partially unreadable for 2 process entries.",
				},
			},
		},
	})

	result, err := service.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(result.ProviderErrors) != 1 {
		t.Fatalf("expected 1 provider error, got %d", len(result.ProviderErrors))
	}

	if result.ProviderErrors[0].Provider != "host" || result.ProviderErrors[0].Source != DiscoverySourceHostProcess {
		t.Fatalf("expected provider metadata to be normalized, got %#v", result.ProviderErrors[0])
	}
}

func TestServiceDiscoverPreservesStableProviderOrder(t *testing.T) {
	first := &stubProvider{
		name:   "first",
		source: DiscoverySourceHostProcess,
		result: ProviderResult{Targets: []RuntimeTarget{
			{
				Source:      DiscoverySourceHostProcess,
				Identity:    RuntimeIdentity{Name: "a", Binary: "xray"},
				HostProcess: &HostProcessCandidate{PID: 1},
			},
			{
				Source:      DiscoverySourceHostProcess,
				Identity:    RuntimeIdentity{Name: "b", Binary: "xray"},
				HostProcess: &HostProcessCandidate{PID: 2},
			},
		}},
	}

	second := &stubProvider{
		name:   "second",
		source: DiscoverySourceDockerContainer,
		result: ProviderResult{Targets: []RuntimeTarget{
			{
				Source:          DiscoverySourceDockerContainer,
				Identity:        RuntimeIdentity{Name: "c", Binary: "xray"},
				DockerContainer: &DockerContainerCandidate{ID: "c1"},
			},
		}},
	}

	service := NewService(first, second)

	result, err := service.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if got := []string{
		result.Targets[0].Identity.Name,
		result.Targets[1].Identity.Name,
		result.Targets[2].Identity.Name,
	}; strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("unexpected target ordering: %v", got)
	}
}

func TestServiceDiscoverSkipsProvidersExcludedByRequest(t *testing.T) {
	hostProvider := &stubProvider{
		name:   "host",
		source: DiscoverySourceHostProcess,
		result: ProviderResult{Targets: []RuntimeTarget{
			{
				Source:      DiscoverySourceHostProcess,
				Identity:    RuntimeIdentity{Name: "host-target", Binary: "xray"},
				HostProcess: &HostProcessCandidate{PID: 3001},
			},
		}},
	}

	dockerProvider := &stubProvider{
		name:   "docker",
		source: DiscoverySourceDockerContainer,
		result: ProviderResult{Targets: []RuntimeTarget{
			{
				Source:          DiscoverySourceDockerContainer,
				Identity:        RuntimeIdentity{Name: "docker-target", Binary: "xray"},
				DockerContainer: &DockerContainerCandidate{ID: "docker-1"},
			},
		}},
	}

	service := NewService(hostProvider, dockerProvider)

	result, err := service.Discover(context.Background(), Request{
		Sources: []DiscoverySource{DiscoverySourceDockerContainer},
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if hostProvider.calls != 0 {
		t.Fatalf("expected host provider to be skipped, got %d calls", hostProvider.calls)
	}

	if dockerProvider.calls != 1 {
		t.Fatalf("expected docker provider to be called once, got %d", dockerProvider.calls)
	}

	if len(result.Targets) != 1 || result.Targets[0].Identity.Name != "docker-target" {
		t.Fatalf("unexpected filtered targets: %#v", result.Targets)
	}
}

func TestServiceDiscoverRejectsTargetWithMismatchedSource(t *testing.T) {
	service := NewService(&stubProvider{
		name:   "host",
		source: DiscoverySourceHostProcess,
		result: ProviderResult{Targets: []RuntimeTarget{
			{
				Source:          DiscoverySourceDockerContainer,
				Identity:        RuntimeIdentity{Name: "mismatch", Binary: "xray"},
				DockerContainer: &DockerContainerCandidate{ID: "container-2"},
			},
		}},
	})

	result, err := service.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(result.Targets) != 0 {
		t.Fatalf("expected mismatched target to be rejected, got %#v", result.Targets)
	}

	if len(result.ProviderErrors) != 1 {
		t.Fatalf("expected 1 provider error, got %d", len(result.ProviderErrors))
	}

	if result.ProviderErrors[0].Code != ProviderErrorCodeInvalidData {
		t.Fatalf("expected invalid_data provider error, got %#v", result.ProviderErrors[0])
	}

	if !strings.Contains(result.ProviderErrors[0].Message, "does not match provider source") {
		t.Fatalf("unexpected provider error message: %#v", result.ProviderErrors[0])
	}
}
