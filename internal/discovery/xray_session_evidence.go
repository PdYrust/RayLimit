package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const xraySessionEvidenceProviderName = "xray_api"

// xrayEndpointDialTimeout bounds the reachability probe dial so an unresponsive
// endpoint cannot stall discovery.
const xrayEndpointDialTimeout = 2 * time.Second

// RuntimeTargetDiscoverer provides runtime targets for Xray-backed evidence lookup.
type RuntimeTargetDiscoverer interface {
	Discover(ctx context.Context, req Request) (Result, error)
}

type xrayEndpointProbe func(ctx context.Context, endpoint APIEndpoint) error
type xraySessionQuery func(ctx context.Context, target RuntimeTarget, endpoint APIEndpoint) ([]SessionEvidence, error)

// XraySessionEvidenceProvider resolves runtime targets, inspects Xray API
// capability metadata, and queries live session evidence from reachable Xray
// API endpoints when conservative evidence is available.
type XraySessionEvidenceProvider struct {
	Discoverer             RuntimeTargetDiscoverer
	APIDetector            APICapabilityDetector
	ProbeEndpoint          xrayEndpointProbe
	RunAPICommand          xrayAPICommandRunner
	RunContainerAPICommand xrayContainerAPICommandRunner
	QuerySessions          xraySessionQuery
	// Timeout bounds each xray API invocation. When zero the provider falls
	// back to defaultXrayAPITimeout.
	Timeout time.Duration
	// XrayBinaryOverride, when set, takes precedence over the detected Xray
	// executable path / binary name when querying the API.
	XrayBinaryOverride string
	// ContainerCLI overrides the container runtime CLI used for containerized
	// runtime queries. An empty value uses the default ("docker").
	ContainerCLI string
}

// XraySessionEvidenceProviderOption customizes a provider at construction time.
type XraySessionEvidenceProviderOption func(*XraySessionEvidenceProvider)

// NewXraySessionEvidenceProvider returns the default Xray-backed evidence provider.
func NewXraySessionEvidenceProvider(discoverer RuntimeTargetDiscoverer, opts ...XraySessionEvidenceProviderOption) XraySessionEvidenceProvider {
	provider := XraySessionEvidenceProvider{
		Discoverer: discoverer,
		Timeout:    defaultXrayAPITimeout,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&provider)
		}
	}

	return provider
}

func (p XraySessionEvidenceProvider) Name() string {
	return xraySessionEvidenceProviderName
}

func (p XraySessionEvidenceProvider) ObserveSessions(ctx context.Context, runtime SessionRuntime) (SessionEvidenceResult, error) {
	return p.observe(ctx, runtime)
}

func (p XraySessionEvidenceProvider) observe(ctx context.Context, runtime SessionRuntime) (SessionEvidenceResult, error) {
	if err := runtime.Validate(); err != nil {
		return SessionEvidenceResult{}, err
	}

	result := SessionEvidenceResult{
		Provider: p.Name(),
		Runtime:  runtime,
	}

	if p.Discoverer == nil {
		result.Issues = append(result.Issues, SessionEvidenceIssue{
			Code:    SessionEvidenceIssueUnavailable,
			Message: "runtime discovery is not configured for Xray-backed session evidence",
		})
		return result, nil
	}

	discoveryResult, err := p.Discoverer.Discover(ctx, Request{Sources: []DiscoverySource{runtime.Source}})
	if err != nil {
		result.Issues = append(result.Issues, SessionEvidenceIssue{
			Code:    SessionEvidenceIssueUnavailable,
			Message: fmt.Sprintf("runtime discovery failed while resolving Xray-backed session evidence: %v", err),
		})
		return result, nil
	}

	targets := matchRuntimeTargets(discoveryResult.Targets, runtime)
	if len(targets) == 0 {
		result.Issues = append(result.Issues, SessionEvidenceIssue{
			Code:    SessionEvidenceIssueUnavailable,
			Message: "no matching discovered runtime target is available for Xray-backed session evidence",
		})
		return result, nil
	}
	if len(targets) > 1 {
		result.Issues = append(result.Issues, SessionEvidenceIssue{
			Code:    SessionEvidenceIssueInsufficient,
			Message: "multiple discovered runtime targets matched the requested runtime; Xray-backed session evidence remains ambiguous",
		})
		return result, nil
	}

	target, err := p.apiDetector().EnrichTarget(ctx, targets[0])
	if err != nil {
		return SessionEvidenceResult{}, err
	}

	if target.APICapability == nil {
		result.Issues = append(result.Issues, SessionEvidenceIssue{
			Code:    SessionEvidenceIssueUnavailable,
			Message: "no Xray API capability metadata is available for the selected runtime",
		})
		return result, nil
	}

	switch target.APICapability.Status {
	case APICapabilityStatusNotEvident:
		result.Issues = append(result.Issues, SessionEvidenceIssue{
			Code:    SessionEvidenceIssueUnavailable,
			Message: target.APICapability.Reason,
		})
		return result, nil
	case APICapabilityStatusUnknown:
		issueCode := SessionEvidenceIssueInsufficient
		if target.APICapability.Limitation == APICapabilityLimitationPermissionDenied {
			issueCode = SessionEvidenceIssuePermissionDenied
		}
		result.Issues = append(result.Issues, SessionEvidenceIssue{
			Code:    issueCode,
			Message: target.APICapability.Reason,
		})
		return result, nil
	}

	if requiresHostReachableAPIEndpoints(target) && len(target.ReachableAPIEndpoints) == 0 && len(target.APIEndpoints) != 0 {
		message := "Xray API capability was inferred, but only runtime-local API endpoint hints are available; no host-reachable endpoint mapping was evident for live session evidence"
		result.Issues = append(result.Issues, SessionEvidenceIssue{
			Code:    SessionEvidenceIssueInsufficient,
			Message: message,
		})
		return result, nil
	}

	endpoints := orderedAPIEndpoints(preferredAPIEndpoints(target))
	if len(endpoints) == 0 {
		result.Issues = append(result.Issues, SessionEvidenceIssue{
			Code:    SessionEvidenceIssueInsufficient,
			Message: "Xray API capability was inferred, but no concrete API endpoint hint is available for live session evidence",
		})
		return result, nil
	}

	probe := p.endpointProbe()
	query := p.sessionQuery()

	for _, endpoint := range endpoints {
		if err := ctx.Err(); err != nil {
			return SessionEvidenceResult{}, err
		}

		if err := probe(ctx, endpoint); err != nil {
			result.Issues = append(result.Issues, endpointProbeIssue(endpoint, err))
			continue
		}

		observed, err := query(ctx, target, endpoint)
		if err != nil {
			result.Issues = append(result.Issues, sessionQueryIssue(endpoint, err))
			continue
		}

		valid, dropped := normalizeSessionEvidence(runtime, endpoint, observed)
		result.Evidence = append(result.Evidence, valid...)
		if dropped != 0 {
			result.Issues = append(result.Issues, SessionEvidenceIssue{
				Code:    SessionEvidenceIssueInsufficient,
				Message: fmt.Sprintf("ignored %d invalid live session evidence entries returned by Xray-backed observation", dropped),
			})
		}

		return result, nil
	}

	return result, nil
}

func (p XraySessionEvidenceProvider) apiDetector() APICapabilityDetector {
	detector := p.APIDetector
	if strings.TrimSpace(detector.containerCLI) == "" {
		detector.containerCLI = normalizeContainerCLI(p.ContainerCLI)
	}

	return detector.withDefaults()
}

func (p XraySessionEvidenceProvider) endpointProbe() xrayEndpointProbe {
	if p.ProbeEndpoint != nil {
		return p.ProbeEndpoint
	}

	return defaultXrayEndpointProbe
}

func (p XraySessionEvidenceProvider) sessionQuery() xraySessionQuery {
	if p.QuerySessions != nil {
		return p.QuerySessions
	}

	return defaultXraySessionQuery(p.apiCommandRunner(), p.containerAPICommandRunner(), p.resolveTimeout(), strings.TrimSpace(p.XrayBinaryOverride))
}

// resolveContainerCLI returns the configured container CLI, defaulting to
// "docker" when unset.
func (p XraySessionEvidenceProvider) resolveContainerCLI() string {
	return normalizeContainerCLI(p.ContainerCLI)
}

// resolveTimeout returns the configured per-call xray API timeout, falling back
// to defaultXrayAPITimeout when unset.
func (p XraySessionEvidenceProvider) resolveTimeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}

	return defaultXrayAPITimeout
}

func (p XraySessionEvidenceProvider) apiCommandRunner() xrayAPICommandRunner {
	if p.RunAPICommand != nil {
		return p.RunAPICommand
	}

	return defaultXrayAPICommandRunner
}

func (p XraySessionEvidenceProvider) containerAPICommandRunner() xrayContainerAPICommandRunner {
	if p.RunContainerAPICommand != nil {
		return p.RunContainerAPICommand
	}

	cli := p.resolveContainerCLI()
	return func(ctx context.Context, containerID string, binary string, server string, timeout time.Duration, command string, args ...string) ([]byte, error) {
		return runXrayContainerAPICommand(ctx, cli, containerID, binary, server, timeout, command, args...)
	}
}

func matchRuntimeTargets(targets []RuntimeTarget, runtime SessionRuntime) []RuntimeTarget {
	if len(targets) == 0 {
		return nil
	}

	matches := make([]RuntimeTarget, 0, len(targets))
	for _, target := range targets {
		if runtime.MatchesTarget(target) {
			matches = append(matches, target)
		}
	}

	return matches
}

func orderedAPIEndpoints(endpoints []APIEndpoint) []APIEndpoint {
	if len(endpoints) == 0 {
		return nil
	}

	ordered := make([]APIEndpoint, len(endpoints))
	copy(ordered, endpoints)
	sort.Slice(ordered, func(i, j int) bool {
		left := ordered[i]
		right := ordered[j]
		leftKey := strings.Join([]string{
			string(left.Network),
			left.Address,
			fmt.Sprintf("%d", left.Port),
			left.Path,
			left.Name,
		}, "|")
		rightKey := strings.Join([]string{
			string(right.Network),
			right.Address,
			fmt.Sprintf("%d", right.Port),
			right.Path,
			right.Name,
		}, "|")
		return leftKey < rightKey
	})

	return ordered
}

func preferredAPIEndpoints(target RuntimeTarget) []APIEndpoint {
	if len(target.ReachableAPIEndpoints) != 0 {
		return target.ReachableAPIEndpoints
	}

	return target.APIEndpoints
}

func requiresHostReachableAPIEndpoints(target RuntimeTarget) bool {
	return strings.TrimSpace(targetContainerID(target)) != ""
}

func defaultXrayEndpointProbe(ctx context.Context, endpoint APIEndpoint) error {
	var network string
	var address string

	switch endpoint.Network {
	case EndpointNetworkTCP:
		network = "tcp"
		address = net.JoinHostPort(normalizeWildcardListenHost(endpoint.Address), strconv.Itoa(endpoint.Port))
	case EndpointNetworkUnix:
		network = "unix"
		address = strings.TrimSpace(endpoint.Path)
	default:
		return fmt.Errorf("unsupported api endpoint network %q", endpoint.Network)
	}

	conn, err := (&net.Dialer{Timeout: xrayEndpointDialTimeout}).DialContext(ctx, network, address)
	if err != nil {
		return err
	}
	_ = conn.Close()

	return nil
}

func endpointProbeIssue(endpoint APIEndpoint, err error) SessionEvidenceIssue {
	code := SessionEvidenceIssueUnavailable
	if isPermissionError(err) {
		code = SessionEvidenceIssuePermissionDenied
	}

	return SessionEvidenceIssue{
		Code:    code,
		Message: fmt.Sprintf("Xray API endpoint %s was not reachable: %v", describeAPIEndpoint(endpoint), err),
	}
}

func sessionQueryIssue(endpoint APIEndpoint, err error) SessionEvidenceIssue {
	code := SessionEvidenceIssueUnavailable
	if queryCode, ok := sessionQueryErrorCode(err); ok {
		return SessionEvidenceIssue{
			Code:    queryCode,
			Message: err.Error(),
		}
	}
	if isPermissionError(err) {
		code = SessionEvidenceIssuePermissionDenied
	}

	return SessionEvidenceIssue{
		Code:    code,
		Message: fmt.Sprintf("live session query failed for Xray API endpoint %s: %v", describeAPIEndpoint(endpoint), err),
	}
}

func normalizeSessionEvidence(runtime SessionRuntime, endpoint APIEndpoint, observed []SessionEvidence) ([]SessionEvidence, int) {
	if len(observed) == 0 {
		return nil, 0
	}

	valid := make([]SessionEvidence, 0, len(observed))
	dropped := 0
	for _, evidence := range observed {
		if !evidence.Runtime.Source.Valid() {
			evidence.Runtime = runtime
		}
		if !evidence.Session.Runtime.Source.Valid() {
			evidence.Session.Runtime = runtime
		}
		if strings.TrimSpace(evidence.Note) == "" {
			evidence.Note = fmt.Sprintf("observed via Xray API endpoint %s", describeAPIEndpoint(endpoint))
		}
		if err := evidence.Validate(); err != nil {
			dropped++
			continue
		}

		valid = append(valid, evidence)
	}

	return valid, dropped
}

func describeAPIEndpoint(endpoint APIEndpoint) string {
	switch endpoint.Network {
	case EndpointNetworkUnix:
		return fmt.Sprintf("unix:%s", strings.TrimSpace(endpoint.Path))
	default:
		host := strings.TrimSpace(endpoint.Address)
		if host == "" {
			host = "127.0.0.1"
		}
		return fmt.Sprintf("%s:%d", host, endpoint.Port)
	}
}

func isPermissionError(err error) bool {
	return errors.Is(err, os.ErrPermission) || strings.Contains(strings.ToLower(err.Error()), "permission denied")
}
