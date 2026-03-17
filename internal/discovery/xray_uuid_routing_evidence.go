package discovery

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

const xrayUUIDRoutingEvidenceProviderName = "xray_routing_api"

type xrayUUIDRoutingContextQuery func(ctx context.Context, runtime SessionRuntime, target RuntimeTarget, endpoint APIEndpoint, uuid string) (xrayUUIDRoutingContextQueryResult, error)

// XrayUUIDRoutingEvidenceProvider resolves one runtime target, verifies that a
// safe RoutingService-backed UUID backend candidate exists, and ingests live
// routing contexts when a concrete query implementation is configured.
//
// The default provider intentionally stops at candidate-only state unless a
// live RoutingService query function is injected. This keeps the trust boundary
// explicit while still giving later classifier phases a real ingestion model.
type XrayUUIDRoutingEvidenceProvider struct {
	Discoverer           RuntimeTargetDiscoverer
	APIDetector          APICapabilityDetector
	ProbeEndpoint        xrayEndpointProbe
	QueryRoutingContext  xrayUUIDRoutingContextQuery
	DialRoutingTransport xrayUUIDRoutingTransportDialer
	BackendDeriver       UUIDNonIPBackendCandidateDeriver
}

// NewXrayUUIDRoutingEvidenceProvider returns the default RoutingService-backed
// UUID routing evidence provider.
func NewXrayUUIDRoutingEvidenceProvider(discoverer RuntimeTargetDiscoverer) XrayUUIDRoutingEvidenceProvider {
	return XrayUUIDRoutingEvidenceProvider{Discoverer: discoverer}
}

func (p XrayUUIDRoutingEvidenceProvider) Name() string {
	return xrayUUIDRoutingEvidenceProviderName
}

func (p XrayUUIDRoutingEvidenceProvider) ObserveUUIDRoutingEvidence(ctx context.Context, runtime SessionRuntime, uuid string) (UUIDRoutingEvidenceResult, error) {
	if err := runtime.Validate(); err != nil {
		return UUIDRoutingEvidenceResult{}, err
	}

	uuid = normalizeUUIDRoutingEvidenceKey(uuid)
	if uuid == "" {
		return UUIDRoutingEvidenceResult{}, fmt.Errorf("uuid routing evidence requires a non-empty uuid")
	}

	result := UUIDRoutingEvidenceResult{
		Provider: p.Name(),
		Runtime:  runtime,
		UUID:     uuid,
	}

	if p.Discoverer == nil {
		result.Issues = append(result.Issues, SessionEvidenceIssue{
			Code:    SessionEvidenceIssueUnavailable,
			Message: "runtime discovery is not configured for Xray-backed uuid routing evidence",
		})
		return result, nil
	}

	discoveryResult, err := p.Discoverer.Discover(ctx, Request{Sources: []DiscoverySource{runtime.Source}})
	if err != nil {
		result.Issues = append(result.Issues, SessionEvidenceIssue{
			Code:    SessionEvidenceIssueUnavailable,
			Message: fmt.Sprintf("runtime discovery failed while resolving Xray-backed uuid routing evidence: %v", err),
		})
		return result, nil
	}

	targets := matchRuntimeTargets(discoveryResult.Targets, runtime)
	if len(targets) == 0 {
		result.Issues = append(result.Issues, SessionEvidenceIssue{
			Code:    SessionEvidenceIssueUnavailable,
			Message: "no matching discovered runtime target is available for Xray-backed uuid routing evidence",
		})
		return result, nil
	}
	if len(targets) > 1 {
		result.Issues = append(result.Issues, SessionEvidenceIssue{
			Code:    SessionEvidenceIssueInsufficient,
			Message: "multiple discovered runtime targets matched the requested runtime; Xray-backed uuid routing evidence remains ambiguous",
		})
		return result, nil
	}

	target, err := p.apiDetector().EnrichTarget(ctx, targets[0])
	if err != nil {
		return UUIDRoutingEvidenceResult{}, err
	}

	candidate, err := p.candidateDeriver().Derive(ctx, target, uuid)
	if err != nil {
		return UUIDRoutingEvidenceResult{}, err
	}
	result.Candidate = &candidate
	if candidate.Status != UUIDNonIPBackendStatusCandidate {
		return result, nil
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
		result.Issues = append(result.Issues, SessionEvidenceIssue{
			Code:    SessionEvidenceIssueInsufficient,
			Message: "Xray RoutingService candidate was inferred, but only runtime-local API endpoint hints are available; no host-reachable endpoint mapping was evident for live uuid routing evidence",
		})
		return result, nil
	}

	endpoints := orderedAPIEndpoints(preferredAPIEndpoints(target))
	if len(endpoints) == 0 {
		result.Issues = append(result.Issues, SessionEvidenceIssue{
			Code:    SessionEvidenceIssueInsufficient,
			Message: "Xray RoutingService candidate was inferred, but no concrete API endpoint hint is available for live uuid routing evidence",
		})
		return result, nil
	}

	probe := p.endpointProbe()
	query := p.routingContextQuery()
	var reachable bool

	for _, endpoint := range endpoints {
		if err := ctx.Err(); err != nil {
			return UUIDRoutingEvidenceResult{}, err
		}

		if err := probe(ctx, endpoint); err != nil {
			result.Issues = append(result.Issues, endpointProbeIssue(endpoint, err))
			continue
		}
		reachable = true

		queryResult, err := query(ctx, runtime, target, endpoint, uuid)
		if err != nil {
			result.Issues = append(result.Issues, uuidRoutingQueryIssue(endpoint, err))
			continue
		}

		result.Issues = append(result.Issues, queryResult.Issues...)
		valid, dropped := normalizeUUIDRoutingContexts(runtime, uuid, queryResult.Contexts)
		result.Contexts = valid
		if dropped != 0 {
			result.Issues = append(result.Issues, SessionEvidenceIssue{
				Code:    SessionEvidenceIssueInsufficient,
				Message: fmt.Sprintf("ignored %d invalid live uuid routing evidence entries returned by Xray-backed observation", dropped),
			})
		}

		return result, nil
	}

	if !reachable {
		return result, nil
	}

	return result, nil
}

func (p XrayUUIDRoutingEvidenceProvider) apiDetector() APICapabilityDetector {
	return p.APIDetector.withDefaults()
}

func (p XrayUUIDRoutingEvidenceProvider) endpointProbe() xrayEndpointProbe {
	if p.ProbeEndpoint != nil {
		return p.ProbeEndpoint
	}

	return defaultXrayEndpointProbe
}

func (p XrayUUIDRoutingEvidenceProvider) routingContextQuery() xrayUUIDRoutingContextQuery {
	if p.QueryRoutingContext != nil {
		return p.QueryRoutingContext
	}

	return defaultXrayUUIDRoutingContextQuery(p.routingTransportDialer())
}

func (p XrayUUIDRoutingEvidenceProvider) routingTransportDialer() xrayUUIDRoutingTransportDialer {
	if p.DialRoutingTransport != nil {
		return p.DialRoutingTransport
	}

	return dialXrayRoutingEndpoint
}

func (p XrayUUIDRoutingEvidenceProvider) candidateDeriver() UUIDNonIPBackendCandidateDeriver {
	if p.BackendDeriver.readFile == nil && p.BackendDeriver.readDir == nil && p.BackendDeriver.statPath == nil {
		return NewUUIDNonIPBackendCandidateDeriver()
	}

	return p.BackendDeriver.withDefaults()
}

func normalizeUUIDRoutingContexts(runtime SessionRuntime, uuid string, observed []UUIDRoutingContext) ([]UUIDRoutingContext, int) {
	if len(observed) == 0 {
		return nil, 0
	}

	normalized := make([]UUIDRoutingContext, 0, len(observed))
	seen := make(map[string]struct{}, len(observed))
	dropped := 0

	for _, context := range observed {
		if context.Runtime == (SessionRuntime{}) {
			context.Runtime = runtime
		} else if !sameEvidenceRuntime(runtime, context.Runtime) {
			dropped++
			continue
		}

		if normalizeUUIDRoutingEvidenceKey(context.UUID) == "" {
			context.UUID = uuid
		} else if normalizeUUIDRoutingEvidenceKey(context.UUID) != normalizeUUIDRoutingEvidenceKey(uuid) {
			dropped++
			continue
		}

		var err error
		context.UUID = normalizeUUIDRoutingEvidenceKey(context.UUID)
		context.Network = strings.ToLower(strings.TrimSpace(context.Network))
		context.Protocol = strings.ToLower(strings.TrimSpace(context.Protocol))
		context.TargetDomain = strings.TrimSpace(context.TargetDomain)
		context.InboundTag = strings.TrimSpace(context.InboundTag)
		context.OutboundTag = strings.TrimSpace(context.OutboundTag)
		context.SourceIPs, err = normalizeUUIDRoutingIPs(context.SourceIPs)
		if err != nil {
			dropped++
			continue
		}
		context.LocalIPs, err = normalizeUUIDRoutingIPs(context.LocalIPs)
		if err != nil {
			dropped++
			continue
		}
		context.TargetIPs, err = normalizeUUIDRoutingIPs(context.TargetIPs)
		if err != nil {
			dropped++
			continue
		}
		if err := context.Validate(); err != nil {
			dropped++
			continue
		}

		key := context.Key()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, context)
	}

	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].Key() < normalized[j].Key()
	})

	return normalized, dropped
}

func uuidRoutingQueryIssue(endpoint APIEndpoint, err error) SessionEvidenceIssue {
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
		Message: fmt.Sprintf("live uuid routing evidence query failed for Xray API endpoint %s: %v", describeAPIEndpoint(endpoint), err),
	}
}
