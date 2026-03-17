package discovery

import (
	"errors"
	"fmt"
)

// DiscoverySource identifies where a runtime candidate was observed.
type DiscoverySource string

const (
	DiscoverySourceHostProcess     DiscoverySource = "host_process"
	DiscoverySourceDockerContainer DiscoverySource = "docker_container"
)

func (s DiscoverySource) Valid() bool {
	switch s {
	case DiscoverySourceHostProcess, DiscoverySourceDockerContainer:
		return true
	default:
		return false
	}
}

// DetectionConfidence describes how strongly the observed evidence suggests an Xray runtime.
type DetectionConfidence string

const (
	DetectionConfidenceLow    DetectionConfidence = "low"
	DetectionConfidenceMedium DetectionConfidence = "medium"
	DetectionConfidenceHigh   DetectionConfidence = "high"
)

func (c DetectionConfidence) Valid() bool {
	switch c {
	case DetectionConfidenceLow, DetectionConfidenceMedium, DetectionConfidenceHigh:
		return true
	default:
		return false
	}
}

// EndpointNetwork identifies the network family for a runtime endpoint.
type EndpointNetwork string

const (
	EndpointNetworkTCP  EndpointNetwork = "tcp"
	EndpointNetworkUnix EndpointNetwork = "unix"
)

func (n EndpointNetwork) Valid() bool {
	switch n {
	case EndpointNetworkTCP, EndpointNetworkUnix:
		return true
	default:
		return false
	}
}

// RuntimeTarget represents a discovered Xray-related runtime candidate.
type RuntimeTarget struct {
	Source                DiscoverySource           `json:"source"`
	Identity              RuntimeIdentity           `json:"identity"`
	HostProcess           *HostProcessCandidate     `json:"host_process,omitempty"`
	DockerContainer       *DockerContainerCandidate `json:"docker_container,omitempty"`
	APICapability         *APICapability            `json:"api_capability,omitempty"`
	APIEndpoints          []APIEndpoint             `json:"api_endpoints,omitempty"`
	ReachableAPIEndpoints []APIEndpoint             `json:"reachable_api_endpoints,omitempty"`
	Inbounds              []InboundSummary          `json:"inbounds,omitempty"`
	Outbounds             []OutboundSummary         `json:"outbounds,omitempty"`
	Evidence              *DetectionEvidence        `json:"evidence,omitempty"`
}

// Validate checks that a runtime target is internally consistent.
func (t RuntimeTarget) Validate() error {
	if !t.Source.Valid() {
		return fmt.Errorf("invalid discovery source %q", t.Source)
	}

	switch t.Source {
	case DiscoverySourceHostProcess:
		if t.HostProcess == nil {
			return errors.New("host_process source requires a host process candidate")
		}
		if t.DockerContainer != nil {
			return errors.New("host_process source cannot include a docker container candidate")
		}
	case DiscoverySourceDockerContainer:
		if t.DockerContainer == nil {
			return errors.New("docker_container source requires a docker container candidate")
		}
		if t.HostProcess != nil {
			return errors.New("docker_container source cannot include a host process candidate")
		}
	}

	if t.Evidence != nil {
		if err := t.Evidence.Validate(); err != nil {
			return fmt.Errorf("invalid detection evidence: %w", err)
		}
	}

	if t.APICapability != nil {
		if err := t.APICapability.Validate(); err != nil {
			return fmt.Errorf("invalid api capability: %w", err)
		}
	}

	for i, endpoint := range t.APIEndpoints {
		if err := endpoint.Validate(); err != nil {
			return fmt.Errorf("invalid api endpoint at index %d: %w", i, err)
		}
	}
	for i, endpoint := range t.ReachableAPIEndpoints {
		if err := endpoint.Validate(); err != nil {
			return fmt.Errorf("invalid reachable api endpoint at index %d: %w", i, err)
		}
	}

	for i, inbound := range t.Inbounds {
		if err := inbound.Validate(); err != nil {
			return fmt.Errorf("invalid inbound summary at index %d: %w", i, err)
		}
	}

	return nil
}

// RuntimeIdentity holds basic user-relevant identity for a candidate runtime.
type RuntimeIdentity struct {
	Name    string `json:"name,omitempty"`
	Binary  string `json:"binary,omitempty"`
	Version string `json:"version,omitempty"`
}

// HostProcessCandidate describes a candidate discovered from the local process table.
type HostProcessCandidate struct {
	PID                 int      `json:"pid,omitempty"`
	ExecutablePath      string   `json:"executable_path,omitempty"`
	CommandLine         []string `json:"command_line,omitempty"`
	WorkingDirectory    string   `json:"working_directory,omitempty"`
	ContainerID         string   `json:"container_id,omitempty"`
	ConfigPaths         []string `json:"config_paths,omitempty"`
	ResolvedConfigPaths []string `json:"resolved_config_paths,omitempty"`
}

// DockerContainerCandidate describes a candidate discovered from a container runtime.
type DockerContainerCandidate struct {
	ID          string            `json:"id,omitempty"`
	Name        string            `json:"name,omitempty"`
	Image       string            `json:"image,omitempty"`
	CommandLine []string          `json:"command_line,omitempty"`
	State       string            `json:"state,omitempty"`
	Status      string            `json:"status,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	ConfigPaths []string          `json:"config_paths,omitempty"`
}

// APICapabilityStatus describes how confidently an API capability can be inferred.
type APICapabilityStatus string

const (
	APICapabilityStatusLikelyConfigured APICapabilityStatus = "likely_configured"
	APICapabilityStatusNotEvident       APICapabilityStatus = "not_evident"
	APICapabilityStatusUnknown          APICapabilityStatus = "unknown"
)

func (s APICapabilityStatus) Valid() bool {
	switch s {
	case APICapabilityStatusLikelyConfigured, APICapabilityStatusNotEvident, APICapabilityStatusUnknown:
		return true
	default:
		return false
	}
}

// APICapabilityLimitation identifies why API capability could not be inferred
// more precisely.
type APICapabilityLimitation string

const (
	APICapabilityLimitationPermissionDenied  APICapabilityLimitation = "permission_denied"
	APICapabilityLimitationMissingConfigPath APICapabilityLimitation = "missing_config_path"
	APICapabilityLimitationIncompleteConfig  APICapabilityLimitation = "incomplete_config"
	APICapabilityLimitationMissingConfigHint APICapabilityLimitation = "missing_config_hint"
)

func (l APICapabilityLimitation) Valid() bool {
	switch l {
	case "", APICapabilityLimitationPermissionDenied, APICapabilityLimitationMissingConfigPath, APICapabilityLimitationIncompleteConfig, APICapabilityLimitationMissingConfigHint:
		return true
	default:
		return false
	}
}

// APICapability captures the current evidence for Xray API exposure.
type APICapability struct {
	Status     APICapabilityStatus     `json:"status"`
	Reason     string                  `json:"reason,omitempty"`
	Limitation APICapabilityLimitation `json:"limitation,omitempty"`
}

// Validate checks that the API capability payload is internally consistent.
func (c APICapability) Validate() error {
	if !c.Status.Valid() {
		return fmt.Errorf("invalid api capability status %q", c.Status)
	}
	if !c.Limitation.Valid() {
		return fmt.Errorf("invalid api capability limitation %q", c.Limitation)
	}

	return nil
}

// APIEndpoint describes a control or inspection endpoint exposed by a runtime.
type APIEndpoint struct {
	Name    string          `json:"name,omitempty"`
	Network EndpointNetwork `json:"network,omitempty"`
	Address string          `json:"address,omitempty"`
	Port    int             `json:"port,omitempty"`
	Path    string          `json:"path,omitempty"`
	TLS     bool            `json:"tls,omitempty"`
}

// Validate checks that an API endpoint is internally consistent.
func (e APIEndpoint) Validate() error {
	if e.Network != "" && !e.Network.Valid() {
		return fmt.Errorf("invalid endpoint network %q", e.Network)
	}

	if e.Port < 0 || e.Port > 65535 {
		return errors.New("endpoint port must be between 0 and 65535")
	}

	if e.Network == EndpointNetworkUnix && e.Port != 0 {
		return errors.New("unix endpoints cannot define a port")
	}

	return nil
}

// InboundSummary is a compact view of a discovered inbound definition.
type InboundSummary struct {
	Tag           string `json:"tag,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	ListenAddress string `json:"listen_address,omitempty"`
	Port          int    `json:"port,omitempty"`
}

// Validate checks that an inbound summary is internally consistent.
func (s InboundSummary) Validate() error {
	if s.Port < 0 || s.Port > 65535 {
		return errors.New("inbound port must be between 0 and 65535")
	}

	return nil
}

// OutboundSummary is a compact view of a discovered outbound definition.
type OutboundSummary struct {
	Tag      string `json:"tag,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// DetectionEvidence captures why a runtime candidate was considered Xray-related.
type DetectionEvidence struct {
	Confidence DetectionConfidence `json:"confidence,omitempty"`
	Reasons    []string            `json:"reasons,omitempty"`
}

// Validate checks that the evidence payload is internally consistent.
func (e DetectionEvidence) Validate() error {
	if e.Confidence == "" {
		if len(e.Reasons) == 0 {
			return nil
		}

		return errors.New("detection reasons require a confidence level")
	}

	if !e.Confidence.Valid() {
		return fmt.Errorf("invalid detection confidence %q", e.Confidence)
	}

	return nil
}
