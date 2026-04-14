package discovery

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// Session represents a single active runtime connection.
type Session struct {
	ID      string         `json:"id,omitempty"`
	Runtime SessionRuntime `json:"runtime"`
	Client  SessionClient  `json:"client,omitempty"`
	Route   SessionRoute   `json:"route,omitempty"`
}

// Validate checks that a session is internally consistent.
func (s Session) Validate() error {
	if err := s.Runtime.Validate(); err != nil {
		return fmt.Errorf("invalid runtime association: %w", err)
	}

	if err := s.Client.Validate(); err != nil {
		return fmt.Errorf("invalid client identity: %w", err)
	}

	return nil
}

// SessionRuntime links a session to the runtime instance that owns it.
type SessionRuntime struct {
	Source      DiscoverySource `json:"source"`
	Provider    string          `json:"provider,omitempty"`
	Name        string          `json:"name,omitempty"`
	HostPID     int             `json:"host_pid,omitempty"`
	ContainerID string          `json:"container_id,omitempty"`
}

// Validate checks that a runtime association is internally consistent.
func (r SessionRuntime) Validate() error {
	if !r.Source.Valid() {
		return fmt.Errorf("invalid discovery source %q", r.Source)
	}

	if r.HostPID < 0 {
		return errors.New("host process id must be greater than or equal to 0")
	}

	name := strings.TrimSpace(r.Name)
	containerID := strings.TrimSpace(r.ContainerID)

	switch r.Source {
	case DiscoverySourceHostProcess:
		if containerID != "" {
			return errors.New("host_process runtime cannot include a container id")
		}
		if r.HostPID == 0 && name == "" {
			return errors.New("host_process runtime requires a process id or runtime name")
		}
	case DiscoverySourceDockerContainer:
		if r.HostPID != 0 {
			return errors.New("docker_container runtime cannot include a host process id")
		}
		if containerID == "" && name == "" {
			return errors.New("docker_container runtime requires a container id or runtime name")
		}
	}

	return nil
}

// MatchesTarget reports whether the runtime association points at the given target.
func (r SessionRuntime) MatchesTarget(target RuntimeTarget) bool {
	if r.Source != target.Source {
		return false
	}

	switch r.Source {
	case DiscoverySourceHostProcess:
		if r.HostPID != 0 {
			return target.HostProcess != nil && r.HostPID == target.HostProcess.PID
		}
	case DiscoverySourceDockerContainer:
		if r.ContainerID != "" {
			return target.DockerContainer != nil && strings.TrimSpace(r.ContainerID) == strings.TrimSpace(target.DockerContainer.ID)
		}
	}

	if strings.TrimSpace(r.Name) == "" {
		return false
	}

	return strings.TrimSpace(r.Name) == strings.TrimSpace(target.Identity.Name)
}

// SessionRuntimeFromTarget builds a session runtime association from a runtime target.
func SessionRuntimeFromTarget(target RuntimeTarget) (SessionRuntime, error) {
	if err := target.Validate(); err != nil {
		return SessionRuntime{}, fmt.Errorf("invalid runtime target: %w", err)
	}

	runtime := SessionRuntime{
		Source: target.Source,
		Name:   strings.TrimSpace(target.Identity.Name),
	}

	switch target.Source {
	case DiscoverySourceHostProcess:
		runtime.HostPID = target.HostProcess.PID
	case DiscoverySourceDockerContainer:
		runtime.ContainerID = strings.TrimSpace(target.DockerContainer.ID)
	}

	if err := runtime.Validate(); err != nil {
		return SessionRuntime{}, err
	}

	return runtime, nil
}

// SessionClient identifies the client side of a session.
type SessionClient struct {
	IP string `json:"ip,omitempty"`
}

// Validate checks that a client identity is internally consistent.
func (c SessionClient) Validate() error {
	if c.IP == "" {
		return nil
	}

	if net.ParseIP(strings.TrimSpace(c.IP)) == nil {
		return fmt.Errorf("invalid client ip %q", c.IP)
	}

	return nil
}

// SessionRoute identifies the routed path for a session.
type SessionRoute struct {
	InboundTag  string `json:"inbound_tag,omitempty"`
	OutboundTag string `json:"outbound_tag,omitempty"`
}
